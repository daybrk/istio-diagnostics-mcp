# istio-diagnostics-mcp

MCP-сервер на Go для расследования ошибок связи между приложениями в Kubernetes с
Istio sidecar. Работает снаружи кластера по kubeconfig: читает ресурсы и логи
`istio-proxy`, получает Envoy config dump через временный port-forward на 15000
и возвращает проверки с доказательствами и границами вывода.

Реализованы 11 MCP-инструментов, stdio, Streamable HTTP с OIDC, сессии с очередью
связей и необязательная интеграция ASTRA. Реализация находится в
`feat/go-mcp-v0.1`. [Точный статус и ограничения](docs/design/implementation-status.md).

## Запуск

Нужны Go 1.25+, `kubectl` в PATH и kubeconfig с доступом к нужному кластеру.
На машине сервера должен работать доступ к Kubernetes API. Версию `kubectl`
подберите под свой кластер; внешние credential plugins из kubeconfig нужно
установить на этой же машине.

```bash
go build -trimpath -o bin/istio-diagnostics-mcp ./cmd/istio-diagnostics-mcp
cp docs/design/examples/server-config.json server-config.json
```

В `server-config.json` задайте настоящий `kube.kubeconfig_path`, context и явный
список разрешённых namespaces. Пример содержит демонстрационные значения и
`transport: "stdio"`. Не включайте namespace в scope, если его данные не должны
попадать клиенту: коллектор читает ресурсы всех разрешённых namespaces для
разрешения участников и политик, а логи/dump — только выбранных участников.

```bash
./bin/istio-diagnostics-mcp -config server-config.json -check-config
./bin/istio-diagnostics-mcp -config server-config.json
```

`-check-config` проверяет конфигурацию без обращения к кластеру или ASTRA.
Stdio-процесс ожидает MCP-сообщения; stdout занят протоколом, журнал идёт в stderr.
Пример настройки MCP-клиента:

```json
{
  "mcpServers": {
    "istio-diagnostics": {
      "command": "/absolute/path/istio-diagnostics-mcp/bin/istio-diagnostics-mcp",
      "args": ["-config", "/absolute/path/server-config.json"]
    }
  }
}
```

Клиентский агент обнаруживает описания tools через MCP. `get_playbook(main)` и
`get_playbook(intake)` объясняют выбор следующего шага; доступны также MCP resources
и prompt `diagnose_connectivity`. Собственная LLM и ключ модельного API серверу
не нужны. При удалённом подключении бинарник и kubeconfig находятся на сервере,
клиенту нужен только URL MCP и токен.

## Как идёт расследование

1. `get_capabilities` показывает scope, лимиты и доступные проверки.
2. `resolve_workload` разрешает имя/selector по владельцам и UID. Неоднозначность
   приводит к вопросу, а не к сбору чужих приложений.
3. `start_diagnosis` принимает workload, inbound/outbound, optional peer и период.
   Без периода фиксирует последние 900 секунд; явное окно может быть длиннее.
4. `get_diagnosis` показывает прогресс, полноту сбора и очередь ошибочных связей.
   При точной паре проверка начинается сразу. Иначе пользователь выбирает связь
   для `investigate_connection`.
5. `get_evidence` выдаёт очищенные фрагменты с источником и временем. После
   результата остаются другие связи, `refresh_diagnosis` или `close_diagnosis`.

Длительная работа идёт асинхронно. Повтор запроса с тем же `operation_id` и вводом
не запускает второй job; изменённый ввод с прежним ключом даёт конфликт.
Отключение клиента не отменяет работу. Для отмены существует `cancel_operation`.
Сессии хранятся в памяти, удаляются по idle TTL и не переживают перезапуск.
`memory_bytes` ограничивает учитываемые сохранённые данные, включая metadata и
ответы для повторных операций. При нехватке места новые операции получают
`RESOURCE_LIMIT`, а неполный результат явно сообщает о потерянной детализации.
Счётчики реплик сохраняются, даже если подробные coverage entries не помещаются.
Это не жёсткий лимит RSS: JSON-декодирование, SDK и буферы сбора требуют
дополнительной памяти. Для лимита процесса используйте контейнер/cgroup.
Диагностические jobs выполняются по одному на сервер; внутри job реплики и
port-forward ограничиваются отдельными параметрами concurrency. Очередь также
входит в operation budget. ASTRA имеет независимый job и бюджет.

Пример первого вызова после уточнения приложения:

```json
{
  "name": "start_diagnosis",
  "arguments": {
    "operation_id": "incident-42-start",
    "workload": {
      "context": "production",
      "namespace": "shop",
      "kind": "Deployment",
      "name": "checkout"
    },
    "direction": "outbound",
    "peer": {"kind": "service", "value": "orders", "namespace": "backend", "port": 8080},
    "time_window": {"lookback_seconds": 2400}
  }
}
```

## Доступ к кластеру

[RBAC-пример](docs/design/examples/rbac.yaml) описывает чтение ресурсов, `pods/log`
и `pods/portforward`; привязки прав назначает администратор. Сервер ничего не
применяет. Нужные namespaces, включая namespace корневых политик, оператор
перечисляет явно. Отказ чтения остаётся пробелом в coverage.

Port-forward выбирает конкретный pod и слушает loopback. Разрешены только GET:
`/config_dump?include_eds`, `/certs`, `/clusters?format=json`, `/server_info`.
Это встроенные пути Envoy; собственного handler в приложении не требуется.
После сбора, отмены, дедлайна или смены UID tunnel закрывается.

Нет offline API, `pods/exec`, active probes, чтения Secrets, логов приложения,
автоматических исправлений и произвольных команд/URL из аргументов инструмента.

## Streamable HTTP

В конфигурации задайте `transport: "streamable_http"` и объект `http` по
[схеме](docs/design/contracts/config.schema.json): `listen`, HTTPS `public_url`,
`allowed_origins`, `auth.mode: "oidc"`, HTTPS `issuer`, `audience` и `bindings`.
Каждая binding содержит точный subject, contexts/namespaces и astra_projects.
Эта область пересекается с глобальным scope сервера.

Поддержаны подписанные JWT access tokens **RS256**: проверяются подпись по JWKS,
issuer, audience, expiry и привязка subject. Opaque tokens и другие алгоритмы
не поддержаны. JWKS кешируется на пять минут, неизвестный kid вызывает обновление.
Конкретные issuer, audience и bindings задаёт оператор; анонимного режима нет.

```bash
./bin/istio-diagnostics-mcp -config server-http.json \
  -tls-cert /etc/tls/server.crt -tls-key /etc/tls/server.key
```

Для TLS reverse proxy на той же машине допустим `listen: "127.0.0.1:8080"` без
TLS-флагов. Прокси должен сохранять внешний Host, совпадающий с `public_url`.
Заголовки `X-Forwarded-*` не заменяют проверку фактического адреса соединения.
Прямой listener вне loopback требует TLS-сертификат и ключ. Endpoint — `/mcp`.

## ASTRA

Пользователь сообщает project ID агенту в диалоге, например:

> Используй ASTRA, project ID payments-docs. Если неясны требования приложения
> или смысл Istio-конфигурации, обратись туда за документацией.

Агент передаёт этот ID в `get_product_context.project_id` при необходимости.
Предварительный catalog и повторный выбор проекта не нужны. Сам Go-сервер не
решает, когда обращаться к ASTRA: это задача клиентского агента по встроенному
playbook. Без запроса пользователя агент выполняет основную диагностику.

Оператор один раз задаёт адреса сервиса и имя переменной окружения с API-ключом:

```json
"astra": {
  "default_url": "https://astra.example/mcp",
  "agent_url": "https://astra.example/mcp/agent",
  "credential_env": "ASTRA_API_KEY"
}
```

Это фрагмент конфигурации; [полный пример](docs/design/examples/server-config-astra.json)
содержит также Kubernetes scope и лимиты. Замените адреса на адреса вашей ASTRA,
а секрет передайте через `ASTRA_API_KEY` в окружении процесса. `default_url` нужен
для catalog/search/source, `agent_url` — для ask; можно настроить один из них.
Ни project ID, ни `enabled: true` в конфигурации не требуются. Наличие настроек
означает доступность интеграции для вызова, а не успешную проверку ключа/сервиса.
Подключение и сверка upstream tools происходят только при запросе контекста.

В stdio отсутствие `allowed_projects` разрешает выбирать проекты в пределах
прав API-ключа. При необходимости задайте явный список; `allowed_projects: []`
запрещает все проекты. В HTTP всегда нужны назначения `astra_projects` в binding
пользователя; глобальный список, если задан, дополнительно сужает эти назначения.
Project ID из диалога не расширяет права HTTP-пользователя.

`request_budget_seconds` и `max_response_bytes` необязательны: значения по
умолчанию — 45 секунд и 1 MiB. Если ASTRA не нужна, блок можно пропустить или
оставить `{}`. Старое явное `enabled: false` сохраняет запрет для совместимости;
при переходе на этот сценарий удалите его из старой конфигурации.

`get_product_context` поддерживает только `catalog`, `ask`, `search`, `source`.
Ответ попадает в отдельные knowledge/evidence записи. Внешняя документация не
становится подтверждённой причиной сетевого отказа. Подробности:
[адаптер ASTRA](docs/design/astra.md).

## Что означает результат

`PASS`/`FAIL` относится к конкретной проверке. `confirmed`/`probable`/`unknown`
описывает силу связи с исследуемым отказом. Наличие route или endpoint не
доказывает доступность; одинаковые порты разных Service не означают конфликт;
неиспользуемый просроченный сертификат не назначается причиной запроса.

Сбор показывает все обнаруженные реплики и недоступные источники. Текущий dump
не восстанавливает конфигурацию на момент старого инцидента. Неизвестные форматы,
динамические matchers, расширения и недостающие атрибуты дают UNKNOWN/UNSUPPORTED.
Покрытие ограничено sidecar, east-west cluster-local, одним кластером.

## Проверки и разработка

```bash
go test -race ./...
go vet ./...
go run -mod=readonly docs/design/validate_contracts.go
go build -trimpath -o bin/istio-diagnostics-mcp ./cmd/istio-diagnostics-mcp
```

Тесты используют синтетические Kubernetes/Envoy данные, локальные HTTP/MCP
серверы и дочерние процессы для проверки отмены. Реальные Kubernetes, Istio,
OIDC и ASTRA здесь ещё не проходили live-проверку. Процент покрытия реальных
инцидентов не измерен. Dockerfile подготовлен, сборка образа отдельно не проверена:

```bash
docker build --build-arg KUBECTL_VERSION=vX.Y.Z -t istio-diagnostics-mcp:local .
```

Укажите существующую версию kubectl, совместимую с кластером. Образ проверяет
SHA256 загруженного бинарника и запускается от непривилегированного пользователя.

[Проектные артефакты](docs/design/README.md) ·
[API и схемы](docs/design/api.md) ·
[План реализации](docs/superpowers/plans/2026-10-22-live-readonly-implementation.md) ·
[Архив прежнего прототипа](https://github.com/daybrk/istio-diagnostics-mcp/tree/archive/go-mcp-v0.1)
