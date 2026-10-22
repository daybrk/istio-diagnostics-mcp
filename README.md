# istio-diagnostics-mcp

MCP-сервер на **Go** для диагностики входящих и исходящих соединений в Istio/Envoy.
Он объясняет выбор маршрута, находит проблемы конфигурации и возвращает доказательства.

**v0.1 — рабочая первая версия с ограниченным покрытием.** Найденный конфигурационный
путь не означает, что приложение доступно по сети. Сервер явно разделяет `PASS`,
`FAIL`, `UNKNOWN` и `UNSUPPORTED`. Он не применяет исправления.

## Возможности

- Официальный [MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk), transport **stdio**.
- Offline-аудит полного Envoy v3 `config_dump` в snake_case или camelCase.
- Диагностика одного выбранного прокси: inbound/outbound, HTTP и TCP/TLS passthrough.
- Выбор listener, filter chain, virtual host, первого подходящего HTTP route и cluster.
- Поэтапное сужение filter chains по порту, destination CIDR, SNI, transport и ALPN.
- Проверка RDS/CDS-ссылок, отсутствующих clusters, дубликатов filter-chain match/domains,
  затенённых catch-all маршрутами правил, отклонённых xDS-обновлений.
- Проверка доступных endpoint assignments с отличием отсутствующих данных от пустого списка.
- Сроки действия публичных PEM-сертификатов, SDS-ссылки, file-backed/redacted сертификаты.
- Live-сбор одного pod и namespaced ресурсов через `kubectl` и `istioctl`.
- Разрешение pod/Deployment/StatefulSet/DaemonSet по owner references.
- Проверка наличия Service endpoints и readiness выбранного pod.
- CLI для offline-разбора без MCP-клиента; синтетические примеры и автоматические тесты.

## Быстрый старт

Требуется Go **1.25+**. Для offline-режима Kubernetes, Python и API-ключи LLM не нужны.

```bash
git clone https://github.com/daybrk/istio-diagnostics-mcp.git
cd istio-diagnostics-mcp
go build -o bin/istio-diagnostics-mcp ./cmd/istio-diagnostics-mcp

./bin/istio-diagnostics-mcp -mode trace \
  -dump examples/http-config-dump.json -request examples/request.json

./bin/istio-diagnostics-mcp -mode trace \
  -dump examples/missing-cluster.json -request examples/request.json

./bin/istio-diagnostics-mcp -mode analyze -dump examples/missing-cluster.json
./bin/istio-diagnostics-mcp -mode tls -dump examples/http-config-dump.json
```

Первый trace вернёт `configuration_path_found`, второй — `configuration_issues`
с проверкой `CLUSTER_NOT_FOUND`. В TLS-примере сертификатов нет: результат будет
`UNKNOWN`, а не «сертификаты исправны».

`-at 2026-10-22T12:00:00Z` задаёт время оценки сертификатов. Это **не** восстанавливает
историческую конфигурацию. Данные должны соответствовать моменту инцидента.

CLI возвращает exit code 1 при ошибке ввода/выполнения. Диагностические находки
находятся в JSON и сами по себе не меняют exit code.

## Подключение к MCP-клиенту

Пример конфигурации клиента, поддерживающего локальный stdio MCP:

```json
{
  "mcpServers": {
    "istio-diagnostics": {
      "command": "/absolute/path/istio-diagnostics-mcp/bin/istio-diagnostics-mcp",
      "args": ["-mode", "serve"]
    }
  }
}
```

На stdout передаются только сообщения протокола; ошибки пишутся в stderr.
HTTP transport и удалённая публикация MCP в этой версии не реализованы.

### Инструменты

| Инструмент | Вход | Результат |
|---|---|---|
| `get_capabilities` | `{}` | Покрытие, ограничения, live scope |
| `analyze_config_dump` | `config_dump` либо `snapshot_id`, опционально `at` | Аудит полного dump |
| `trace_connection` | `config_dump` либо `snapshot_id`, `request`, опционально `at` | Путь на одном прокси |
| `inspect_tls` | `config_dump` либо `snapshot_id`, опционально `at` | Локальные сертификаты и SDS |
| `resolve_workload` | `namespace`, `workload` | Кандидаты pod по точному имени/владельцам |
| `collect_snapshot` | `namespace`, `pod` | ID снимка и статусы сбора |
| `diagnose_connectivity` | `snapshot_id` **или** `namespace`+`pod`; `request`; опционально `service` | Trace, contextual audit и Kubernetes-проверки |

`config_dump` — JSON-объект, **не строка и не локальный путь**. MCP не читает
произвольные файлы по переданным путям. Offline CLI читает явно указанные пользователем файлы.

Пример `request`:

```json
{
  "direction": "outbound",
  "port": 443,
  "protocol": "HTTPS",
  "destination_ip": "10.20.0.5",
  "listener_name": "0.0.0.0_443",
  "host": "api.example.com",
  "sni": "api.example.com",
  "alpn": "h2",
  "method": "GET",
  "path": "/health",
  "headers": {"x-tenant": "billing"}
}
```

Не копируйте `listener_name` из примера вслепую: он должен существовать в вашем dump.
`direction` задаётся относительно выбранного прокси. `port` — destination port,
видимый **этому** прокси: у gateway он может отличаться от внешнего Service port.
Для входящего sidecar поддерживается также выбор через virtual inbound `15006`
и `filter_chain_match.destination_port`.

Для TLS passthrough используйте `TLS`, для HTTP после TLS termination — `HTTPS`.
HTTP-запрос до TLS origination обычно описывается как `HTTP`: важно, какие байты
поступают на анализируемый listener. Отсутствующий `sni` означает, что SNI не передан.
Если ALPN нужен для выбора цепочки, но не указан, сервер остановится с `UNSUPPORTED`.

## Live-режим

По умолчанию выключен. На машине запуска нужны `kubectl` и `istioctl`, совместимый
с установленным Istio, и настроенная аутентификация Kubernetes.

```bash
export ISTIO_DIAG_ENABLE_LIVE=true
export ISTIO_DIAG_CONTEXT=my-development-cluster
export ISTIO_DIAG_NAMESPACES=payments,istio-system
./bin/istio-diagnostics-mcp
```

Для MCP-клиента задайте эти значения в `env` конфигурации процесса. Namespace
должен быть явно разрешён. Никакого автоматического выбора текущего context нет.

Пример последовательности вызовов:

```json
{"name":"resolve_workload","arguments":{"namespace":"payments","workload":"payments"}}
```

Выберите pod из результата, затем:

```json
{
  "name": "diagnose_connectivity",
  "arguments": {
    "namespace": "payments",
    "pod": "payments-actual-pod-name",
    "request": {
      "direction": "outbound",
      "port": 8080,
      "protocol": "HTTP",
      "host": "orders.payments.svc.cluster.local",
      "path": "/health"
    },
    "service": "orders"
  }
}
```

`service` — явная дополнительная проверка Service в том же namespace; это не
доказательство, что именно этот Service выбран маршрутом. Для inbound укажите
принимающий pod и его локальный destination port. Ingress/egress gateway проверяется
так же, с указанием gateway pod и параметров запроса на данном участке.

Коллектор выполняет фиксированные команды `kubectl get` и `istioctl proxy-config all`.
Параметры передаются аргументами без shell. Нет произвольного exec-инструмента,
активных сетевых запросов, чтения Kubernetes Secrets, apply/delete или рестартов.

`istioctl proxy-config` может использовать `pods/exec` для доступа к диагностике
прокси. Поэтому YAML в `deploy/rbac.example.yaml` отделяет обычное чтение от
опционального права `pods/exec`. Само Kubernetes-право exec шире операций этого
приложения: назначайте его только подходящей диагностической identity.

Недостающие CRD/права возвращаются как неполный сбор, а не как отсутствие ресурса.
Снимки хранятся только в памяти, до 16 штук, TTL 15 минут. Перезапуск удаляет снимки.
Один вывод команды ограничен 20 MiB, команда — 20 секундами, сбор — 90 секундами.
Env-переменные контейнеров pod не сохраняются, private-key/token/password поля редактируются.
Config dump и metadata всё равно могут содержать внутренние имена и другие данные;
выводы передаются подключённому MCP-клиенту.

## Как интерпретировать ответ

- `checks` — проверки пути и явно выбранного Service.
- `context_checks` — аудит всего dump. Например, истёкший неиспользуемый сертификат
  здесь **не** становится подтверждённой причиной запроса.
- `evidence` — источник, JSON Pointer к исходному объекту и наблюдение.
- `path` — выбранные компоненты конфигурации; при weighted routing это кандидаты.
- `limitations` — непроверенные аспекты и границы вывода.

`configuration_path_found` означает, что конфигурационные ссылки разрешены. Для
утверждения «приложение доступно» нужны фактические соединения, логи и runtime-данные.
`configuration_blocked` описывает отсутствие matching chain/route при заданных
входных атрибутах. `configuration_issues` может относиться только к части веток.

## Ограничения v0.1

- Один proxy за вызов; нет автоматического восстановления многошагового пути.
- Только Envoy v3; ambient/ztunnel, multi-cluster и Kubernetes Gateway API пока без адаптеров.
- Нет runtime DNS/TCP/TLS/HTTP probes, лог-корреляции и истории изменений.
- NetworkPolicy, AuthorizationPolicy и прочие политики собираются как контекст;
  их effective-семантика и политики root/cross-namespace не вычисляются.
- Нет симуляции Lua/Wasm, generic matcher trees, source-address filter-chain
  условий, query/runtime/gRPC matching и динамического выбора cluster по header/plugin.
- Trace принимает канонические HTTP paths. Escaped paths, dot segments и ранняя
  мутация headers требуют дополнительного HCM evaluation и возвращают UNSUPPORTED.
- Сертификаты: только сроки доступных публичных PEM. Нет подтверждения remote trust,
  SAN, revocation, фактического использования сертификата или успешной ротации.
- Runtime outlier ejection, panic mode, DNS/original-destination clusters не моделируются.
- Отсутствие EDS не равно отсутствию endpoints. `HEALTHY` в dump не равно рабочей сети.
- Один и тот же port у разных сервисов сам по себе не считается конфликтом.
- Нельзя найти всех проигравших при генерации Istio ресурсов по одному Envoy dump.

Подробности алгоритма и следующие этапы: [docs/architecture.md](docs/architecture.md).

## Разработка и проверки

```bash
go test ./...
go test -race ./...
go vet ./...
go test ./internal/diagnostics -fuzz=FuzzAnalyze -fuzztime=10s
go build ./cmd/istio-diagnostics-mcp
```

Тесты используют синтетические конфигурации и mock collector; доступ к кластеру не нужен.
Интеграционный тест MCP проверяет handshake, tools/list, вызов инструмента и отказ live-режима.
Файл `.github/workflows/ci.yml` запускает тесты, race detector, vet и сборку.

## Docker

```bash
docker build -t istio-diagnostics-mcp:dev .
docker run --rm -i istio-diagnostics-mcp:dev
```

Образ содержит только сервер и предназначен для **offline stdio MCP**. Для live-режима
запускайте бинарник рядом с настроенными `kubectl`/`istioctl` либо соберите свой образ
с совместимыми CLI и контролируемыми Kubernetes credentials. Встроенного HTTP endpoint нет.
