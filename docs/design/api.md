# MCP API · контракт `2026-10-22`

[Навигация](README.md) · [JSON Schema](contracts/mcp.schema.json) ·
[Каталог инструментов](contracts/mcp-tools.json) · [Примеры](examples/tool-cases.json)

[Пример JSON-RPC обмена](examples/mcp-exchange.json) показывает structuredContent
и совместимый text-блок одного и того же результата после initialize.

**Контракт реализован в Go-сервере.** [Статус и ограничения](implementation-status.md). Это MCP JSON-RPC API; отдельного REST
API `/diagnoses` не предлагается. OpenAPI не подменяет схемы MCP tools.
Транспорт и lifecycle реализуются официальным Go SDK с согласованием версии MCP.
Версия прикладного контракта независима от protocolVersion MCP.

## Транспорт

| Параметр | Stdio | Streamable HTTP |
|---|---|---|
| Подключение | Запуск процесса клиентом | URL сервиса `/mcp` |
| Где kubeconfig | Машина процесса | Машина сервера |
| Логи сервера | stderr, не stdout | Отдельный структурированный logger |
| Identity | Настроенный локальный principal | Проверенный auth principal до dispatch |
| Состояние расследования | Серверная память | Серверная память; не transport session |

Для HTTP использовать предусмотренные согласованной версией MCP headers,
Content-Type/Accept, POST/GET, optional SSE и session handling SDK. Не строить
собственную несовместимую обёртку. Неаутентифицированный доступ к tools запрещён;
Origin проверяется по allowlist, TLS обязателен для удалённого подключения.
Конкретный auth provider — открытое решение O02, не выдуманный рабочий endpoint.

## Формат ответа инструмента

MCP `CallToolResult.structuredContent` содержит объект соответствующей Output
схемы. В `content` возвращается text-блок с тем же JSON для клиентов без поддержки
structuredContent. Не добавлять туда вторую, противоречащую интерпретацию результата.

| Поле | Семантика |
|---|---|
| `contract_version` | Всегда `2026-10-22` |
| `outcome` | `ok`, `needs_clarification`, `partial`, `error` |
| `data` | Типизированный результат конкретного инструмента; обязателен при non-error |
| `warnings` | Ограничения с кодом и понятным пояснением |
| `next_actions` | Разрешённые действия и краткая инструкция клиенту |
| `error` | При outcome=error: code, message, retryable; при успехе отсутствует |

JSON-RPC ошибки: неверный method/tool и схема аргументов обрабатываются на уровне
протокола (`-32601`/`-32602` по месту ошибки); ошибка выполнения tool даёт
`isError=true`, outcome=error. needs_clarification и partial — обычные результаты
с `isError=false`. Отсутствие сетевой связности приложения само по себе не является
ошибкой выполнения tool. Для ошибки без структуры сервер не выдаёт фиктивный PASS.

## Инструменты

### Совместимость discovery и входных аргументов

`tools/list` публикует входные схемы с раскрытыми локальными `$ref`. Вход
`start_diagnosis` допускает объект либо одну JSON-кодированную строку объекта
в полях `workload`, `peer`, `time_window`; `refresh_diagnosis` — в `time_window`.
Предпочтительны объекты. Строка ограничена 32768 Unicode-символами. На сервере
она декодируется один раз, затем применяется строгая каноническая схема из
`mcp.schema.json`. Массивы, null, повторное кодирование, лишние поля и неверные
типы отвергаются до engine/collector. Прочие текстовые поля не декодируются.
Нормализация не меняет scope, права доступа или семантику operation_id.

Это расширение транспортного ввода для клиентов, передающих вложенные объекты
строками. Только серверного декодера недостаточно: клиент может проверять
arguments по discovery-схеме до отправки MCP-запроса. Канонический контракт и
Output-схемы остаются прежними. Initialize.instructions и playbooks задают
порядок работы и остановку после одной неудачной попытки исправить аргументы;
сервер не может принудительно остановить повторы внутри стороннего агента.

| Tool | Ввод | Результат / побочное действие |
|---|---|---|
| `get_capabilities` | Пустой объект | Версии, разрешённый scope, limits, ASTRA status, formats |
| `resolve_workload` | context?/namespace?, kind, name или selector | Кандидаты с UID; вопрос при недостаточном scope |
| `start_diagnosis` | operation_id, workload?, direction?, peer?, time_window?, diagnosis_id? | Создать/уточнить сессию; job либо question |
| `get_diagnosis` | diagnosis_id, attempt_id?, cursor?, limit? | Состояние, resume summary, coverage, findings, jobs, очередь |
| `investigate_connection` | diagnosis_id, connection_id, operation_id | Job для выбранной связи текущей попытки |
| `get_evidence` | diagnosis_id, evidence_id, offset?, limit? | Ограниченный очищенный фрагмент и locator |
| `refresh_diagnosis` | diagnosis_id, operation_id, time_window, compare_to_attempt_id? | Новая attempt с новым окном; optional comparison |
| `cancel_operation` | diagnosis_id, operation_id | Отмена указанного job; сессия и частичный результат сохраняются |
| `close_diagnosis` | diagnosis_id | Закрыть сессию, отменить jobs, освободить evidence/tunnels |
| `get_playbook` | module_id, diagnosis_id? | Текст модуля выбранной/pinned версии, условия использования |
| `get_product_context` | diagnosis_id, operation_id, action + action-specific поля | Optional ASTRA job; результат в knowledge records сессии |

Машиночитаемые input/outputSchema и required-поля находятся в JSON Schema.
Каталог содержит относительные `$ref` для хранения в репозитории. Перед выдачей
`tools/list` сервер формирует самодостаточные schema с локальными `$defs`, чтобы
клиенту не требовалось читать GitHub или файловую систему сервера.

`get_capabilities`, `resolve_workload`, `get_diagnosis`, `get_evidence`,
`get_playbook` имеют readOnlyHint=true. Создающие/изменяющие серверную сессию tools
имеют readOnlyHint=false, хотя Kubernetes остаётся read-only. Идемпотентность
мутирующих операций обеспечивается operation_id, не предположением модели.

## Входные модели

### Workload и peer

В `get_capabilities.scope` каждый разрешённый context содержит
`namespaces: ["*"]`: сервер не ограничивает namespaces. Реальные права чтения
определяет Kubernetes RBAC, отказы отражаются в coverage.

`WorkloadQuery`: kind `Deployment|StatefulSet|DaemonSet|Pod|Selector`, ровно name
для именованного объекта или selector для Selector. Единственный разрешённый
context выбирается автоматически. Отсутствующий namespace всегда требует
уточнения: старый список namespaces и маркер `*` не являются значением по умолчанию.
Сбор без однозначных context/namespace запрещён. `WorkloadRef` результата всегда
содержит context, namespace, kind, name, uid.

Selector — способ поиска, у него нет собственного Kubernetes UID. Совпавшие pod'ы
группируются по владельцам; при нескольких приложениях возвращаются отдельные
кандидаты. WorkloadRef всегда указывает конкретный workload/самостоятельный Pod.

`PeerQuery`: kind `workload|service|host|ip`, value и optional namespace/port/protocol.
Для service/workload namespace необходим до сбора; не наследовать namespace
молча при неоднозначности. Host/IP разрешаются по доступным данным кластера,
без DNS/probe с машины MCP. Неустановленная принадлежность остаётся unknown.
direction относится к основному workload, а не к стороне, которая сформулировала
жалобу. Protocol `http|https|grpc|tcp|unknown` не выводится только из номера порта.

### Время

`time_window` — ровно одна форма:

```json
{"lookback_seconds": 2400}
```

```json
{"start":"2026-10-22T10:00:00Z","end":"2026-10-22T10:40:00Z"}
```

start < end; timestamps с timezone; будущий end отклоняется. Окно сбора имеет
exclusive end. Ограничение бюджета чтения не сокращает запрошенное окно молча.
`refresh_diagnosis` всегда требует window; не повторяет default неявно.
Нормализованное окно возвращается сервером и одинаково для всех участников.

## Сессии, jobs, конкурентность

`start_diagnosis` при недостаточном вводе создаёт сессию needs_clarification.
Клиент получает diagnosis_id и question с полем field. Уточнение отправляется
повторным start с этим diagnosis_id и новым operation_id; менять scope после
начала сбора нельзя. При готовом вводе создаётся attempt с pinned versions.

Длительные операции сразу возвращают job queued/running. `get_diagnosis` получает
его прогресс. После ответа queued исходный JSON-RPC request завершён: его отмена
не отменяет job; для этого используется `cancel_operation`.

Operation ID уникален в principal/session: у создания новой сессии ключ
principal+operation_id. Для остальных — principal+diagnosis_id+operation_id.
Повтор с тем же tool и каноническими args возвращает тот же результат/job.
Другие args с прежним ID → IDEMPOTENCY_CONFLICT. Дедупликация действует до TTL;
после утраты сессии сервер не обещает распознать старый ключ создания.

Один активный diagnostic job на сессию; конфликт → OPERATION_IN_PROGRESS с ID
уже работающей операции. Optional ASTRA job имеет отдельную квоту. Re-read ничего
не запускает. Retry сети/ASTRA ограничен и не сбрасывает общий deadline.

`capabilities.astra.enabled` вычисляется по наличию endpoint/credential settings
и legacy override; обязательного `enabled` в server config нет. Пользовательский
project ID передаётся явно в `get_product_context`, предварительный catalog не
требуется. Клиентский агент вызывает ASTRA по запросу пользователя при пробелах
в знаниях. Права и настройка описаны в [контракте ASTRA](astra.md).

## Пагинация и чтение evidence

`get_diagnosis.limit`: default 20, max 100 элементов каждой коллекции. cursor
привязан к principal, session, attempt и ревизии представления; содержит offsets
для connections/findings/knowledge/jobs/coverage.entries. Новая revision →
CURSOR_STALE; клиент начинает с первой страницы. Объект `totals` содержит полные
размеры всех пяти коллекций; next_cursor есть, пока хотя бы одна не исчерпана.
Summary и агрегаты coverage не зависят от страницы. Ограничение байт может уменьшить
страницу, но не totals; оно не разрешает скрыть продолжение. Если даже минимальная
сводка не помещается, вернуть RESOURCE_LIMIT. Findings/jobs/knowledge — краткие
сводки с evidence IDs; подробности читаются отдельно. Эти правила действуют и
для Diagnosis view, возвращаемого start/investigate/refresh/cancel/product tools.

Coverage counts относятся к pod'ам, а entries — к отдельным источникам. Pod считается
collected, когда все запланированные для него чтения завершились; partial — когда
часть данных получена, unavailable — когда не получено ничего, pending — работа
ещё не начата. Эти четыре категории непересекающиеся и в сумме дают discovered_pods.
attempted_pods = discovered_pods - pending_pods. Truncated/unsupported часть данных
не позволяет считать pod полностью collected.

`get_evidence.offset` — 0-based индекс строки очищенного представления;
`limit` default 50, max 200. Эти индексы не являются исходными номерами строк:
source locator и JSON Pointer хранятся отдельно. next_offset присутствует только
при продолжении. Объект одного evidence не может быть скрыто обрезан без truncated.
Unknown/expired/чужой evidence ID → EVIDENCE_NOT_FOUND без раскрытия владельца.

## Промпты и resources

`get_playbook` работает во всех целевых клиентах с tools. Дополнительно сервер
может выдавать те же файлы как resources `istio-diagnostics://playbooks/{version}/{id}`
и один выбираемый пользователем prompt `diagnose_connectivity`, который содержит
main+intake. Это вспомогательные способы загрузки; основной flow не требует их
поддержки клиентом. Публичный tool `diagnose_connectivity` прототипа при миграции
удаляется; prompt с таким именем относится к другому namespace MCP.

В ответах diagnostic tools next_actions содержат короткие инструкции текущего
этапа, поэтому недоступный resource не блокирует продолжение. ASTRA-модуль не
загружается автоматически при disabled. Pinned bundle нельзя заменить latest
в середине сессии. Запрос неизвестного module_id → PLAYBOOK_NOT_FOUND.

## Ошибки прикладного слоя

| Код | Поведение клиента |
|---|---|
| SCOPE_DENIED | Показать доступную область; не обходить ограничение |
| SESSION_NOT_FOUND / SESSION_EXPIRED | Не выдумывать старый результат; предложить новый сбор |
| SESSION_CLOSED | Не продолжать работу со старой сессией |
| INVALID_STATE | Использовать next_actions/current state |
| OPERATION_IN_PROGRESS | Читать имеющийся job |
| IDEMPOTENCY_CONFLICT | Исправить ключ операции; не повторять старый с другими args |
| INVALID_TIME_WINDOW | Уточнить или исправить окно |
| CONNECTION_NOT_FOUND / EVIDENCE_NOT_FOUND | Обновить допустимый список в этой сессии |
| CURSOR_STALE | Начать пагинацию с первой страницы |
| RESOURCE_LIMIT | Показать partial и причину; не скрывать pod'ы |
| INTEGRATION_DISABLED | Продолжить базовую диагностику без ASTRA |
| PROJECT_SELECTION_REQUIRED | Выбор проекта нужен только для ASTRA |
| UPSTREAM_UNAVAILABLE / UPSTREAM_FORBIDDEN | Не подменять отсутствие знания диагнозом |
| UPSTREAM_CONTRACT_MISMATCH | Сообщить о несовместимом интерфейсе ASTRA |
| PLAYBOOK_NOT_FOUND | Использовать основную инструкцию и сообщить о пробеле |
| INTERNAL_ERROR | Показать correlation ID без внутреннего stack trace |

Collector errors отдельных ресурсов входят в coverage entries, а не делают весь
tool error. Retryable=true означает допустимость ограниченного повтора, не команду
повторять бесконечно. В schema error code допускает новые значения для совместимости;
неизвестный код клиент показывает безопасно с message и next_actions.
