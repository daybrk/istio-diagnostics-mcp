# Каталог диагностических проверок

[Навигация](README.md) · Статус: целевой каталог; не перечень готовых evaluators.

У каждого правила стабильный ID, поддержанные версии/форматы, входные evidence,
условие срабатывания и ограничение причинного вывода. Неподдержанный evaluator
возвращает UNSUPPORTED; недостающие обязательные данные — UNKNOWN. FAIL описывает
нарушение условия проверки, confidence — связь с расследуемым отказом.

## Проверки

| Rule ID | Нужные данные | Что можно установить | Что запрещено заключать автоматически |
|---|---|---|---|
| WORKLOAD_PROXY_STATE | Pod UID, injection/revision metadata, container/initContainer status | Нет proxy, неготовность, restart/termination | Любой restart вызван Istio; Running означает ready |
| PROXY_STARTUP_ERROR | Распознанный diagnostic/previous log и status | Ошибка запуска/валидации, связанная с pod/process | Причина всех сетевых отказов из любой строки ERROR |
| SERVICE_ENDPOINTS | Service + полный доступный набор EndpointSlice + readiness | Ноль backend, несоответствие selector/readiness/subset | Историческая ошибка вызвана текущим пустым набором без временной связи |
| SERVICE_PORT_MAPPING | Service ports/targetPort, pod named ports, active cluster endpoint | Несоответствие разрешаемых port mappings | Процесс слушает порт только потому, что containerPort указан |
| ROUTE_SELECTION | Listener/filter chain/route и необходимые атрибуты запроса | Конкретная выбранная ветка либо множество кандидатов | Неподдержанный matcher можно пропустить и продолжить как PASS |
| CLUSTER_REFERENCE | Active route/TCP proxy и active cluster config | Ссылка на отсутствующий cluster | Rejected config обязательно заменила рабочую active config |
| LISTENER_CONFLICT | Applicable resources, active/rejected listener + error state/log | Реальный overlap, отвергнутый Envoy | Совпадение только числового порта является конфликтом |
| ROUTE_SHADOWING | Порядок и поддержанная семантика matches | Доказуемо недостижимая ветка | Любой общий prefix ошибочен или связан с инцидентом |
| XDS_APPLY_STATE | Active/warming/rejected, версии, errors | Обновление отвергнуто или часть конфигурации warming | Proxy не обслуживает трафик вообще |
| TLS_VALIDITY | Доступные cert metadata + время + связь с выбранным TLS context | Сертификат просрочен/not-yet-valid на этом контексте | Любое существующее TLS-соединение сразу оборвалось |
| TLS_MODE_COMPATIBILITY | Обе стороны, active transport sockets, policy, handshake evidence | Несогласованность режима/identity при достаточных данных | Только DR/PeerAuthentication YAML полностью доказывает handshake outcome |
| SDS_DELIVERY | Diagnostic logs, secret refs, active/warming TLS context | Не получен/не обновлён secret или не готов TLS context | Без istiod evidence установлена причина CA/JWT/файлового сбоя |
| ISTIO_AUTHORIZATION | Effective scope, активный RBAC, атрибуты запроса, denial evidence | Применимое правило блокирует выбранный запрос | Неполный namespace/root scope или CUSTOM provider оценён полностью |
| JWT_VALIDATION | RequestAuthentication, active JWT filter, доступная ошибка | Ошибка JWT/JWKS на рассматриваемом пути | Самостоятельно сходить к jwksUri для проверки |
| NETWORK_POLICY_SCOPE | Политики обеих сторон, selectors, namespaces, ports | Статический результат применимых правил | Реальный CNI/NAT/conntrack работает именно так или он причина timeout |
| UPSTREAM_FAILURE | Correlated proxy events, flags/details, addresses, timing | Refused/reset/timeout на известном участке | Кто занял socket или точная причина отказа процесса без данных |
| PROTOCOL_STATUS | Доступные HTTP/gRPC/TCP поля и local/upstream reply | Application error vs proxy local failure | HTTP 200 всегда означает успешный gRPC |
| REPLICA_DIVERGENCE | Все доступные proxy snapshots и versions | Различия реплик и распределения симптомов | Корреляция с версией доказывает bug версии |
| DNS_CONTEXT | Service/name, pod DNS metadata, доступные proxy messages | Ошибка имени/видимости или DNS-related symptom | Отсутствие access log доказывает DNS failure или DNS health |
| PRODUCT_EXPECTATION | Optional ASTRA source + версия + live evidence | Расхождение документированного требования и состояния | Текст ответа ASTRA сам подтверждает причину |

## Правила причинности

Для confirmed evaluator обязан представить evidence механизма и identity/time
связь с выбранным событием. Если подтверждён механизм, но конкретный ресурс-
источник неизвестен, вывод так и формулируется. Конфликтующие наблюдения снижают
вывод до probable/unknown и сохраняются, а не отбрасываются.

Истёкший cert сравнивается с временем наблюдаемого handshake, когда доступны
нужные данные; текущая `/certs` не восстанавливает прежнюю цепочку. Static route
по текущему dump оценивает текущую конфигурацию. Для long-lived connections,
retry и rollout границы времени входят в explanation.

Политика DENY с HTTP-атрибутами может затронуть TCP при отсутствии атрибутов;
evaluator обязан учитывать семантику поддержанной версии, а не отбрасывать такое
правило как «не HTTP». STRICT/PERMISSIVE/auto mTLS оцениваются вместе с фактическим
выбранным контекстом. Переписывание адресов и passthrough явно меняют атрибуты.

## Проверяемые примеры и известные issue

Каждое правило получает положительный, отрицательный и неполный сценарий.
Ссылки на публичные issue хранятся как основание сценария с версией и топологией,
а не как runtime lookup, который назначает diagnosis по совпадению строки.
Каталог не обещает поддержку всех Istio extensions; Lua/Wasm/CUSTOM/неизвестные
matchers имеют explicit boundary.

Начальные приоритеты: WORKLOAD_PROXY_STATE, PROXY_STARTUP_ERROR,
SERVICE_ENDPOINTS, SERVICE_PORT_MAPPING, ROUTE_SELECTION, CLUSTER_REFERENCE,
XDS_APPLY_STATE, TLS_VALIDITY, UPSTREAM_FAILURE. Следующие правила реализуются
только вместе с meaningful fixtures и поддержанным диапазоном семантики.
План реализации должен учитывать весь целевой объём, не объявляя приоритетные
правила единственными обещанными возможностями продукта.
