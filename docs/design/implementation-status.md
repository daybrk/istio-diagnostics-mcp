# Статус реализации · 23 октября 2026

[Навигация](README.md) · [Запуск](../../README.md) · [План](../superpowers/plans/2026-10-22-live-readonly-implementation.md)

Новый сервер реализован в исходной ветке `feat/go-mcp-v0.1`. Старый offline
прототип сохранён отдельно; совместимости с его публичными tools нет.

| Область | Реализованное поведение | Граница |
|---|---|---|
| MCP | 11 инструментов, раскрытые input schemas, JSON в text и structuredContent; ограниченная совместимость с JSON-кодированными объектами | Контракт `2026-10-22`; после декодирования строгая валидация; транспорт согласует MCP через SDK |
| Инструкции | Семь встроенных модулей bundle `2026-10-23.2`, initialize.instructions, resources и prompt | Модули версионированы manifest; поведение стороннего агента сервером не гарантируется |
| Сессии | Ownership, TTL, idempotency, jobs, отмена, закрытие, история attempts, cursor pagination | Только память процесса; после рестарта восстановление не обещается |
| Доступ | Разрешённые contexts, все namespaces в пределах Kubernetes RBAC; старые namespace lists игнорируются с сообщением | Namespace приложения требуется для идентификации; context/ownership/ASTRA bindings сохраняются |
| Сбор | Kubectl с фиксированными аргументами, owner UID, все найденные реплики, ресурсы всех namespaces с ограничениями объёма и RBAC fallback, Events, current/previous proxy logs | Отказы доступа и недоступные форматы остаются явными пробелами |
| Envoy | Loopback port-forward к pod:15000, четыре фиксированных GET, лимиты и UID monitoring | Нет active probes и /stats; текущая конфигурация не является исторической |
| Анализ | Проверки состояния proxy, Service/EndpointSlice/ports, route/cluster, xDS, TLS, policy subset, симптомов и различий реплик | Консервативные подмножества семантики; unsupported/unknown не скрываются |
| HTTP | OIDC JWT RS256, issuer/audience/expiry/signature, subject bindings, Host/Origin checks | Opaque tokens и другие JWT algorithms не поддержаны; реальный provider не проверен |
| ASTRA | Project ID из диалога, готовность по endpoint/credential settings; фиксированные catalog/ask/search/source, project/repo scope, redaction, byte/deadline limits | Реальная установка не проверена; знания не становятся автоматическим причинным диагнозом |
| Запуск | Go binary, CLI config validation, SIGTERM cleanup, stderr JSON journal, CI | Dockerfile не собран в этой среде |

## Ограничения диагностических правил

Правила возвращают UNKNOWN при недостатке атрибутов/источников и UNSUPPORTED для
семантики вне реализованного подмножества. В частности, нельзя безопасно
моделировать произвольные Lua/Wasm/CUSTOM providers, extension matchers, динамический
cluster selection, все условия AuthorizationPolicy/NetworkPolicy и фактический CNI.
Полный поддержанный набор проверок сообщает `get_capabilities`; это перечень
реализованных evaluators, а не обещание диагностики каждого варианта правила.

PRODUCT_EXPECTATION не выполняет автоматическое доказательство по свободному
тексту ASTRA. Агент клиента читает knowledge evidence и сопоставляет его с live
наблюдениями. Неизвестная индексная revision не приравнивается к образу приложения.

Смена/удаление pod, ротация логов, недоступные namespaces, неизвестный Host/SNI,
отсутствие трафика после изменения и TLS passthrough ограничивают выводы. Без
достаточных доказательств сервер не объявляет сеть исправной или корневую причину
подтверждённой. Реальная матрица версий/нагрузки требует доступа к окружению.

TLS mode comparison выполняется только при связке Service → EndpointSlice →
конкретный backend pod/port и однозначной простой listener chain. Capture listener
с условным выбором chain остаётся UNKNOWN. Совпадение Service port и номера
несвязанного listener не является доказательством TLS mismatch.

Память ограничивается отдельно для сохраняемого состояния и материализации
анализа. Сохраняемый бюджет учитывает replay, findings, connections, coverage,
knowledge и jobs; пропуски дают RESOURCE_LIMIT/partial. Счётчики покрытия реплик
не заменяются числом сохранённых подробных записей. Лимит не является точным RSS:
временные JSON-структуры/буферы SDK требуют запаса и внешнего лимита процесса.
Одновременно выполняется один diagnostic job; внутри него действует ограничение
параллелизма реплик/туннелей. Knowledge job — максимум один на всю сессию, включая
исторические attempts.

## Проверки в репозитории

- Контрактные примеры и prompt hashes из проектного комплекта.
- Unit/integration fixtures для разрешения владельцев, всех реплик, полноты чтения,
  временных окон, неподдержанных данных и диагностической причинности.
- Subprocess-тесты для ограничения вывода и завершения port-forward.
- Session tests для выбора/остатка очереди, replay/conflict, refresh, отмены,
  ownership, сужения scope, истечения TTL, памяти и пагинации.
- MCP SDK handshake/tools/resources, OIDC/JWKS и ASTRA через локальные fixtures.
- Discovery-валидация до MCP-вызова и однократное декодирование workload/peer/window:
  native/encoded формы, отказ неверным типам, лишним полям и double encoding.
- Интеграция coordinator с настоящим анализатором: direct pair с указанным и
  неуказанным портом, IP/workload identities, связь логов обеих сторон через
  UID/EndpointSlice, malformed dump, Service port ≠ backend port.
- Отозванные права при creation replay, historical ASTRA completion/quota,
  накопление clarification replay и ограничение metadata больших результатов.
- Smoke собранного stdio-бинарника вне каталога проекта: initialize, 11 tools,
  capabilities, clarification/resume, playbook, disabled ASTRA и close.

Эти проверки подтверждают работу кода на фикстурах. Они не заменяют live smoke
с kubeconfig пользователя, его реальными версиями и форматом логов. Измеренного
процента диагностируемых Istio incidents пока нет.
