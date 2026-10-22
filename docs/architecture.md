# Архитектура v0.1

Это первая реализация, а не заявление о полном покрытии алгоритма troubleshooting.

## Компоненты

- `cmd/istio-diagnostics-mcp`: stdio server и offline CLI.
- `internal/server`: типизированные MCP-инструменты, проверка входа, bounded in-memory snapshot store.
- `internal/diagnostics`: нормализация имён JSON-полей, audit, trace, публичные сертификаты.
- `internal/live`: ограниченный read-only collector и сопоставление Service/EndpointSlice.

Движок не вызывает LLM. MCP-клиент может формулировать объяснение на языке пользователя,
опираясь на структурированные доказательства. Metadata и config dump являются данными,
а не инструкциями для клиента.

## Алгоритм trace

1. Валидировать направление, порт, протокол и полный v3 dump.
2. Выбрать активный listener с учётом адреса/порта/направления; неоднозначность — UNKNOWN.
3. Поэтапно сузить filter chains по destination port, destination CIDR, SNI, transport, ALPN.
   После выбора более специфичного SNI нет возврата к менее специфичному при ошибке ALPN.
4. Определить поддерживаемый HCM/TCP proxy. Неподдерживаемые изменяющие путь фильтры
   останавливают вычисление; auth-фильтры отмечаются как непроверенные.
5. Для HTTP выбрать virtual host и первый совпавший route. Поддерживаются basic
   path/prefix/path-separated-prefix/RE2-compatible regex, method через headers,
   exact/prefix/suffix/present/regex header matching и exact StringMatcher.
6. Разобрать direct response/redirect или forwarding cluster candidates.
7. Проверить наличие clusters, EDS/static assignment. Для runtime DNS/custom/original-dst — UNKNOWN.
8. Вернуть конфигурационный verdict, доказательства и ограничения; не утверждать доступность сети.

## Алгоритм audit

- Читать active listeners/clusters/routes/secrets отдельно от warming/rejected состояния.
- Отмечать error_state как факт неудачного обновления, не утверждая, что активная версия неисправна.
- Проверять cluster references, одинаковые filter-chain matches и domains внутри route config.
- Находить доказуемое затенение последующим unconditional prefix catch-all маршрутом.
- Проверять интервалы сертификатов относительно указанного времени; не читать filename из dump.
- Возвращать весь набор находок без автоматического назначения их причинами инцидента.

## Границы доказательств

JSON Pointer относится к объекту исходного dump, без преобразования snake_case/camelCase.
Наблюдение содержит только необходимую информацию, а не полный секрет или исходный сертификат.
CollectedAt — время начала сбора; чтения Kubernetes не являются атомарным снимком.
Поэтому разрыв ссылок во время rollout нужно перепроверять новым снимком.

## Следующие этапы

1. Логи и Envoy runtime stats: подтверждение конкретного соединения, flags и transport failures.
2. Probe runner с контролируемыми назначениями и сохранением source identity/Host/SNI.
3. Effective Istio authorization и NetworkPolicy через адаптер CNI; проверка обеих сторон.
4. Автоматический граф source sidecar → egress/ingress → destination и изменение атрибутов между hops.
5. Связь с исходными Istio YAML, namespace visibility, `istioctl analyze`, семантический diff снимков.
6. Remote TLS chain/SAN/identity и ротация SDS, ambient/ztunnel и Kubernetes Gateway API.

Неподдерживаемые механизмы должны оставаться явно UNKNOWN/UNSUPPORTED до появления
проверенного evaluator и regression-тестов.
