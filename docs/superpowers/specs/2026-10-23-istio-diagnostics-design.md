# Istio Diagnostics: дизайн MVP

Дата: 2026-10-23. Статус: согласован в обсуждении, ожидает ревью исполнителя.

Предыстория: [разбор монолога](../../../01-transcript-analysis.md), [предложения по алгоритму](../../../02-algorithm-improvements.md). Это чистый лист: прежний сервер `daybrk/istio-diagnostics-mcp` не является основой. Из 02 взяты идея трёх представлений (декларативное / загруженное / наблюдаемое) и правила безопасности. Сессии, evidence IDs и state-машина расследования из 02 в MVP не входят.

## 1. Намерение

Пользователь говорит агенту в Claude Code: «приложение A в namespace A не может обратиться к приложению B в namespace B». Агент по skill проходит расследование: окружение → istiod → путь через Envoy и Istio CRD → логи → знания о продукте (ASTRA) → итог с объяснением и предложением. Пользователь получает причину и конкретный следующий шаг, или честное «не хватает данных».

Зачем: расследование Istio-инцидентов сегодня требует эксперта и ручного чтения config dump. Цель — чтобы агент делал это воспроизводимо, а человек видел причину, а не мегабайты JSON.

## 2. Цели, roadmap, анти-цели

**Цели MVP**

- Полный проход шагов 3.2–3.7 из черновика на bookinfo.
- Детерминированный анализ пути A→B в коде сервера, агенту — выжимка и findings.
- Поддержка разных версий Istio и форков с кастомными CRD через цепочку анализаторов.
- Приёмка по 8 группам сценариев (раздел 10).

**Roadmap** (сознательно не в MVP, возможно позже)

- Центральный многопользовательский сервер, HTTP-транспорт, auth.
- Сессии и состояние расследования на сервере.
- Автоматическое применение исправлений.
- Kubernetes Events (исключены по решению из монолога).
- Встраивание анализаторов upstream Istio (`istio.io/istio/pkg/config/analysis`). Интерфейс готов под это, реализация позже.
- Entry-point tool с инструкциями для клиентов без skills.
- Реальная ASTRA. Только mock.
- Ambient mode (ztunnel/waypoint). MVP только sidecar. При обнаружении ambient-меток на ns анализатор `proxy-connectivity` возвращает `analyzer_error` с кодом `unsupported`, не `no_sidecar`.
- Fallback на istiod `/debug/config_dump` при отсутствии прав на `pods/portforward`. Источник конфигурации один — Envoy admin на localhost:15000 самого proxy (см. 5.2).
- Полный обход CRD кластера как штатный шаг. Поиск идёт от ссылок в дампе; cluster-wide list только по эскалации (см. 5.2).
- Анализ содержимого EnvoyFilter. Список EnvoyFilter читается в крайнем случае и только как факт «есть претендент на hop».

**Анти-цели** (провал, даже если «работает»)

- Сервер отдаёт значения Secret, service account token, приватные ключи.
- Сервер делает мутации в кластере или произвольный exec/shell.
- Агент получает сырой config dump и строит топологию сам.
- Skill предлагает исправления, когда Istio исправен (сценарий 7).
- Warning останавливает анализ или подаётся как причина сбоя.

## 3. Ограничения

- Клиент: Claude Code. Skill в формате SKILL.md + `references/`.
- Сервер: Go, транспорт stdio, kubeconfig пользователя, его RBAC. Сервер права не расширяет, а сужает.
- Только чтение: get/list ресурсов, `pods/log`, `pods/portforward` на Envoy admin (только GET внутри), `pods/proxy` на istiod. Никаких exec, create/patch/delete объектов.
- Чувствительное: Secret не читаем вообще. Сертификаты — через Envoy admin `/certs` (там нет ключей). Env pod'ов отдаём, но значения `valueFrom.secretKeyRef` заменяем на `<secret:name/key>`. Логи и dump режем лимитами.
- Версии Istio разные, в том числе форки с дополнительными CRD. Кастомные CRD только дополняют стандартные: VS/DR/Gateway/SE/PeerAuth/AuthPolicy сохраняют upstream-схему. Замена стандартных ресурсов не поддерживается и не планируется. Одна нормализованная модель на все флейворы.
- Сабагенты запускает клиент (Agent tool). Сервер о них не знает.
- Период для логов задаёт пользователь, ограничений нет.

## 4. Архитектура

```
Пользователь ──► Claude Code агент ──(skill istio-incident)──┐
                      │                                       │
                      ├─ MCP istio-diag (Go, stdio) ──► kube API, Envoy admin
                      ├─ MCP astra-mock (stdio) ──────► JSON-фикстуры
                      └─ Agent tool → сабагенты (логи по pod'ам) → get_logs
```

| Компонент | Отвечает за |
|---|---|
| Skill `istio-incident` | Алгоритм расследования, общение с пользователем, запреты, промпт сабагента, формат итога, чтение результатов tools |
| MCP `istio-diag` | Доступ к данным, безопасность, нормализованная модель, цепочка анализаторов |
| MCP `astra-mock` | Эталонное описание продукта bookinfo |
| Агент клиента | Оркестрация, сабагенты, гипотезы, итог |

Сервер stateless. Каждый вызов tool самодостаточен. Состояние расследования (что проверено, что осталось) держит агент по skill.

## 5. MCP istio-diag

### 5.1. Tools

Все tools принимают `context?` (kube context, по умолчанию текущий). Ошибки возвращаются структурно: `{error: {code, message, hint}}`, не исключением протокола. Коды: `not_found`, `forbidden`, `no_sidecar`, `proxy_unreachable`, `too_large`, `internal`.

| Tool | Вход | Выход |
|---|---|---|
| `describe_namespace` | `namespace` | labels (`istio-injection`, `istio.io/rev`), наличие Sidecar/PeerAuth/AuthPolicy, список workloads |
| `describe_workload` | `namespace`, `name` (deployment/pod/service) | pod'ы: phase, контейнеры, наличие `istio-proxy`, image proxy, revision, env (с маскировкой), service ports, ownerReferences |
| `find_gateways` | `namespace`, `host?` | ingress/egress gateway pod'ы и Gateway-ресурсы, связанные с namespace через VS `gateways:` или selector |
| `istiod_status` | `revision?` | pod'ы istiod, версия, `/debug/syncz` по прокси: SYNCED/STALE/NOT SENT |
| `get_proxy_config` | `namespace`, `pod`, `host?`, `port?` | срез дампа: listeners, routes, clusters, endpoints, отфильтрованные по host/port. Без фильтра — только сводка (счётчики, имена) |
| `get_istio_resources` | `namespace`, `host?`, `kinds?[]`, `scope?: local/cluster` | VS/DR/Gateway/SE/Sidecar/PeerAuth/AuthPolicy + кастомные GVR, видимые из namespace с учётом exportTo. `local` (по умолчанию): только `namespace`, ns назначения из `host` и root ns. `cluster`: постраничный проход по всему кластеру с фильтром по host, только по явному запросу. `EnvoyFilter` отдаётся только при явном `kinds: [EnvoyFilter]`, в выдачу по умолчанию не входит |
| `get_proxy_certs` | `namespace`, `pod` | Envoy `/certs`: subject, SAN, not_before/not_after, days_left; без ключей |
| `get_logs` | `namespace`, `pod`, `container`, `since`, `until`, `limit?`, `grep?` | строки логов в окне, обрезка по лимиту с пометкой `truncated` |
| `analyze_path` | `source{namespace, workload}`, `destination{host, port, protocol?}`, `via?: direct/ingress/egress`, `analyzers?[]`, `start_from?` | см. 5.4 |

Семантика `analyze_path`:

- `via` обязателен, если путь идёт через gateway. Skill определяет его из слов пользователя; если неясно — спрашивает. Без `via` — `direct`. Автоопределения нет: «мимо egress» — ошибка только когда пользователь заявил путь через egress.
- `via: ingress` — `source` опционален (внешний клиент). `destination.host` — внешний Host/SNI, который матчится на Gateway. Backend-сервис анализатор выводит из VS/route сам и кладёт в `path`.
- `via: egress` — `destination.host` — внешний host (ServiceEntry). Путь: source sidecar → egress gateway → внешний host.
- `direct` — `destination.host` — service внутри меша, короткое имя раскрывается в FQDN по namespace destination (если задан) или source.
- `proxy-connectivity` проверяет sidecar только у участников, которые есть в пути: при `ingress` без `source` — только gateway и destination.

`analyze_path` — главный инструмент. Остальные — для первичного осмотра (3.2) и для уточнений, когда агенту нужно показать пользователю конкретику.

### 5.2. Сбор данных (не зависит от версии Istio)

- Kubernetes: client-go + dynamic client. Istio CRD читаются как unstructured. Список GVR: стандартные `networking.istio.io` (v1, v1beta1, v1alpha3), `security.istio.io` (v1, v1beta1) + кастомные из конфига сервера. Discovery API подтверждает, какие есть в кластере.
- Envoy admin слушает только localhost:15000, через `pods/proxy` он недостижим. Единственный путь к дампу — `pods/portforward` (так работает istioctl): по факту чтение, но RBAC требует verb `create` на subresource `pods/portforward`. Это единственное исключение из «только get/list», оно фиксируется в документации RBAC. Fallback на istiod `/debug/config_dump?proxyID=` не делаем: это сгенерированная, а не загруженная конфигурация, она требует отдельного режима «данные не подтверждены» во всей модели и цепочке, плюс поиска istiod-pod'а, который держит соединение с proxy. Анализируем только то, что Envoy реально загрузил. При `forbidden` на portforward любой tool, которому нужен дамп (`get_proxy_config`, `get_proxy_certs`, `analyze_path`), возвращает `{error: {code: forbidden, hint}}`, где `hint` называет pod и нужное RBAC-правило; анализаторы не запускаются. Если дамп недоступен хотя бы у одного участника пути, `analyze_path` не выполняется целиком: частичный путь не строим. Только GET. Дамп с масками: `config_dump?resource=dynamic_listeners`, `dynamic_route_configs`, `dynamic_active_clusters`, `include_eds=true`; `/clusters?format=json`; `/certs`. Полный дамп не запрашиваем.
- Istiod: `pods/proxy` на порт 15014, только `/debug/syncz`. Это статус синхронизации proxy, не источник конфигурации. Другие debug-эндпоинты istiod не используются.
- Кэш на время одного вызова tool: дамп одного pod'а не скачивается дважды внутри `analyze_path`.
- Поиск CRD идёт от дампа, не от кластера. Уровни, каждый следующий только если предыдущий не объяснил путь:
  1. `refs` — всегда. Из дампа берутся ссылки `metadata.filter_metadata.istio.config` (VS на routes, DR на clusters, Gateway на listeners), `istio.services[]` на clusters (ServiceEntry), id правил RBAC-фильтра `ns[<ns>]-policy[<name>]` (AuthorizationPolicy). Каждая ссылка это `get` по ns и имени. Стоимость равна числу winners.
  2. `local` — всегда, дёшево. List по host в трёх ns: клиента, назначения, root. Закрывает PeerAuthentication и Sidecar (в дампе есть только их эффект, не имя), а также «не тот host», «два VS», «конфликт DR» в типичной раскладке.
  3. `cluster` — только если hop оборван или winner не ожидаемый, а в `local` кандидата нет. Постраничный list (`limit`/`continue`) по всему кластеру с фильтром по host и exportTo на каждой странице. Единственный случай, когда он нужен: ресурс в чужом ns с `exportTo`.
  4. `envoyfilter` — крайний случай. Только если в дампе есть звено пути без `istio.config` и без кандидата на уровнях 1–3. List EnvoyFilter в ns клиента, ns назначения и root ns. Анализ содержимого EnvoyFilter не делается: в ответ попадает факт «на этот hop претендует EnvoyFilter X», дальше решает пользователь.

### 5.3. Нормализованная модель

Одна структура для всех анализаторов. Исполнитель уточняет поля.

```
Model
  Request        source, destination, via, resolved FQDN
  Flavor         istio version, distribution, revision, crds[]
  Participants   source pods, destination pods, gateway pods (с proxy status)
  Loaded         hops[]: для каждого прокси на пути —
                 listener → filter chain → route → vhost → cluster → endpoints
                 winners: множество istio.config (ссылки на CRD) из метаданных дампа
  Declared       claimants: CRD, которые по host/port/gateway/exportTo претендуют на путь,
                 как unstructured + разобранные стандартные поля.
                 Загружается лениво по уровням refs → local → cluster → envoyfilter (см. 5.2):
                 анализатор просит m.Declared(scope), модель грузит и кэширует.
                 У каждого claimant: scope, из которого он пришёл, и visible_via
                 (own_ns | exported_to_ns | exported_all | root_ns | hidden:export_to)
  Inbound        destination mTLS mode по filter chains, PeerAuth
  Certs          по gateway pod'ам
```

Связка dump → CRD: `metadata.filter_metadata.istio.config` на routes, clusters, listeners. Имена кластеров `outbound|port|subset|host` разбираются в структуру. У каждого winner сравнивается `resourceVersion` объекта из `get` с `last_updated` ресурса в дампе: если объект изменён после загрузки, winner помечается `changed_after_load`, и анализаторы понижают confidence.

Построение пути:

- direct: source outbound listener по порту → RDS → vhost с domain destination → routes → clusters → endpoints → destination inbound.
- egress: source → cluster на egress gateway → дамп egress pod'а → listener/SNI → route → cluster к ServiceEntry.
- ingress: дамп ingress pod'а → listener порт → filter chain → route → cluster destination → inbound.

Обрыв на любом звене фиксируется как `hop.missing = true` с причиной.

### 5.4. Цепочка анализаторов

```go
type Analyzer interface {
    ID() string
    Supports(f Flavor) bool
    Analyze(ctx context.Context, m *Model) (Result, error)
}

type Result struct {
    Errors   []Finding // останавливают цепочку
    Warnings []Finding // копятся
}

type Finding struct {
    Rule        string
    Hop         string
    Resource    string // kind/namespace/name
    Expected    string
    Actual      string
    Explanation string
    Confidence  string // high | medium | low
}
```

Правила исполнения:

1. Порядок — массив в конфиге сервера. Код порядок не задаёт.
2. Для каждого: `Supports(flavor)` false → в `skipped`. True → `Analyze`.
3. `Errors` непусто → стоп. Остальные в `not_run`.
4. Ошибка от `Analyze` (сбой самого анализатора) → стоп, `status: analyzer_error`.
5. `Warnings` копятся через всю цепочку.
6. Все прошли → `status: clean`.
7. `start_from` — начать с указанного анализатора. `analyzers[]` — явный список вместо автовыбора.

Ответ `analyze_path`:

```json
{
  "status": "failed | clean | analyzer_error",
  "flavor": {"version": "1.24.2", "distribution": "upstream", "revision": "default"},
  "failed_at": "virtual-service",
  "errors": [],
  "warnings": [],
  "ran": [], "skipped": [], "not_run": [],
  "path": []
}
```

Анализаторы MVP, в порядке по умолчанию:

| ID | Проверяет | Сценарии |
|---|---|---|
| `proxy-connectivity` | sidecar есть у обоих и у gateway, injection label/revision на ns, istiod жив, syncz SYNCED | 1 |
| `path-exists` | путь проходится до endpoints; обрыв → где | 2 (нет пути, мимо egress, нет пути с ingress) |
| `gateway` | Gateway существует, selector попадает на pod, порт/протокол server'а совпадают с listener; >1 Gateway на порт с разным protocol/TLS → проигравший без filter chain | 3 |
| `virtual-service` | host VS резолвится в service; routes в vhost совпадают с VS; >1 VS на host+gateway → warning если победитель рабочий, error если нужные routes отсутствуют; exportTo скрывает нужный VS → error | 2 |
| `destination-rule` | cluster metadata указывает на ожидаемый DR; >1 DR на host → ownership по ns клиента; subset без DR; exportTo | 4 |
| `tls-consistency` | source cluster tls mode vs destination inbound (STRICT/PERMISSIVE/DISABLE); DR tls где не нужен; egress: cluster protocol/TLS vs egress listener | 4, 3 |
| `certificates` | срок cert на gateway, SNI cert vs host | 5 |
| `custom-example` | `Supports` по наличию кастомного CRD из конфига; правил нет; демонстрирует ветвление | — |

`virtual-service` и `destination-rule` работают по правилам Istio: мерж VS на gateway, DR first-wins по времени в одном ns, локальный ns клиента приоритетнее экспортированного. Исполнитель сверяет с документацией Istio целевых версий.

Детект флейвора: image istiod → версия и дистрибутив (по registry/имени), `istio.io/rev`, список CRD через discovery. Конфиг сервера может задать соответствие «признак → distribution».

### 5.5. Конфигурация сервера

Файл YAML, путь флагом. Поля: `analyzers` (упорядоченный список id), `extra_gvr`, `distributions` (match по image regex → name), `limits` (log_lines, dump_bytes). Без файла — дефолты.

## 6. MCP astra-mock

Отдельный процесс, stdio. Данные из JSON-фикстур в `astra-mock/fixtures/`. Логики нет.

Tools: `list_projects`, `get_project(id)`, `get_component(project, name)`, `get_dependency(project, from, to)`.

Фикстура `bookinfo`: 4 компонента (productpage, details, reviews v1/v2/v3, ratings), порт 9080, HTTP. Зависимости: productpage→details, productpage→reviews, reviews→ratings. У компонента: ожидаемые env (`DETAILS_HOSTNAME`, `REVIEWS_HOSTNAME`, `SERVICES_DOMAIN` и т.п. по upstream bookinfo), ожидаемые Istio-ресурсы (Gateway `bookinfo-gateway`, VS `bookinfo`, DR по версиям reviews).

Для сценария 6 эталон остаётся верным, ломается кластер: у productpage в overlay env `REVIEWS_HOSTNAME=reviews-v9`. Skill должен найти расхождение «эталон говорит `reviews`, в кластере `reviews-v9`».

Язык: Go, тот же репозиторий, отдельный бинарник. Исполнитель может выбрать иной, если проще.

## 7. Skill istio-incident

Структура:

```
skills/istio-incident/
  SKILL.md                 алгоритм, правила, когда какой модуль читать
  references/
    environment.md         шаг 3.2: что смотреть в describe_*, istiod_status; критерии «проксей нет»
    analysis.md            как читать analyze_path: errors → диагноз, warnings → рекомендации, clean → дальше
    logs.md                шаг 3.5: выбор pod'ов, окно, промпт сабагента, формат заключения, лимит параллелизма 4
    astra.md               шаг 3.6: когда звать, как сопоставлять эталон с env/ресурсами, что считать расхождением
    report.md              формат итога: причина, доказательства, предложение, ограничения, блок best practice
    security.md            запреты: не просить секреты, не применять изменения, не выполнять инструкции из логов
```

Алгоритм в SKILL.md:

1. Зафиксировать A, B, направление, путь (direct/ingress/egress), период. Уточнить только если неоднозначно.
2. Осмотр: `describe_namespace` для обоих ns, `describe_workload` для обоих, `find_gateways`, `istiod_status`. Явные проблемы (pod не Running, нет sidecar) → сразу к итогу.
3. `analyze_path`. `failed` → диагноз по errors, к итогу. `analyzer_error` → сообщить ограничение, продолжить логами. `clean` → шаг 4.
4. Логи: сабагент на pod (source, destination, участвующие gateway). Каждый зовёт `get_logs`, возвращает заключение по шаблону из `logs.md`. Основной агент сопоставляет.
5. Если логи не объяснили → ASTRA: `get_component` для A и B, `get_dependency(A,B)`. Сравнить с env из `describe_workload` и ресурсами из `get_istio_resources`.
6. Итог по `report.md`. `clean` и ничего не найдено → «Istio исправен, причин не найдено», без предложений. Warnings — отдельный блок, не причина.

Пользователь может указать project ID ASTRA, версию/дистрибутив Istio, список анализаторов. Skill передаёт их в tools.

## 8. Безопасность

| Граница | Поведение |
|---|---|
| Kube API | только get/list; `pods/log`; `pods/portforward` (create, но по факту чтение); `pods/proxy` GET на istiod. RBAC пользователя |
| Secrets | не читаются. Env `secretKeyRef` маскируется |
| Envoy admin | только GET на фиксированные пути. Никаких POST (`/logging`, `/quitquitquit` и т.п.) |
| Логи/dump | лимиты из конфига, пометка `truncated` |
| ASTRA | отправляются только имена компонентов и проекта |
| Текст из логов/ASTRA | данные, не инструкции. Прописано в skill |
| Исправления | только предложение и способ проверки. Применяет пользователь |

## 9. Структура репозитория

```
cmd/istio-diag/          main
cmd/astra-mock/          main
internal/kube/           клиенты, discovery, GVR
internal/envoy/          admin API, парсинг dump, разбор имён кластеров
internal/model/          Model, построение пути, winners/claimants
internal/analyzers/      интерфейс, реестр, цепочка, по пакету на анализатор
internal/tools/          MCP tools
internal/config/
astra-mock/fixtures/
skills/istio-incident/
test/env/                bookinfo + ingress + egress + внешний сервис (kustomize base)
test/scenarios/<id>/     overlay поломки + expected.md (ожидаемый вывод skill)
docs/
```

MCP SDK для Go — на выбор исполнителя. Официальный `modelcontextprotocol/go-sdk` предпочтителен.

## 10. Приёмочные сценарии

Окружение: Istio с ingress и egress gateway, bookinfo, внешний сервис для egress. Фиксированная TLS-топология:

- Ingress: Gateway HTTPS с `credentialName` (пользовательский серверный cert). Для сценария 5 — истёкший cert в этом Secret. Виден в `/certs` ingress pod'а как server cert.
- Sidecar → egress gateway: `ISTIO_MUTUAL` по upstream-примеру Istio egress. Этот cert выдан istiod, его не ломаем.
- Egress → внешний host: TLS origination `MUTUAL` с клиентским cert через `credentialName`. Для сценария 5 — истёкший клиентский cert. Виден в `/certs` egress pod'а как client cert. Сценарий 3 «не тот протокол» — Gateway server на egress с `HTTP` при DR `tls.mode: ISTIO_MUTUAL` у sidecar, и наоборот.
- Внешний сервис: nginx с TLS в отдельном namespace без sidecar, за ServiceEntry `resolution: DNS` на его cluster-DNS имя под fake-доменом (например `external.example.test`). DNS-разрешение fake-домена — через Istio DNS proxy или CoreDNS rewrite; исполнитель выбирает. Каждый сценарий — overlay + `expected.md`: какой анализатор должен упасть, какое правило, что skill должен сказать пользователю.

| # | Группа | Поломки | Ожидание |
|---|---|---|---|
| 1 | Proxy не подключен | нет injection label на ns; proxy pod не работает | `proxy-connectivity` error |
| 2 | VirtualService | не тот host; маршрут мимо egress; нет пути с ingress; нет пути вообще; >1 VS с разными настройками; VS из другого ns через exportTo | `path-exists` или `virtual-service` error; конфликт с рабочим победителем — warning |
| 3 | Gateway | egress gateway с не тем протоколом; не тот порт; >1 Gateway на порт с разными настройками; gateway не создан | `gateway` error |
| 4 | DestinationRule | неверный tls; tls включён где не нужен; DR из другого ns через exportTo | `destination-rule` или `tls-consistency` error |
| 5 | Сертификат | истёкший cert на ingress/egress https | `certificates` error |
| 6 | Ошибка в bookinfo | Istio верен, env productpage расходится с эталоном ASTRA | `clean`; skill подтверждает Istio, находит расхождение через ASTRA |
| 7 | Всё верно | — | `clean`; skill не предлагает действий |
| 8 | Масса | 100+ Gateway на разные порты + VS + DR, один сломан | нужный error; время ответа и объём ответа в пределах лимитов |

`expected.md` фиксирует правило (`Finding.Rule`) и суть объяснения, а не обязательный анализатор: fail-fast может сработать раньше по цепочке (например, «gateway не создан» ловит `path-exists`, а не `gateway`). Главное — верное объяснение пользователю. Колонка «Ожидание» в таблице — ориентир.

Сценарий 2 «не тот host» покрывается двумя overlay: ошибка в `spec.hosts` (VS не применяется) и ошибка в `route.destination.host` (маршрут в несуществующий service). Сценарий 4 «tls где не нужен» — DR `tls.mode: SIMPLE` на внутренний service без TLS.

Для сценария 8 исполнитель замеряет время `analyze_path` и размер ответа. Целевых чисел нет, нужен факт.

## 11. Порядок реализации

1. Скелет сервера, конфиг, `describe_*`, `istiod_status`, `find_gateways`. Тестовое окружение, сценарий 1.
2. Envoy admin, парсинг dump, модель пути, `get_proxy_config`, `get_istio_resources`. Анализаторы `proxy-connectivity`, `path-exists`. Сценарий 2 (нет пути).
3. `gateway`, `virtual-service`, `destination-rule`, `tls-consistency`. Сценарии 2–4, 8.
4. `get_proxy_certs`, `certificates`. Сценарий 5.
5. `get_logs`, skill целиком с модулем логов и сабагентами.
6. `astra-mock`, модуль ASTRA в skill. Сценарии 6, 7.
7. `custom-example`, детект дистрибутива по конфигу.

## 12. Оставлено исполнителю

- Точные поля Model и JSON-схемы tools.
- Выбор MCP SDK.
- Как именно детектить дистрибутив форка (regex по image — стартовое предложение).
- Способ запуска тестового окружения (kind/minikube, версия Istio для приёмки).
- Формат `expected.md` и как прогонять приёмку (вручную через Claude Code в MVP допустимо).
- Внутренняя структура skill-модулей, пока покрыты пункты из раздела 7.

## 13. Решения, принятые мной в ходе обсуждения

Отмечены, чтобы пользователь мог их отвергнуть:

- Stateless сервер, состояние у агента.
- Топология и diff в коде, не у агента.
- Сертификаты через Envoy `/certs`, не через Secret.
- Один `core` разбит на 7 мелких анализаторов ради точного fail-fast.
- Upstream-анализаторы Istio отложены, интерфейс под них оставлен.
- `astra-mock` на Go в том же репо.
- Лимит параллельных сабагентов 4.
- Дамп только через `pods/portforward` на Envoy admin, без fallback на istiod debug; это единственный не-get verb. Нет прав — явная ошибка `forbidden`, не анализ по сгенерированному конфигу. (Изменено 2026-10-23 после обсуждения: fallback отдавал «что istiod хотел отправить», а не «что proxy загрузил», и требовал отдельного режима degraded в модели.)
- Семантика `via`: обязателен для gateway-путей, без автоопределения.
- TLS-топология тестового окружения (раздел 10) и место истёкших cert.
- Ambient вне MVP.
- `expected.md` привязан к правилу, не к анализатору.
- CRD ищутся от дампа (ссылки `istio.config`), не перебором кластера. Уровни refs → local → cluster → envoyfilter, каждый следующий только по эскалации. EnvoyFilter — крайний случай, без анализа содержимого. (Решение 2026-10-23.)
