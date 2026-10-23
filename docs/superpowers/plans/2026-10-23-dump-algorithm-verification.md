# Проверка алгоритма «CRD от дампа» на живом кластере

Дата: 2026-10-23. Относится к [дизайну MVP](../specs/2026-10-23-istio-diagnostics-design.md), разделы 5.2–5.3.

## Зачем

Дизайн опирается на допущения о содержимом дампа Envoy и поведении Istio, которые взяты из памяти, а не проверены на целевой версии. Если хотя бы одно не подтвердится, меняется модель или список уровней поиска. Проверяем до написания кода.

## Что нужно

- Кластер с Istio (sidecar mode), доступ по kubeconfig с правами пользователя, под которым будет работать сервер.
- bookinfo или любая пара сервисов A→B через HTTP, у B есть хотя бы один VirtualService и один DestinationRule с subset. Без них часть допущений останется `UNKNOWN`.
- Машина с kubeconfig: `kubectl`, `jq`, `curl`. Linux: `test/scripts/check-dump-assumptions.sh` (bash 4+). macOS: `test/scripts/check-dump-assumptions-macos.sh` (системный bash 3.2, `brew install jq`). Логика одинаковая. С Windows не запускается: нет jq и port-forward в фоне ведёт себя иначе.

## Допущения и критерии

| ID | Допущение | Как проверяем | PASS | Если FAIL |
|---|---|---|---|---|
| A1 | Прав `create pods/portforward`, `get pods/log`, `get pods/proxy` достаточно; cluster-wide list CRD может отсутствовать | `kubectl auth can-i` | три первых `yes` | Переписать раздел RBAC в дизайне |
| A2 | Маски `resource=` и `name_regex` на `/config_dump` работают, дамп с масками заметно меньше полного | 4 запроса с масками + 1 полный, размеры и время | в каждом ответе один `@type`; `name_regex` отфильтровал; сумма масок < полного | Фильтровать в Go, пересмотреть лимит `dump_bytes` |
| A3 | Routes несут `metadata.filter_metadata.istio.config` со ссылкой на VS в формате `/apis/.../namespaces/<ns>/virtual-service/<name>` | обход listener → RDS → vhost по host → routes | ≥1 route с ссылкой на VS, формат совпал | Winners для VS брать через `local`, уровень `refs` сужается |
| A4 | Clusters несут `istio.config` на DR | clusters по `\|port\|*\|host` | у subset-кластеров ссылка на DR | То же для DR |
| A5 | Clusters несут `istio.services[]` `{host,name,namespace}` | те же clusters | поле есть | ServiceEntry искать на уровне `local` |
| A6 | У listeners/routes/clusters есть `last_updated` и `version_info` | jq по дампу | поля есть | Убрать `changed_after_load` из 5.3 |
| A7 | Sidecar-ресурс в дампе виден только как эффект, имени нет | grep `/sidecar/` в дампе при наличии Sidecar в кластере | открытый вопрос: любой результат ценен | Если имя есть, Sidecar переезжает на уровень `refs` |
| A8 | Inbound mTLS mode читается из filter chains `virtualInbound` по `transport_protocol`; имени PeerAuthentication в дампе нет | дамп pod'а B | набор `tls`/`raw_buffer` по порту; строки `peer-authentication` нет | Пересмотреть `tls-consistency` |
| A9 | AuthorizationPolicy читается из id правил RBAC-фильтра `ns[<ns>]-policy[<name>]-rule[<n>]` | дамп pod'а B | при наличии AuthPolicy в ns B id такого вида есть | AuthPolicy на уровень `local` |
| A10 | `/debug/syncz` через `pods/proxy` GET отдаёт sent/acked nonce по proxy; при нескольких istiod нужно опросить все | `kubectl get --raw` по каждому istiod pod'у | запись для pod'а A найдена хотя бы у одного istiod | Пересмотреть `proxy-connectivity` |
| A11 | Ссылка из `istio.config` превращается в `kubectl get` без дополнительного поиска | parse пути → `get -o resourceVersion` | каждый winner получен | Уровень `refs` неработоспособен, план поиска пересматривается |
| A12 | Путь A→B целиком проходится по дампу: listener → RDS → vhost → route → cluster → endpoints | скрипт печатает цепочку | каждое звено непустое | Найти, где обрыв, уточнить 5.3 «Построение пути» |

## Порядок

### 1. Автоматическая часть, 5 минут

```sh
cd test/scripts
SRC_NS=default SRC_WORKLOAD=productpage-v1 \
DST_HOST=reviews.default.svc.cluster.local DST_PORT=9080 \
bash check-dump-assumptions.sh
```

Переменные: `SRC_NS`, `SRC_WORKLOAD` (deployment), `DST_HOST` (FQDN или короткое имя), `DST_PORT`, `ISTIO_NS`, `LOCAL_PORT`, `KCTX`, `OUT`. Дефолты под bookinfo в `default`.

Результат: таблица `A1..A12` со статусами `PASS`/`FAIL`/`UNKNOWN` и сырые дампы в `out/<timestamp>/`. `UNKNOWN` значит «в кластере нет ресурса, на котором это проверяется»: нужно добавить ресурс и повторить.

### 2. Ручные эксперименты, по одному, с откатом

Меняют кластер, поэтому не в скрипте. Каждый: применить, подождать 5 секунд, повторить скрипт, откатить.

**M1. exportTo без `.` скрывает ресурс в своём ns.** В ns B создать VS на host B с `exportTo: ["some-other-ns"]` и заведомо ломающим route. Ожидание: в дампе A ссылки на этот VS нет, трафик A→B работает. Потом `exportTo: [".", "some-other-ns"]`: ссылка появилась. Влияет на шаг 4 алгоритма `get_istio_resources`.

**M2. VS из чужого ns через exportTo виден в дампе A.** В ns C создать VS на host B с `exportTo: ["<ns A>"]`. Ожидание: ссылка `/namespaces/C/virtual-service/...` в routes дампа A. Подтверждает, что уровень `cluster` нужен только для объяснения, а не для обнаружения winner'а.

**M3. STALE в syncz воспроизводится.** Сломать проверку istiod → proxy нельзя без мутаций, поэтому проверяем только формат: сразу после `kubectl apply` нового VS снять syncz в цикле раз в секунду и поймать момент `sent != acked`. Если за 10 попыток не поймали, оставляем формат как есть и помечаем `UNKNOWN`.

**M4. forbidden на portforward даёт понятную ошибку.** Создать в ns A ServiceAccount + Role с `get/list pods` без `pods/portforward`, выпустить токен `kubectl create token`, запустить скрипт с этим kubeconfig. Ожидание: A1 `no`, port-forward падает с `forbidden`, остальные шаги не выполняются. Это поведение `analyze_path` по дизайну.

**M5. Объём на массе (сценарий 8).** Применить 100 Gateway + VS + DR в отдельном ns, повторить шаг 1, сравнить размеры и время A2 до и после. Целевых чисел нет, нужен факт для раздела 10.

### 3. Что записать

По итогам в дизайн вносятся только изменения из колонки «Если FAIL». Результаты таблицы и числа из M5 сохраняются рядом с этим планом как `2026-10-23-dump-algorithm-verification-results.md` с версией Istio и дистрибутивом.
