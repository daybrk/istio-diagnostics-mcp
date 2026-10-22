# Сбор, конфигурация и доступ

[Навигация](README.md) · [Schema конфигурации](contracts/config.schema.json) ·
[Пример](examples/server-config.json)

## Kubernetes API

Используется фиксированный `kubectl` runner без shell. В аргументах всегда явные
context/namespace, timeout и формат вывода. Credentials только из выбранного
kubeconfig. Ни инструмент MCP, ни ответ ASTRA не могут передать команду runner.

| API group | Ресурсы | Verbs | Зачем |
|---|---|---|---|
| core | pods, services | get/list | UID, lifecycle, ports, selectors |
| apps | deployments, statefulsets, daemonsets, replicasets | get/list | Идентификация владельцев и rollout |
| discovery.k8s.io | endpointslices | get/list | Backend addresses, readiness, port mapping |
| networking.k8s.io | networkpolicies | get/list | Применимость ingress/egress policy |
| networking.istio.io | virtualservices, destinationrules, serviceentries, sidecars, envoyfilters | get/list | Routing, visibility, TLS и расширения |
| security.istio.io | authorizationpolicies, peerauthentications, requestauthentications | get/list | Политики выбранной связи |
| core | pods/log | get | Только container=istio-proxy, current/previous |
| core или events.k8s.io | events | get/list | Lifecycle/readiness с UID и временем; без дублирования двух API |
| core | namespaces | get/list в разрешённой области | Labels для namespaceSelector/injection/revision |
| core | pods/portforward | get/create по используемому транспорту | Connect к pod:15000 |

Не требуются Secrets, pods/exec, ephemeralcontainers или права менять workload.
Watch разрешён пользователем, но текущему запросному flow не обязателен.
Недоступные namespaces/root policies не заменяются пустыми списками.
Namespaced Role не может дать доступ к namespaces; его чтение требует отдельно
выданных cluster-scoped разрешений. Не расширять allowlist для получения этой информации.

[RBAC-пример](examples/rbac.yaml) — документ для администратора, не применяется
MCP. В нём нет RoleBinding и нет автоматической выдачи прав. Для каждого
диагностируемого и root-policy namespace оператор задаёт scope отдельно.

## Логи и время

Для каждого pod вызывать logs с `--container=istio-proxy --timestamps=true
--since-time=<start>`, отдельно `--previous=true` при наличии рестарта. Верхнюю
границу фильтровать локально: нельзя ожидать от kubectl logs флаг until.
Текущий и previous container instance различаются в evidence. Missing previous
не доказывает отсутствие предыдущего сбоя.

Duration помогает учесть завершившийся в окне запрос, начавшийся раньше, если его
строка доступна. Since-time, ротация, удаление pod, незавершённые TCP-сеансы и
буферизация ограничивают полноту; сервер не обещает восстановить все пересечения.
Ранняя прочитанная строка не устанавливает срок хранения. Формат и доля
неразобранных строк входят в coverage, исходные неизвестные поля не становятся нулями.

## Envoy API

1. Создать port-forward к конкретному pod UID/name; слушать только loopback.
2. Дождаться готовности или завершения child process в пределах timeout.
3. Go HTTP client делает фиксированные GET с response-byte limit и без redirects.
4. Закрыть tunnel при успехе, отмене, timeout, смене/удалении pod или shutdown.

| Endpoint | Назначение | Ограничение |
|---|---|---|
| `/config_dump?include_eds` | Active/warming/rejected listeners, routes, clusters, endpoints | Root HTML не является dump; неизвестный type_url остаётся неподдержанным |
| `/certs` | Доступные сведения сертификатов | Не доказывает использование конкретного cert выбранным соединением |
| `/clusters?format=json` | Доступное состояние clusters/hosts | Наличие host не доказывает успешное подключение |
| `/server_info` | Версия и состояние процесса | Текущее состояние, не история выбранного окна |

Список неизменяем через tool args. `/stats`, runtime mutations и произвольный
admin path не разрешены этим контрактом. У фиксированных endpoint версионный
parser; unsupported endpoint не останавливает остальные чтения.

## Лимиты: начальные предложения

| Настройка | Default | Поведение при достижении |
|---|---|---|
| Активные сессии | 16 | RESOURCE_LIMIT; не удалять активную чужую сессию |
| Session idle TTL | 1800 s | Очистка; expired вместо восстановления из выдуманного состояния |
| Общая память evidence | 256 MiB | Частичный результат; явное перечисление неполученного |
| Параллельные pod reads | 4 | Очередь всех pod'ов |
| Параллельные tunnels | 2 | Очередь; cleanup на каждый tunnel |
| Kubernetes request timeout | 15 s | Одна ограниченная повторная попытка transient ошибки |
| Diagnostic job budget | 120 s | Завершить partial; сохранить доступные результаты |
| Логи на container instance | 8 MiB | Truncated=true, remaining coverage unknown |
| Envoy response | 32 MiB | Отдельный resource_limit, не разбирать усечённый JSON |
| Ответ MCP | 512 KiB | Пагинация/evidence IDs, не скрытое усечение |
| ASTRA request budget | 45 s | Optional unavailable/partial, основная ветка продолжается |

Период логов не ограничен 15 минутами или TTL. Большое окно может превысить budget;
в таком случае вернуть запрошенное окно и фактическую полноту, а не другое окно.
Размер одного ответа ASTRA дополнительно ограничен конфигурацией адаптера.
Пустой поток при cap не обозначается как отсутствие ошибок.

## Конфигурация

Сервер принимает JSON-конфигурацию с schema_version, transport, kube, limits и astra
через `-config`. Пример используется текущим бинарником; `-check-config` проверяет его без сети.
Неизвестные поля отклоняются; секреты — через environment reference, не текст
файла или MCP args. При disabled ASTRA не проверять наличие её credentials и не
делать network discovery. HTTP режим без валидной auth config не стартует.

Kube context/namespace allowlist задаётся оператором. Запрос пользователя может
сузить, но не расширить её. Remote principal scope пересекается с этой областью.
Сервер работает на машине с доступом к API Kubernetes; локальный DNS этой машины
не используется как доказательство DNS приложения.
