# ASTRA-SBT · необязательный адаптер

[Навигация](README.md) · [API](api.md) · [Промпт](prompts/integrations/astra.md)

**Default off.** Нет требований к ASTRA URL/ключу/projectId для запуска и
основной диагностики. Контракт основан на переданном пользователем справочнике
«Справочник инструментов MCP», имя сервера `ASTRA-SBT MCP`. Подключение к реальной
установке и её авторизация ещё не проверялись. Полный внутренний справочник с
адресами корпоративного портала не публикуется в репозитории.

## Предлагаемая интеграция

Оператор может настроить default и/или agent endpoint. `/mcp` предоставляет
каталог/поиск/чтение; `/mcp/agent` — только agent_loop. Инструмент вне своего
режима не вызывается по имени. При подключении adapter сверяет tools/list и
схемы разрешённых инструментов; методология initialize — внешний текст, не
исполняемая программа Go и не расширение полномочий диагностического сервера.

| Наш `get_product_context.action` | Upstream tool | Точный перевод |
|---|---|---|
| `catalog` | `rag_catalog` | project_id → projectId, includeFullSpecification=false |
| `ask` | `agent_loop` | question → message, project_id → projectId, repo?, mode=simple/advanced |
| `search` | `semantic_search` | query, projectId, repo?, top_k=5, mode=hybrid |
| `source` | `read_file` | projectId, repo, path, offset (1-based), limit (≤400) |

Никакой generic `call_tool(name,args)` наружу не предоставляется. Git и прочие
инструменты ASTRA не вызываются этим адаптером. Отсутствие нужного endpoint/tool
даёт UPSTREAM_CONTRACT_MISMATCH только этой optional операции.

Source path — относительный POSIX-путь внутри выбранного репозитория, без `..`,
абсолютного пути или URL. Repo проверяется по каталогу разрешённого проекта.
Вызов product context допускается после создания attempt; до этого возвращается
INVALID_STATE с предложением завершить идентификацию основного workload.

Каждая операция привязана к diagnosis/principal и отдельному operation_id;
возвращается job, результат появляется в knowledge records `get_diagnosis`.
Большой ответ читается через evidence ID. `advanced` запускается только явным
mode аргументом; simple не эскалируется автоматически из-за пустого ответа.
Параметр repo у agent_loop — мягкий hint и не граница авторизации.

## Формы upstream ответов

| Tool | Известный контракт | Нормализация |
|---|---|---|
| rag_catalog без projectId | `{projects,totalProjects,hint}` | Список проектов; без обязательного чтения полных спецификаций |
| rag_catalog с projectId | Массив проектов с repos | Список репозиториев выбранного проекта |
| agent_loop | `{answer: string, meta: object}` | Текст и usage summary; citations/структурированные requirements не гарантированы |
| semantic_search | results/total/meta; citation у chunk | Сохранить исходную citation, repo/path, доступные lines |
| read_file | content + meta | Фрагмент из индекса; lineFrom/lineTo/totalLines и guardApplied при наличии |

Справочник неоднозначно описывает multi-project selection: в одном месте
`meta.projects/projectSelectionRequired`, в другом `meta.catalog`. Adapter должен
иметь fixtures для обеих документированных форм. Неизвестная форма даёт contract
mismatch, а не пустой набор зависимостей. `results:[]` с подсказкой выбора не
считается успешным доказательством отсутствия данных.

## Область и идентичность

Для ask/search/source project_id передаётся явно. Нельзя полагаться на серверный
MCP_PROJECT_ID в общем сервисе с несколькими пользователями. Mapping workload →
project_id может быть задан оператором либо выбран пользователем из доступного
каталога; название Deployment не считается кодом продукта автоматически.
Локальный allowlist проектов пересекается с правами upstream credentials.
Каталог фильтруется до передачи клиенту; общие credentials не дают пользователям
читать проекты за пределами их назначенного scope.

Сначала проверить configured/enabled/allowed principal; только затем устанавливать
внешнее соединение. Нет automatic probing URL из документа, пользовательского
лога или ответа ASTRA. Настройки endpoint и credentials доступны только оператору.

## Ошибки и деградация

| Upstream | Наш результат | Повтор |
|---|---|---|
| project_not_found | Выбор из доступных suggestions/catalog | После исправления ID |
| project_access_denied / 403 | UPSTREAM_FORBIDDEN | Нет автоматического повтора/перебора |
| project_has_no_enabled_repos | Контекст недоступен для этого проекта | Не выбирать другой проект молча |
| project_id_placeholder / invalid | Ошибка настройки/ввода | После исправления |
| repo_not_found / file_not_found | Недоступный конкретный источник | Не считать доказательством отсутствия требования |
| repo_reindexing / 409 | Временно unavailable | Не более одного retry в бюджете |
| MCP protocol error / timeout / 5xx | UPSTREAM_UNAVAILABLE | Один transient retry, deadline не продлевается |

ASTRA failures не меняют исход основного diagnostic job и не удаляют его evidence.
При disabled нет вопросов о выборе проекта. Необходимость уточнения projectId
останавливает только product-context job.

## Доказательства и данные

Передавать продукт/версию, выбранную связь, краткую сигнатуру ошибки и необходимые
очищенные факты. Внешние данные не включают kubeconfig, tokens, private keys,
полные dump'ы или потоки логов. Клиентская question тоже проходит ограничение
размера и redaction; сервер не добавляет скрытые сырые данные по своему усмотрению.

Сохранить provider, project/repo/path, original citation, retrieved_at и доступную
revision. Index read, disk read и deployed image могут относиться к разным
ревизиям. HEAD из git не доказывает свежесть Qdrant; в этом контракте индекс не
обещает commit-pinned чтение. Неизвестную revision обозначать unknown.

Требование продукта — expected behavior. Live observation — отдельный источник.
Ссылка на файл укрепляет проверяемость ответа, но не подтверждает причинность
сетевого сбоя. Свободный текст разбирает клиентский агент; поддержанные Go-правила
по-прежнему требуют собственных доказательств. Optional caching в текущем проекте
ограничено сессией и её principal, project и версией; общего межпользовательского
кэша ответов нет.
