# Источники и происхождение требований

[Навигация](README.md) · Дата проверки интерфейсов: 22 октября 2026.

## Приоритет источников

Прямые решения пользователя задают scope и разрешённые операции. Официальные
спецификации уточняют интерфейсы. Вложения описывают пользовательское окружение,
но наличие документа не доказывает реальный доступ. GitHub issues дают проверочные
сценарии, не статистику production-инцидентов и не диагноз кластера пользователя.

## MCP

- [Архитектура MCP](https://modelcontextprotocol.io/docs/2026-07-28/learn/architecture).
- [Go SDK: clients и servers](https://github.com/modelcontextprotocol/go-sdk).
- [Tools, схемы и results](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).
- [Stdio и Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).
- [Resources и управление контекстом клиентом](https://modelcontextprotocol.io/specification/2025-11-25/server/resources).
- [Prompts и их получение](https://modelcontextprotocol.io/specification/2025-11-25/server/prompts).
- [Lifecycle и согласование capabilities](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle).

Версионные ссылки закрепляют использованные описания механизмов, а не требование
всегда договариваться о protocolVersion 2025-11-25. Фактическая negotiated version
определяется клиентом и SDK; app contract `2026-10-22` версионируется независимо.

## Kubernetes, Envoy и Istio

- [kubectl logs](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_logs/).
- [Logging architecture и ротация](https://kubernetes.io/docs/concepts/cluster-administration/logging/).
- [kubectl port-forward](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_port-forward/).
- [RBAC и subresources](https://kubernetes.io/docs/reference/access-authn-authz/rbac/).
- [Envoy Admin](https://www.envoyproxy.io/docs/envoy/latest/operations/admin).
- [Envoy access logs](https://www.envoyproxy.io/docs/envoy/latest/configuration/observability/access_log/usage.html).
- [Istio network issues](https://istio.io/latest/docs/ops/common-problems/network-issues/).
- [Istio security issues](https://istio.io/latest/docs/ops/common-problems/security-issues/).
- [AuthorizationPolicy](https://istio.io/latest/docs/reference/config/security/authorization-policy/).

Latest-документация не задаёт версию пользовательского кластера. Сбор должен
обнаруживать фактические версии; неизвестная семантика не становится PASS.

## Пользовательские материалы

- HTML корня Envoy Admin на 15000: подтверждает существование встроенного
  config_dump с include_eds в предоставленной странице; это не config dump.
- Markdown «Справочник инструментов MCP», ASTRA-SBT: режимы default/agent,
  параметры и ошибки. Использован для [описания адаптера](astra.md). Внутренние
  URL и исходное вложение не копируются в публичный репозиторий.
- [Историческая спецификация](../superpowers/specs/2026-10-22-live-readonly-diagnostics-design.md).
- [Исследование 21 Istio issue](../research/2026-10-22-istio-issue-coverage.md).

В исходном справочнике ASTRA есть две формы meta для выбора проекта. Это
сохранённое ограничение контракта, которое должно проверяться fixture-ами и
реальным tools/list, а не устраняться догадкой разработчика.
