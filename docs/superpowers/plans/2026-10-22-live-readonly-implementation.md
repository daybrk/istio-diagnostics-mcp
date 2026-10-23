# Live read-only MCP implementation plan

> **For agentic workers:** Use Superpowers execution and verification practices. The user explicitly requested implementation now on `feat/go-mcp-v0.1`; continue without another approval handoff.

**Goal:** Ship the Go MCP server described by the existing live diagnostics contract.

**Architecture:** Embedded schemas and playbooks constrain every tool. A principal-scoped in-memory coordinator runs cancellable collector jobs and deterministic rules. Kubernetes access uses fixed kubectl arguments and loopback port-forward; optional ASTRA uses a constrained MCP client.

**Tech Stack:** Go 1.25+, official MCP Go SDK v1.8.0, jsonschema-go v0.4.3; standard-library subprocess/HTTP/crypto.

**Spec:** ../../design/README.md and ../../design/api.md; schemas are authoritative for wire shapes.

## Global Constraints

- Work in the existing `feat/go-mcp-v0.1` branch; do not merge main.
- Live read-only; no exec, probes, Secrets, application logs or arbitrary admin URLs.
- All replicas, one frozen [start,end) window; default 900 seconds only when omitted.
- Stdio and authenticated Streamable HTTP; principal ownership on every lookup.
- ASTRA disabled by default; failure must not block diagnostics.
- Unknown data and unsupported evaluators remain explicit; no claims of live-cluster verification without a cluster.

## Review Focus

- Pod name reused with a different UID: reject snapshot attribution and close the tunnel.
- Partial/denied namespace reads: preserve unknown coverage, never infer absent resources.
- Cancellation and HTTP disconnect: jobs survive disconnect, explicit cancel closes child processes.
- Cross-principal session/evidence/cursor lookup: indistinguishable not-found and no scope expansion.
- Huge/malformed logs, schemas and upstream responses: bounded memory and explicit truncation.

## Task 1: Shared contracts and configuration

Files: `docs/design/assets.go`, `internal/core/{models,config,types,helpers}.go` and tests.
Interfaces: generated API models; `core.Collector.Resolve/Collect`, `core.Snapshot`, `core.Analysis`, `core.Principal`, `core.Config`, `core.Handler.Call`.
- [x] Write tests for frozen windows, scope intersection, config rejection and bundled schema validation; observe failures.
- [x] Embed existing artifacts without duplicating or changing prompt hashes; implement shared types and validation.
- [x] Verify `go test ./internal/core ./docs/design`.

## Task 2: Live collector

Files: `internal/live/` only. Consumes core interfaces; produces `live.New(core.Config) *live.Collector` implementing core.Collector.
- [x] Tests for owner UID resolution, every replica, scoped fixed argv, current/previous time-filtered proxy logs, bounded output, cancellation and UID replacement.
- [x] Implement resource reads and fixed port-forward endpoints with concurrency/deadline limits; retain errors per source.
- [x] Verify `go test ./internal/live`.

## Task 3: Deterministic analysis

Files: `internal/diagnostics/` only. Produces `Analyze(*core.Snapshot,*core.Connection) core.Analysis` and `SupportedChecks() []string`.
- [x] Tests for JSON/default access logs, failure grouping, readiness, endpoints/ports, xDS, route/cluster references, TLS and incomplete/unsupported data.
- [x] Implement evidence-backed checks without equating static configuration with network success; include unsupported boundaries for remaining catalog rules.
- [x] Verify `go test ./internal/diagnostics`.

## Task 4: Transports and optional product adapter

Files: `internal/transport/`, `internal/astra/` only. `transport.NewServer(core.Handler,core.Config)`, `transport.HTTPHandler(core.Handler,core.Config)`; `astra.New(core.Config)` implements core.ProductProvider.
- [x] Tests for official MCP initialize/list/call, self-contained schemas, authenticated subject scope, invalid JWT/origin, redacted bounded ASTRA mapping and default-off no-I/O.
- [x] Implement stdio/Streamable HTTP with verified OIDC JWT, allowed origins, fixed ASTRA tools and tools/list validation.
- [x] Verify `go test ./internal/transport ./internal/astra`.

## Task 5: Session coordinator

Files: `internal/engine/`. Consumes collector/analyzer/provider; produces `engine.New(config,collector,provider,analyzer,checks)`, `Call`, `Close`.
- [x] Tests for clarification, direct pair, queue selection, async poll, idempotency, cancellation, TTL, ownership, memory and revision-bound pagination, refresh comparisons.
- [x] Implement all eleven tools; keep historical attempts and evidence locators, freeze windows, expose coverage and next actions.
- [x] Verify `go test -race ./internal/engine` with deterministic collector fixtures.

## Task 6: Runnable application and integration

Files: `cmd/istio-diagnostics-mcp/`, README, CI, Dockerfile, examples/config, implementation-status document.
- [x] Add CLI config loading and signal cleanup; wire real collector/analysis/provider/transports.
- [x] End-to-end stdio and HTTP protocol smoke tests; all output shapes validate against embedded contracts.
- [x] Run `go test -race ./...`, `go vet ./...`, build, artifact validator and fresh independent review; fix actionable findings.
- [x] Publish commits to the same branch and update PR #1 with actual implementation, checks and remaining live-environment limitations.

Independent component tasks 2–4 can run concurrently once Task 1 interfaces are fixed; each owns separate directories. Coordinator integration stays with the main implementer. No agent may commit another agent's work.

## Execution record

- Tasks 1–6 implemented on the existing branch. Components 2–4 were developed
  independently against the shared core interfaces; coordinator integration and
  the consolidated review fix pass were performed by the main implementer.
- Independent whole-implementation review: 0 Critical, 8 Important defects.
  All nine reproductions first failed and now pass as repository regressions.
- Fixed: direct-pair identities and unspecified metadata; discovered IP decoding;
  metadata/replay memory admission; backend listener selection; unrelated denied
  controller list blocking a named Pod; revoked creation replay; malformed Envoy
  sections treated as empty; historical knowledge completion/quota.
- Additional failing regressions fixed: quoted multiword credential redaction,
  and both proxy-side records mapped through UID-bound EndpointSlice ports.
- Retained-state byte accounting is not a Go RSS ceiling. Diagnostics serialize
  collection/analysis across sessions, keep per-pod concurrency inside a job,
  limit analysis materialization, and report explicit incomplete data on limits.
- Real cluster, external ASTRA/provider and Docker image were not exercised here;
  repository fixtures and protocol smoke tests do not replace those checks.

Final verification: `go test -race ./...` — all eight packages passed;
`go vet ./...`, `go build -trimpath`, `-check-config`, formatting and
`git diff --check` passed. Artifact validator: 11 tools, 20 cases, two
negative configs, seven prompt hashes, 98 local links. Compiled stdio
binary smoke outside the repository directory passed. Publication targets
the existing branch and PR #1; main is not merged.
