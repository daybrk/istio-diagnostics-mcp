# ASTRA User Project Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans. The user requested the behavior change on the existing branch; implement without another approval handoff.

**Goal:** Let users supply an ASTRA project ID in conversation and let the client agent use it when useful, without an enable switch or a preconfigured project in local mode.

**Architecture:** Infer ASTRA availability from configured endpoints/credential environment variable. Keep explicit per-call project IDs and existing HTTP principal authorization. Publish revised embedded agent playbooks.

**Tech Stack:** Existing Go 1.25 / MCP SDK; no new dependencies.

**Spec:** ../specs/2026-10-23-astra-user-project-design.md

## Global Constraints

- Same feat/go-mcp-v0.1 branch and PR #1; no main merge.
- No real credentials or network calls to a live cluster/ASTRA in tests.
- No implicit project selection, no HTTP authorization expansion.
- Legacy explicit enabled:false and empty allowlists continue to deny access.
- MCP wire contract 2026-10-22; prompt bundle 2026-10-23.

## Review Focus

- Omitted versus empty allowed_projects must have different semantics.
- HTTP subjects cannot inherit local stdio credential-wide access.
- No project or missing configuration cannot cause upstream I/O.
- Changing credentials/configuration must not expose a prior broader session.
- Prompt metadata, resources, manifest hashes and runtime bundle version agree.

## Task 1: Configuration and authorization

Files: internal/core/config.go/types.go, internal/astra/client.go/normalize.go,
internal/engine/catalog.go/product.go/engine.go, internal/transport/http.go; their tests;
docs/design/contracts/config.schema.json.
Interfaces: AstraConfig.Available() bool; Principal.AstraCredentialScope bool;
AstraConfig.ProjectAllowed(string) bool; existing Query and MCP inputs unchanged.

- [x] Add failing config and MCP fixture tests for auto availability and a user-supplied project with no catalog/allowlist.
- [x] Verify RED; implement optional legacy switch and explicit global/principal scope intersection.
- [x] Cover deny-all, legacy disabled, missing ID, missing token, HTTP permissions and narrowed historical scope.
- [x] Run core/astra/engine/transport tests.

## Task 2: Agent workflow, examples and publication

Files: docs/design/prompts/main.md/integrations/astra.md/manifest.json,
docs/design/assets.go/assets_test.go, internal/engine/view.go/catalog.go,
internal/transport/server.go, README and ASTRA/config documentation/examples.
Interfaces: design.PromptVersion; wire contract and tool count unchanged.

- [x] Revise prompts: explicit user project wins; ask ASTRA for relevant product/Istio knowledge gaps; no mandatory catalog; preserve evidence boundaries.
- [x] Update bundle metadata/hashes, tool description, operator instructions and runnable config example without enabled/allowed_projects.
- [x] Verify prompt resource and tool result versions, run race suite, vet, build and artifact validator.
- [x] Independent review and fix material findings before publication.

Publication target: existing branch/PR; remote commit and CI results are recorded in PR #1 and the handoff.

## Execution record

- Task 1: focused config, adapter, engine and transport tests pass. Direct user
  project and optional config tests were observed RED before implementation.
- Empty allowlist serialization regression observed RED → GREEN using Go 1.25
  `omitzero`, preserving nil versus explicitly empty slices.
- Task 2: runtime prompt version and endpoint-specific action tests observed
  RED → GREEN; examples and embedded modules now use bundle 2026-10-23.
- Endpoint availability metadata now advertises only actions supported by the
  configured endpoint(s), so a search-only deployment guides the client correctly.
- Full validation passed: race suite across all eight packages, vet, build,
  both CLI config checks, formatting/diff checks; artifact validator confirms
  11 tools, 20 cases, 2 config examples, 2 negative configs and 7 prompt hashes.
- Independent fresh-context review: no Critical, Important or Minor findings;
  focused tests and hashes independently verified.
- Final ruling: no in-process configuration reload is implemented; configuration
  changes require restart and discard in-memory sessions. Hypothetical reload
  revocation is outside current reachable behavior; adding reload later requires
  revisiting session authorization rather than reusing this conclusion.
- Final ruling: live ASTRA compatibility and upstream permission changes were
  not verified without the real service/key. Local fixtures establish adapter
  and scope behavior only; deployment may still encounter upstream mismatch or
  denied access. Such failures must remain optional knowledge-job failures.
