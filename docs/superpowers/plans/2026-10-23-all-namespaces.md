# All Namespaces Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for inline execution and one final independent review.

**Goal:** Remove server namespace allowlists within assigned Kubernetes contexts.
**Architecture:** Context-only principals; bounded cluster resource lists; explicit workload identity.
**Tech Stack:** Existing Go/MCP SDK/kubectl implementation.
**Spec:** `docs/superpowers/specs/2026-10-23-all-namespaces-design.md`.

## Global Constraints

- Use existing `feat/go-mcp-v0.1` and PR; no main merge or Kubernetes mutations.
- Preserve context, HTTP identity, session and ASTRA authorization.
- Legacy namespaces are accepted but ignored; never used as defaults.
- Logs/dumps remain restricted to the selected participants and window.

## Review Focus

- Old HTTP namespace lists must not silently retain restrictions; stderr documents the migration.
- Missing workload namespace must not resolve to `*` or the old first namespace.
- Empty cross-namespace lists must remain distinguishable from failed reads.
- Denied namespace enumeration must not suppress available workload data.
- Context revocation must still hide sessions and creation replay.

### Task 1: Context authorization and configuration

Files: core config/types, config schema, engine intake/session handling, HTTP tests.
Interface: principals match contexts only; canonical capability scopes use `["*"]`.

- [x] Add regression tests for omitted/legacy namespaces and cross-namespace intake.
- [x] Run focused tests; expect rejection under the old namespace restrictions.
- [x] Remove namespace authorization/defaults, keep context checks, warn on legacy config.
- [x] Update tests for deliberately changed semantics; retain context revocation checks.
- [x] Run core/engine/transport tests; expect PASS.

### Task 2: Resource collection across namespaces

Files: live resolver/collector and regression tests.
Interface: `readResources` receives selected namespaces as fallback hints, never as limits.

- [x] Test cross-namespace lists, Kubernetes denial, empty-list completeness and wrong-context rejection.
- [x] Run tests; expect cross-namespace discovery to fail under the old collector.
- [x] Add fixed all-namespace list arguments and namespace identity checks.
- [x] Group resource/list evidence by real namespace; bounded selected-namespace fallback on Forbidden.
- [x] Run live/diagnostics tests and race suite; expect PASS.

### Task 3: Documentation and delivery

Files: README, API/config/RBAC examples, runtime prompts and manifest, current artifact metadata.

- [x] Explain all namespaces within assigned contexts, kubeconfig RBAC and legacy migration.
- [x] Publish prompt bundle `2026-10-23.2`; regenerate hashes and consistent examples.
- [x] Run race tests, vet, build, check-config, artifact checker and stdio smoke.
- [x] Get one independent read-only review and address material findings.

Delivery: publish the same branch/PR and verify CI.

Review found unbudgeted per-namespace list-marker expansion. Added atomic
namespace-kind materialization with byte accounting, selected-namespace priority,
cancellation checks and a 1,000-namespace regression. Re-review and the full
verification suite passed.
