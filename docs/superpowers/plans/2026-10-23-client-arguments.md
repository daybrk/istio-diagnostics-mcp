# Client argument compatibility and bounded recovery

## Scope and evidence

The first Qwen Code investigation never reached collection: nested workload,
peer and time-window objects were serialized as strings and rejected during
argument validation. Changing the target or time window cannot repair this.
The installed client/model version is unknown; do not attribute the encoding
to one particular Qwen component or claim a live cluster diagnosis succeeded.

Keep branch `feat/go-mcp-v0.1`, the existing API, read-only collection, principal
scope and ASTRA authorization. Use synthetic names in all public fixtures.

## Task 1: Transport compatibility (RED → GREEN)

Files: `docs/design/assets.go`, `internal/transport/server.go`, a transport
argument helper and regression tests.

1. Reproduce rejection using the actual `tools/list` schema as a client-side
   validator, followed by a real in-memory MCP exchange.
2. Inline input schema references for discoverability. Advertise native objects
   first and a bounded JSON-string alternative only for start's workload, peer,
   time_window and refresh's time_window. Keep canonical contracts strict.
3. Decode those strings once, require JSON objects, then run canonical validation
   before dispatch. Never recursively decode unrelated text. Invalid mode fields,
   unknown fields, malformed JSON, arrays, null and double encoding must fail
   without dispatch. Object and encoded-object forms must dispatch the same data.
4. Verify the focused transport/design tests. Expected: all green, unchanged
   canonical rejection of strings and unchanged output discovery size limits.

## Task 2: Agent recovery and delivery

Files: initialization instructions, main/intake prompts, manifest, API and README.

1. Deliver startup instructions during MCP initialize and in tool descriptions.
   Load capabilities and intake before starting; resolve before consuming a
   candidate. Use actual identity, never guess an owner or label selector.
2. On argument validation failure, permit one corrected retry; then report an
   integration failure with the retained input. Do not change scope/time, invent
   timestamps, invoke unrelated tools or use ASTRA as substitute collection.
3. Publish prompt bundle `2026-10-23.1`; regenerate hashes and example metadata.
   Document rebuilding the configured binary and restarting Qwen to reload tools.
4. Run race tests, vet, build and artifact validation. Request one fresh-context
   review of the final change, address material findings and publish to existing
   branch/PR. Expected: local checks and GitHub CI pass; no claim of live Qwen or
   Kubernetes verification.

Shared interface: discovery permits encoded strings, transport normalizes them,
engine continues to accept only canonical objects. Both layers are needed because
client validation can reject a call before it reaches Go. Prompt instructions
reduce agent retry loops but cannot enforce a third-party model's behavior.
