# Deterministic snapshot evaluators

`Analyze(snapshot, selected)` performs no network or filesystem I/O and does not
mutate its input. IDs use `core.NewID`; evaluations and ordering otherwise depend
only on the supplied snapshot. `SupportedChecks` advertises 19 bounded rule
families. Every catalog rule produces an explicit result. Product expectations
remain `UNSUPPORTED` without separately supplied versioned product knowledge.

The parser supports Kubernetes-timestamped Istio default 22-field access text,
flat structured JSON access fields (including common snake/camel case variants),
and recognized plain/JSON diagnostic levels. The Kubernetes prefix determines
membership in the frozen `[start,end)` window. Unrecognized records retain an
example and an explicit limitation. Counts are **log records**, including retries,
duplicates, and both sides when available; they are never labeled unique requests.
HTTP/2 alone does not imply gRPC, and TCP never acquires inferred HTTP fields.

| Rule family | Implemented boundary |
| --- | --- |
| Readiness/startup | Regular and native init-container proxy status; recognized startup errors; no restart-to-cause inference |
| Services | Complete `EndpointSliceList` markers establish absence; readiness and numeric/named target ports; no listening-process inference |
| Route/cluster | Envoy admin v3 active config; bounded listener/filter-chain selection, exact/prefix path and selected pseudo-header matchers, exact/wildcard virtual-host domains, RDS/inline routes, direct/weighted cluster references |
| Listener/shadowing/xDS | Explicit rejected overlaps, unconditional exact/prefix route shadowing, separate active/rejected/warming state |
| TLS/SDS | Selected direct transport sockets, active-secret presence, certificate association by secret name or public active-secret PEM serial; single-source/single-destination TLS mode comparison |
| Authorization/JWT | Recognized RBAC/JWT/JWKS denial mechanisms; namespace DENY operation subset, including missing HTTP attributes on TCP; CUSTOM/targetRefs and broader policy semantics remain explicit boundaries |
| NetworkPolicy | Complete namespace policy sets, isolation/allow unions, matchLabels and observed IP/port subset; no CNI/NAT/conntrack causality claim |
| Symptoms/protocol/DNS | Recorded refusal/reset/timeout, HTTP and gRPC outcomes, recognized DNS symptoms; no exact process/resolver cause from flags/status alone |
| Replicas | Selected active cluster semantics and available Envoy versions, grouped by source/destination role |

Current snapshots establish current configuration facts. They do not reconstruct
historical routes, endpoint membership, secret rotations, Pod IP continuity, or
handshakes. The evaluator never promotes those facts, flags, or status codes to a
confirmed incident root cause. Missing sources are `UNKNOWN`; unsupported matcher
or extension semantics are never skipped as a successful match. Cluster transport
socket matches, complex filter-chain selection, arbitrary headers, regex/extension
matchers, full effective authorization, and many policy selector/protocol forms
remain bounded unknown/unsupported cases. No Cartesian replica correlation or
external DNS/JWKS/application probe is attempted.

Fixtures include positive, negative, incomplete, malformed, and temporal cases.
Run `go test ./internal/diagnostics`, `go test -race ./internal/diagnostics`, and
`go vet ./internal/diagnostics`. Live-cluster accuracy has not been established by
these synthetic fixtures.
