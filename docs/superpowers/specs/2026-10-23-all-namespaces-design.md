# Remove namespace allowlists

The user explicitly requested removal of namespace restrictions. Keep the Go
server, current branch and read-only workflow. Every assigned Kubernetes context
allows diagnostics in every namespace accessible through the server's kubeconfig.
HTTP authentication, context assignments, session ownership and ASTRA project
permissions remain enforced. No Kubernetes RBAC changes are performed.

Remove namespace enforcement rather than merely making the old list optional:
otherwise existing configurations would retain the exact restriction the user
asked to remove. Accept legacy `namespaces` configuration fields, ignore their
values, and report this migration on stderr. New examples specify only context.
Capabilities retain their existing shape and advertise `namespaces: ["*"]`.
This wildcard describes server scope, not a Kubernetes permission guarantee.

The workload's namespace is still part of its identity. Ask when it is missing;
never infer it from an obsolete allowlist or pass `*` as a workload namespace.
An explicitly supplied peer may be in any namespace of the selected context.

Read resource metadata across namespaces with bounded `kubectl get ...
--all-namespaces` calls. Preserve namespace attribution and complete-list markers
used by existing diagnostic rules. Keep logs/dumps limited to actual selected
participants, with the frozen window, UID guards, byte and time budgets. If an
all-namespace read is forbidden, attempt the selected source/peer namespaces and
report incomplete cluster coverage. Namespace enumeration is not a prerequisite
for reading workload resources. A denied Kubernetes read remains a coverage gap.

Alternatives considered: optional namespace lists would preserve unwanted old
restrictions; enumerating namespaces then issuing every resource request in each
namespace would multiply calls and require namespace-list permission. Choose
context-only authorization and cluster-wide resource lists with bounded fallback.

Verification: omitted/legacy config, cross-namespace workload/peer discovery,
missing namespace clarification, retained context/auth/session restrictions,
all-namespace list attribution, partial RBAC failures, and successful empty lists.
No changes to Istio port rules or gateway support are included in this patch.
