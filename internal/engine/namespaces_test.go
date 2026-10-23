package engine

import (
	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
	"testing"
)

func TestStartAcceptsWorkloadAndPeerOutsideLegacyNamespaceList(t *testing.T) {
	e, f, p := setup(t)
	p.Scopes = []core.Scope{{Context: "test-cluster", Namespaces: []string{"old-only"}}}
	args := startArgs("all-namespaces")
	args["workload"] = map[string]any{"context": "test-cluster", "namespace": "new-app", "kind": "Pod", "name": "worker"}
	args["peer"] = map[string]any{"kind": "service", "value": "kubernetes", "namespace": "default", "port": 443}
	d := diagnosis(t, call(t, e, p, "start_diagnosis", args))
	d = settled(t, e, p, d.DiagnosisID)
	if f.calls.Load() != 1 || d.Workload == nil || d.Workload.Namespace != "new-app" || d.State == "needs_clarification" {
		t.Fatalf("did not collect cross-namespace request: %+v", d)
	}
}

func TestNamespaceIsNotInferredFromLegacyScope(t *testing.T) {
	p := core.Principal{Scopes: []core.Scope{{Context: "cluster", Namespaces: []string{"old-only"}}}}
	q, ask, err := normalizeQuery(core.WorkloadQuery{Kind: "Pod", Name: "worker"}, p)
	if err != nil || ask == nil || ask.Field != "workload.namespace" || q.Namespace != "" {
		t.Fatalf("q=%+v ask=%+v err=%v", q, ask, err)
	}
}
