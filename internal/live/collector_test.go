package live

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daybrk/istio-diagnostics-mcp/internal/diagnostics"
)

type fakeRunner struct {
	mu    sync.Mutex
	calls [][]string
	fail  string
	data  map[string]string
}

func (f *fakeRunner) Run(_ context.Context, p string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string{p}, args...))
	resource := p
	if p == "kubectl" {
		resource = args[3]
	}
	if resource == f.fail {
		return nil, errors.New("access denied by Kubernetes RBAC")
	}
	if v, ok := f.data[resource]; ok {
		return []byte(v), nil
	}
	if p == "istioctl" {
		return []byte(`{"configs":[{"@type":"type.googleapis.com/envoy.admin.v3.ListenersConfigDump","dynamic_listeners":[]}]}`), nil
	}
	if resource == "pods" {
		return []byte(`{"metadata":{"name":"api-1","namespace":"apps","labels":{"app":"api"}},"spec":{"containers":[{"env":[{"name":"PASSWORD","value":"secret-value"}]}]},"status":{"phase":"Running"}}`), nil
	}
	return []byte(`{"items":[]}`), nil
}
func collector(r Runner) Collector {
	return Collector{Config: Config{Enabled: true, Context: "test-context", Namespaces: []string{"apps"}}, Runner: r}
}
func TestLiveAccessGuards(t *testing.T) {
	for _, tc := range []struct {
		name, ns, pod string
		cfg           Config
	}{{"disabled", "apps", "api", Config{}}, {"no-context", "apps", "api", Config{Enabled: true, Namespaces: []string{"apps"}}}, {"wrong-namespace", "other", "api", Config{Enabled: true, Context: "test", Namespaces: []string{"apps"}}}, {"injection", "apps", "--all-namespaces", Config{Enabled: true, Context: "test", Namespaces: []string{"apps"}}}} {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeRunner{}
			_, e := (Collector{Config: tc.cfg, Runner: r}).Collect(context.Background(), tc.ns, tc.pod)
			if e == nil || len(r.calls) != 0 {
				t.Fatalf("error=%v calls=%v", e, r.calls)
			}
		})
	}
}
func TestPartialCollectionAndFixedCommands(t *testing.T) {
	r := &fakeRunner{fail: "networkpolicies.networking.k8s.io"}
	s, e := collector(r).Collect(context.Background(), "apps", "api-1")
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, c := range s.Collection {
		if c.Resource == r.fail && c.Status == "UNKNOWN" {
			found = true
		}
	}
	if !found {
		t.Fatal(s.Collection)
	}
	if len(s.Dump) == 0 || s.ID == "" {
		t.Fatal("snapshot missing")
	}
	for _, call := range r.calls {
		joined := strings.Join(call, " ")
		if !strings.Contains(joined, "--context=test-context") || !strings.Contains(joined, "--namespace=apps") {
			t.Fatal(call)
		}
		if call[0] == "kubectl" && call[3] != "get" {
			t.Fatal("mutation", call)
		}
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "secret-value") {
		t.Fatal("pod environment was exposed")
	}
}
func TestDumpCollectionFailureIsNotHealthy(t *testing.T) {
	r := &fakeRunner{fail: "istioctl"}
	s, e := collector(r).Collect(context.Background(), "apps", "api-1")
	if e != nil {
		t.Fatal(e)
	}
	report, e := Diagnose(s, diagnostics.Request{Direction: "outbound", Port: 443, Protocol: "HTTPS"}, "", time.Now())
	if e != nil || report.Verdict != "undetermined" {
		t.Fatalf("%+v %v", report, e)
	}
}
func TestServiceEmptyVersusMissingEvidence(t *testing.T) {
	s := Snapshot{Resources: map[string]diagnostics.Object{"services": {"items": []any{diagnostics.Object{"metadata": diagnostics.Object{"name": "api"}, "spec": diagnostics.Object{}}}}}}
	q := diagnostics.Request{Direction: "inbound", Port: 8080, Protocol: "HTTP"}
	r, e := Diagnose(s, q, "api", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	has := func(code string) bool {
		for _, c := range r.Checks {
			if c.Code == code {
				return true
			}
		}
		return false
	}
	if !has("SERVICE_ENDPOINTS_UNKNOWN") {
		t.Fatal(r)
	}
	s.Resources["endpointslices.discovery.k8s.io"] = diagnostics.Object{"items": []any{}}
	r, e = Diagnose(s, q, "api", time.Now())
	if e != nil || !has("SERVICE_NO_ENDPOINTS") {
		t.Fatalf("%+v %v", r, e)
	}
}
func TestResolveDeploymentByOwnerNotPrefix(t *testing.T) {
	r := &fakeRunner{data: map[string]string{"pods": `{"items":[{"metadata":{"name":"unrelated-name","ownerReferences":[{"kind":"ReplicaSet","name":"rs-1"}]}},{"metadata":{"name":"api-fake"}}]}`, "replicasets.apps": `{"items":[{"metadata":{"name":"rs-1","ownerReferences":[{"kind":"Deployment","name":"api"}]}}]}`}}
	pods, e := collector(r).Resolve(context.Background(), "apps", "api")
	if e != nil || len(pods) != 1 || asObject(pods[0]["metadata"])["name"] != "unrelated-name" {
		t.Fatalf("%+v %v", pods, e)
	}
}
func TestOutputLimit(t *testing.T) {
	b := &limitedBuffer{max: 5}
	_, _ = b.Write([]byte("123"))
	_, _ = b.Write([]byte("456789"))
	if b.b.String() != "12345" || !b.exceeded {
		t.Fatalf("%+v", b)
	}
}
func TestRunnerRejectsArbitraryExecutable(t *testing.T) {
	_, e := (ExecRunner{}).Run(context.Background(), "sh", "-c", "echo bad")
	if e == nil {
		t.Fatal("expected denial")
	}
}
