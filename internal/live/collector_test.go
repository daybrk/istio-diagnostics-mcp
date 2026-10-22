package live

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
)

type fakeRunner struct {
	mu       sync.Mutex
	calls    [][]string
	objects  map[string][]map[string]any
	logs     string
	previous string
	failures map[string]error
	onRun    func([]string)
	onStart  func([]string)
	process  process
}

func (f *fakeRunner) Run(ctx context.Context, args []string, limit int) (commandResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, append([]string{}, args...))
	hook := f.onRun
	f.mu.Unlock()
	if hook != nil {
		hook(args)
	}
	if ctx.Err() != nil {
		return commandResult{}, ctx.Err()
	}
	var result []byte
	verb, index := "", 0
	for i, a := range args {
		if a == "get" || a == "logs" {
			verb = a
			index = i
			break
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if verb == "logs" {
		result = []byte(f.logs)
		if has(args, "--previous=true") {
			result = []byte(f.previous)
		}
	} else {
		resource := args[index+1]
		if e := f.failures[resource]; e != nil {
			return commandResult{Stderr: e.Error()}, e
		}
		list := f.objects[resource]
		if index+2 < len(args) && !strings.HasPrefix(args[index+2], "-") {
			name := args[index+2]
			var object map[string]any
			for _, o := range list {
				if str(meta(o), "name") == name {
					object = o
					break
				}
			}
			if object == nil {
				return commandResult{Stderr: "NotFound"}, errors.New("NotFound")
			}
			result, _ = json.Marshal(object)
		} else {
			result, _ = json.Marshal(map[string]any{"items": list})
		}
	}
	truncated := len(result) > limit
	if truncated {
		result = result[:limit]
	}
	return commandResult{Stdout: result, Truncated: truncated}, nil
}
func (f *fakeRunner) Start(_ context.Context, args []string) (process, error) {
	if f.onStart != nil {
		f.onStart(args)
	}
	if f.process == nil {
		return nil, errors.New("no tunnel")
	}
	return f.process, nil
}
func has(v []string, s string) bool {
	for _, x := range v {
		if x == s {
			return true
		}
	}
	return false
}
func testConfig() core.Config {
	return core.Config{Kube: core.KubeConfig{KubeconfigPath: "/selected/kubeconfig", Contexts: []core.Scope{{Context: "cluster", Namespaces: []string{"app"}}}}, Limits: core.Limits{PodConcurrency: 2, PortForwardConcurrency: 1, RequestTimeoutSeconds: 2, OperationBudgetSeconds: 10, MaxLogBytes: 1024, MaxEnvoyResponseBytes: 4096, MemoryBytes: 1 << 20}}
}
func object(kind, name, uid string, owner ...string) map[string]any {
	m := map[string]any{"name": name, "namespace": "app", "uid": uid}
	if len(owner) > 0 {
		m["ownerReferences"] = []any{map[string]any{"kind": owner[0], "name": owner[1], "uid": owner[2], "controller": true}}
	}
	return map[string]any{"apiVersion": "v1", "kind": kind, "metadata": m}
}
func fixture() *fakeRunner {
	return &fakeRunner{objects: map[string][]map[string]any{
		"deployments": {object("Deployment", "shop", "d1")}, "replicasets": {object("ReplicaSet", "shop-old", "r1", "Deployment", "shop", "d1"), object("ReplicaSet", "shop-new", "r2", "Deployment", "shop", "d1")},
		"pods": {object("Pod", "shop-old-a", "p1", "ReplicaSet", "shop-old", "r1"), object("Pod", "shop-new-b", "p2", "ReplicaSet", "shop-new", "r2"), object("Pod", "shop-imposter", "p3", "ReplicaSet", "shop-new", "wrong")},
	}, failures: map[string]error{}}
}
func testCollector(f *fakeRunner) *Collector { c := New(testConfig()); c.runner = f; return c }
func query() core.WorkloadQuery {
	return core.WorkloadQuery{Context: "cluster", Namespace: "app", Kind: "Deployment", Name: "shop"}
}
func request() core.CollectRequest {
	return core.CollectRequest{Workload: core.WorkloadRef{Context: "cluster", Namespace: "app", Kind: "Deployment", Name: "shop", UID: "d1"}, Direction: "outbound", Window: core.ResolvedWindow{Start: "2026-10-22T12:00:00Z", End: "2026-10-22T12:15:00Z"}}
}

func TestResolveCountsEveryReplicaByOwnerUID(t *testing.T) {
	f := fixture()
	c := testCollector(f)
	r, e := c.Resolve(context.Background(), testConfig().LocalPrincipal(), query())
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Candidates) != 1 || r.Candidates[0].PodCount != 2 || r.Candidates[0].Workload.UID != "d1" {
		t.Fatalf("owner grouping = %+v", r)
	}
	for _, a := range f.calls {
		for _, want := range []string{"--kubeconfig=/selected/kubeconfig", "--context=cluster", "--namespace=app", "--request-timeout=2s", "-o=json"} {
			if !has(a, want) {
				t.Errorf("missing %s in %v", want, a)
			}
		}
	}
}
func TestSelectorGroupsOwnersWithoutGuessingNames(t *testing.T) {
	f := fixture()
	q := query()
	q.Kind = "Selector"
	q.Name = ""
	q.Selector = "app=shop"
	r, e := testCollector(f).Resolve(context.Background(), testConfig().LocalPrincipal(), q)
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Candidates) != 2 {
		t.Fatalf("candidates = %+v", r)
	}
	for _, x := range r.Candidates {
		if x.Workload.UID == "d1" && x.PodCount != 2 {
			t.Fatal(x)
		}
		if x.Workload.Kind == "Selector" {
			t.Fatal("synthetic selector UID")
		}
	}
}
func TestRejectInvalidOrDeniedQueriesWithoutReads(t *testing.T) {
	for _, q := range []core.WorkloadQuery{{Context: "cluster", Namespace: "else", Kind: "Pod", Name: "p"}, {Context: "cluster", Namespace: "app", Kind: "Pod", Name: "--all"}, {Context: "cluster", Namespace: "app", Kind: "Selector", Selector: "x=y; touch /tmp/a"}} {
		f := fixture()
		_, e := testCollector(f).Resolve(context.Background(), testConfig().LocalPrincipal(), q)
		if e == nil || len(f.calls) > 0 {
			t.Fatalf("query accepted or read: %+v, %v", q, e)
		}
	}
}
func TestCollectFiltersFrozenWindowAndRetainsAllPods(t *testing.T) {
	f := fixture()
	f.logs = "2026-10-22T11:59:59Z before\n2026-10-22T12:00:00Z first\n2026-10-22T12:14:59Z last\n2026-10-22T12:15:00Z after\n"
	f.previous = "2026-10-22T12:05:00Z previous\n"
	f.objects["pods"][0]["spec"] = map[string]any{"containers": []any{map[string]any{"name": "istio-proxy", "env": []any{map[string]any{"name": "TOKEN", "value": "secret"}}}}}
	f.objects["pods"][0]["status"] = map[string]any{"containerStatuses": []any{map[string]any{"name": "istio-proxy", "restartCount": float64(1)}}}
	s, e := testCollector(f).Collect(context.Background(), testConfig().LocalPrincipal(), request(), nil)
	if e != nil {
		t.Fatal(e)
	}
	if len(s.Pods) != 2 {
		t.Fatalf("pods=%d", len(s.Pods))
	}
	for _, p := range s.Pods {
		if p.Role != "source" {
			t.Error(p.Role)
		}
		v := string(p.LogsCurrent)
		if strings.Contains(v, "before") || strings.Contains(v, "after") || !strings.Contains(v, "first") {
			t.Fatalf("window logs: %q", v)
		}
		if p.Ref.UID == "p1" && !strings.Contains(string(p.LogsPrevious), "previous") {
			t.Fatal("previous absent")
		}
		b, _ := json.Marshal(p.Object)
		if strings.Contains(string(b), "secret") {
			t.Fatal("unredacted Pod object")
		}
	}
	for _, a := range f.calls {
		if has(a, "logs") && (!has(a, "--container=istio-proxy") || !has(a, "--timestamps=true") || !has(a, "--since-time=2026-10-22T12:00:00Z")) {
			t.Fatal(a)
		}
	}
}
func TestResourceDeniedRemainsCoverage(t *testing.T) {
	f := fixture()
	f.failures["services"] = errors.New("Forbidden")
	s, e := testCollector(f).Collect(context.Background(), testConfig().LocalPrincipal(), request(), nil)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, x := range s.Coverage {
		if x.Source == "resources" && x.Status == "forbidden" && strings.Contains(x.Detail, "services") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing forbidden resource coverage: %+v", s.Coverage)
	}
}
func TestReusedPodUIDRejectsLogs(t *testing.T) {
	f := fixture()
	f.logs = "2026-10-22T12:00:00Z should-discard\n"
	f.onRun = func(a []string) {
		if has(a, "logs") {
			f.mu.Lock()
			for _, p := range f.objects["pods"] {
				if str(meta(p), "uid") == "p1" {
					meta(p)["uid"] = "replacement"
				}
			}
			f.mu.Unlock()
		}
	}
	s, e := testCollector(f).Collect(context.Background(), testConfig().LocalPrincipal(), request(), nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range s.Pods {
		if p.Ref.UID == "p1" && len(p.LogsCurrent) > 0 {
			t.Fatal("attributed replacement logs to original UID")
		}
	}
	found := false
	for _, v := range s.Coverage {
		if v.PodUID == "p1" && v.Source == "logs_current" && v.Status == "unavailable" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing UID replacement coverage")
	}
}
func TestCancellationPreservesPendingReplicas(t *testing.T) {
	f := fixture()
	ctx, cancel := context.WithCancel(context.Background())
	f.onRun = func(a []string) {
		if has(a, "logs") {
			cancel()
		}
	}
	c := testCollector(f)
	c.podSlots = make(chan struct{}, 1)
	s, _ := c.Collect(ctx, testConfig().LocalPrincipal(), request(), nil)
	if s == nil || len(s.Pods) != 2 {
		t.Fatalf("lost discovered pods: %+v", s)
	}
	for _, p := range s.Pods {
		found := false
		for _, v := range s.Coverage {
			if v.PodUID == p.Ref.UID {
				found = true
			}
		}
		if !found {
			t.Fatal("pod absent from coverage")
		}
	}
	pending := false
	for _, v := range s.Coverage {
		if v.Source == "logs_current" && v.Status == "pending" {
			pending = true
		}
	}
	if !pending {
		t.Fatalf("queued pod was marked attempted after cancellation: %+v", s.Coverage)
	}
}

type fakeProcess struct {
	reader io.ReadCloser
	done   chan error
	mu     sync.Mutex
	closed bool
}

func (p *fakeProcess) Output() io.ReadCloser { return p.reader }
func (p *fakeProcess) Done() <-chan error    { return p.done }
func (p *fakeProcess) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return p.reader.Close()
}
func TestLogLimitIsExplicitAndDoesNotParsePartialLine(t *testing.T) {
	f := fixture()
	f.logs = "2026-10-22T12:00:00Z " + strings.Repeat("x", 2000)
	c := testCollector(f)
	s, e := c.Collect(context.Background(), testConfig().LocalPrincipal(), request(), nil)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, v := range s.Coverage {
		if v.Source == "logs_current" && v.Status == "truncated" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing truncation")
	}
	for _, p := range s.Pods {
		if len(p.LogsCurrent) != 0 {
			t.Fatal("partial log line retained")
		}
	}
}

var _ = time.Second

func TestCollectServicePeerDiscoversEveryReplicaAndListProof(t *testing.T) {
	f := fixture()
	peer := object("Pod", "api-a", "peer-a")
	meta(peer)["labels"] = map[string]any{"app": "api"}
	peer2 := object("Pod", "api-b", "peer-b")
	meta(peer2)["labels"] = map[string]any{"app": "api"}
	f.objects["pods"] = append(f.objects["pods"], peer, peer2)
	service := object("Service", "api", "svc")
	service["spec"] = map[string]any{"selector": map[string]any{"app": "api"}, "clusterIP": "10.0.0.1"}
	f.objects["services"] = []map[string]any{service}
	for _, kind := range []string{"service", "host", "ip"} {
		t.Run(kind, func(t *testing.T) {
			req := request()
			value := "api"
			if kind == "host" {
				value = "api.app.svc.cluster.local"
			}
			if kind == "ip" {
				value = "10.0.0.1"
			}
			req.Peer = &core.PeerQuery{Kind: kind, Namespace: "app", Value: value}
			s, e := testCollector(f).Collect(context.Background(), testConfig().LocalPrincipal(), req, nil)
			if e != nil {
				t.Fatal(e)
			}
			if len(s.Pods) != 4 {
				t.Fatalf("missing peer replicas: %+v", s.Pods)
			}
			for _, pod := range s.Pods {
				if strings.HasPrefix(pod.Ref.UID, "peer-") && pod.Role != "destination" {
					t.Fatal(pod.Role)
				}
			}
			proof := false
			for _, r := range s.Resources {
				if r.Kind == "EndpointSliceList" {
					items, ok := r.Object["items"].([]any)
					proof = ok && len(items) == 0
				}
			}
			if !proof {
				t.Fatal("missing successful empty EndpointSlice list proof")
			}
		})
	}
}
func TestNamedReadRejectsNamespaceMismatch(t *testing.T) {
	f := fixture()
	meta(f.objects["deployments"][0])["namespace"] = "forbidden"
	_, e := testCollector(f).get(context.Background(), "cluster", "app", "deployments", "shop", "")
	if e == nil {
		t.Fatal("accepted resource outside namespace")
	}
}
func TestSelectorGrammar(t *testing.T) {
	for _, s := range []string{"app=shop", "app.kubernetes.io/name in (shop, api),!disabled", "tier!=frontend", "version"} {
		if !validSelector(s) {
			t.Errorf("valid selector rejected: %s", s)
		}
	}
	for _, s := range []string{"app value", "app in ()", "app===value", "app=foo,,tier=bar", "in (x)", "-x=y"} {
		if validSelector(s) {
			t.Errorf("invalid selector accepted: %s", s)
		}
	}
}
func TestTransientReadRetriesOnceAndForbiddenNeverRetries(t *testing.T) {
	for _, tc := range []struct {
		message string
		want    int
	}{{"connection reset", 2}, {"context deadline exceeded", 2}, {"Forbidden", 1}} {
		f := fixture()
		f.failures["services"] = errors.New(tc.message)
		_, e := testCollector(f).get(context.Background(), "cluster", "app", "services", "", "")
		if e == nil || len(f.calls) != tc.want {
			t.Fatalf("%s: error=%v calls=%d", tc.message, e, len(f.calls))
		}
	}
}

func TestNativeSidecarRestartCollectsPreviousLogs(t *testing.T) {
	f := fixture()
	f.previous = "2026-10-22T12:05:00Z previous native proxy\n"
	f.objects["pods"][0]["status"] = map[string]any{"initContainerStatuses": []any{map[string]any{"name": "istio-proxy", "restartCount": float64(2)}}}
	s, e := testCollector(f).Collect(context.Background(), testConfig().LocalPrincipal(), request(), nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, pod := range s.Pods {
		if pod.Ref.UID == "p1" && !strings.Contains(string(pod.LogsPrevious), "previous native proxy") {
			t.Fatal("native sidecar restart lost previous logs")
		}
	}
}
