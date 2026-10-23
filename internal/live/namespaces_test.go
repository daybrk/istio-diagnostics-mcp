package live

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
)

// Model real namespace filtering and RBAC that permits selected namespace reads
// but denies a cluster-wide list. Named-read fixtures remain intentionally raw.
type namespaceRunner struct {
	*fakeRunner
	denyAll map[string]bool
}

func (f *namespaceRunner) Run(ctx context.Context, args []string, limit int) (commandResult, error) {
	resource, namespace := "", ""
	for i, arg := range args {
		if arg == "get" {
			resource = args[i+1]
		}
		if strings.HasPrefix(arg, "--namespace=") {
			namespace = strings.TrimPrefix(arg, "--namespace=")
		}
	}
	if f.denyAll[resource] && (has(args, "--all-namespaces") || resource == "namespaces" && namespace == "") {
		f.mu.Lock()
		f.calls = append(f.calls, append([]string{}, args...))
		f.mu.Unlock()
		return commandResult{Stderr: "Forbidden"}, errors.New("Forbidden")
	}
	result, err := f.fakeRunner.Run(ctx, args, limit)
	if err != nil || resource == "namespaces" || namespace == "" {
		return result, err
	}
	var list map[string]any
	if json.Unmarshal(result.Stdout, &list) != nil || list["items"] == nil {
		return result, err
	}
	items := []any{}
	for _, item := range list["items"].([]any) {
		if str(meta(item.(map[string]any)), "namespace") == namespace {
			items = append(items, item)
		}
	}
	list["items"] = items
	result.Stdout, _ = json.Marshal(list)
	return result, err
}
func crossNamespaceFixture() *namespaceRunner {
	f := fixture()
	svc := object("Service", "api", "svc-default")
	meta(svc)["namespace"] = "default"
	f.objects["services"] = []map[string]any{svc}
	policy := object("PeerAuthentication", "mesh-default", "policy-system")
	meta(policy)["namespace"] = "istio-system"
	f.objects["peerauthentications.security.istio.io"] = []map[string]any{policy}
	other := object("Pod", "unrelated", "other-pod")
	meta(other)["namespace"] = "other"
	f.objects["pods"] = append(f.objects["pods"], other)
	return &namespaceRunner{fakeRunner: f, denyAll: map[string]bool{}}
}
func TestResourcesAcrossNamespacesWithoutNamespaceEnumeration(t *testing.T) {
	f := crossNamespaceFixture()
	f.denyAll["namespaces"] = true
	c := New(testConfig())
	c.runner = f
	r := c.readResources(context.Background(), testConfig().LocalPrincipal(), "cluster")
	if len(r.objects["default"]["Service"]) != 1 || len(r.objects["istio-system"]["PeerAuthentication"]) != 1 {
		t.Fatalf("missing cross-namespace resources: %v", r.objects)
	}
	if _, ok := r.objects["app"]["NetworkPolicy"]; !ok {
		t.Fatal("lost successful empty list")
	}
	if len(r.failures) == 0 {
		t.Fatal("namespace enumeration denial disappeared")
	}
	found := false
	for _, args := range f.calls {
		if has(args, "services") {
			found = true
			if !has(args, "--all-namespaces") || !has(args, "--context=cluster") || has(args, "--namespace=*") {
				t.Fatal(args)
			}
		}
	}
	if !found {
		t.Fatal("no service discovery")
	}
}
func TestCollectionFallsBackToSelectedNamespacesOnForbidden(t *testing.T) {
	f := crossNamespaceFixture()
	f.denyAll["services"] = true
	c := New(testConfig())
	c.runner = f
	req := request()
	req.Peer = &core.PeerQuery{Kind: "service", Namespace: "default", Value: "api", Port: 443}
	s, err := c.Collect(context.Background(), testConfig().LocalPrincipal(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	found, partial := false, false
	for _, r := range s.Resources {
		if r.Kind == "Service" && r.Namespace == "default" && r.Name == "api" {
			found = true
		}
	}
	for _, entry := range s.Coverage {
		if entry.Source == "resources" && entry.Status == "partial" {
			partial = true
		}
	}
	if !found || !partial {
		t.Fatalf("fallback service=%v partial=%v", found, partial)
	}
	if len(s.Pods) != 2 {
		t.Fatalf("collected unrelated pods: %d", len(s.Pods))
	}
	for _, args := range f.calls {
		if has(args, "logs") && !has(args, "--namespace=app") {
			t.Fatal(args)
		}
	}
}
func TestResourceDiscoveryRejectsUnassignedContext(t *testing.T) {
	f := crossNamespaceFixture()
	c := New(testConfig())
	c.runner = f
	r := c.readResources(context.Background(), testConfig().LocalPrincipal(), "other-context")
	if len(f.calls) != 0 || len(r.failures) == 0 {
		t.Fatalf("calls=%v failures=%v", f.calls, r.failures)
	}
}
func TestResolveRequiresNamespaceWithoutDefaultingLegacyList(t *testing.T) {
	f := fixture()
	q := query()
	q.Namespace = ""
	r, err := testCollector(f).Resolve(context.Background(), testConfig().LocalPrincipal(), q)
	if err != nil || r.Question == nil || len(f.calls) != 0 {
		t.Fatalf("resolution=%+v err=%v calls=%v", r, err, f.calls)
	}
}

func TestAllNamespaceMarkersRespectMemoryBudget(t *testing.T) {
	f := fixture()
	for i := 0; i < 1000; i++ {
		ns := object("Namespace", fmt.Sprintf("ns-%04d", i), fmt.Sprintf("ns-uid-%04d", i))
		delete(meta(ns), "namespace")
		f.objects["namespaces"] = append(f.objects["namespaces"], ns)
	}
	c := testCollector(f)
	r := c.readResources(context.Background(), testConfig().LocalPrincipal(), "cluster", "app")
	encoded, _ := json.Marshal(r.entries)
	if len(encoded) > c.cfg.Limits.MemoryBytes || r.used > c.cfg.Limits.MemoryBytes {
		t.Fatalf("budget=%d entries=%d accounted=%d", c.cfg.Limits.MemoryBytes, len(encoded), r.used)
	}
	limited := false
	for _, failure := range r.failures {
		var fault *core.Fault
		if errors.As(failure.err, &fault) && fault.Code == "RESOURCE_LIMIT" {
			limited = true
		}
	}
	if !limited {
		t.Fatal("omitted completeness records must report RESOURCE_LIMIT")
	}
	if _, ok := r.objects["app"]["NetworkPolicy"]; !ok {
		t.Fatal("selected namespace lost priority for successful empty list")
	}
	// Each published list must retain all of that namespace-kind's objects.
	for _, entry := range r.entries {
		if strings.HasSuffix(entry.Kind, "List") {
			kind := strings.TrimSuffix(entry.Kind, "List")
			if len(entry.Object["items"].([]any)) != len(r.objects[entry.Namespace][kind]) {
				t.Fatal("partial list published as complete")
			}
		}
	}
}

func TestResourceMaterializationStopsOnCancellation(t *testing.T) {
	c := New(testConfig())
	r := resources{objects: map[string]map[string][]map[string]any{"app": {"Service": {object("Service", "api", "s1")}}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.materializeResources(ctx, "cluster", &r, map[string]bool{"Service": true}, []string{"app"})
	if len(r.entries) != 0 || len(r.objects) != 0 || len(r.failures) != 1 || !errors.Is(r.failures[0].err, context.Canceled) {
		t.Fatalf("canceled materialization: %+v", r)
	}
}
