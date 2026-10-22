package engine

import (
	"context"
	"fmt"
	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
	"github.com/daybrk/istio-diagnostics-mcp/internal/diagnostics"
	"net"
	"strings"
	"testing"
	"time"
)

type reviewCollector struct{ fixtureCollector }

func (f *reviewCollector) Collect(ctx context.Context, p core.Principal, r core.CollectRequest, emit func(core.Progress)) (*core.Snapshot, error) {
	stamp := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	return &core.Snapshot{Request: r, CollectedAt: core.Timestamp(time.Now()), Pods: []core.PodSnapshot{{Ref: core.WorkloadRef{Context: r.Workload.Context, Namespace: "shop", Kind: "Pod", Name: "app-1", UID: "pod-uid"}, Role: "source", LogsCurrent: []byte(stamp + ` {"method":"GET","path":"/","protocol":"HTTP/1.1","response_code":503,"response_flags":"UF","upstream_cluster":"outbound|80||backend.shop.svc.cluster.local","upstream_host":"10.0.0.2:8080","authority":"backend.shop.svc.cluster.local"}`)}}}, nil
}
func TestReviewDirectPairRealAnalyzer(t *testing.T) {
	e, _, p := setup(t)
	e.collector = &reviewCollector{}
	e.analyze = diagnostics.Analyze
	args := startArgs("direct")
	args["peer"] = map[string]any{"kind": "service", "value": "backend", "namespace": "shop", "port": 80, "protocol": "http"}
	d := diagnosis(t, call(t, e, p, "start_diagnosis", args))
	d = settled(t, e, p, d.DiagnosisID)
	e.mu.Lock()
	a := e.sessions[d.DiagnosisID].attempts[d.AttemptID]
	findings := append([]core.Finding{}, a.findings...)
	e.mu.Unlock()
	failures := 0
	for _, f := range findings {
		if f.RuleID == "PROTOCOL_STATUS" && f.CheckStatus == "FAIL" {
			failures++
		}
	}
	t.Logf("selected=%+v, observed failures=%d", d.Connections, failures)
	if failures != 1 || d.Connections[0].ObservationCount != 1 {
		t.Error("direct pair discarded a matching 503 access record")
	}
}

func TestDirectPairWithoutPortProtocol(t *testing.T) {
	e, _, p := setup(t)
	e.collector, e.analyze = &reviewCollector{}, diagnostics.Analyze
	args := startArgs("unspecified")
	args["peer"] = map[string]any{"kind": "service", "value": "backend", "namespace": "shop"}
	d := diagnosis(t, call(t, e, p, "start_diagnosis", args))
	d = settled(t, e, p, d.DiagnosisID)
	if len(d.Connections) != 1 || d.Connections[0].ObservationCount != 1 || d.Connections[0].Port != 80 || d.Connections[0].Protocol != "http" {
		t.Fatalf("pair did not bind observed metadata: %+v", d.Connections)
	}
}

func TestPeerIdentitiesRoundTrip(t *testing.T) {
	for _, tt := range []struct{ identity, kind, value, ns string }{
		{"ip:2001:db8::1", "ip", "2001:db8::1", ""},
		{"api.shop.svc.local", "host", "api.shop.svc.local", ""},
		{"shop/Deployment/backend", "workload", "Deployment/backend", "shop"},
		{"shop/workload/backend", "workload", "backend", "shop"},
	} {
		q := peerFrom(core.Connection{Destination: tt.identity}, "outbound")
		if q.Kind != tt.kind || q.Value != tt.value || q.Namespace != tt.ns {
			t.Fatalf("%s: %+v", tt.identity, q)
		}
	}
}

func TestAllAnalysisMetadataIsBounded(t *testing.T) {
	e, _, p := setup(t)
	e.cfg.Limits.MemoryBytes = 65536
	e.analyze = func(s *core.Snapshot, c *core.Connection) core.Analysis {
		a := core.Analysis{}
		for i := 0; i < 1000; i++ {
			a.Connections = append(a.Connections, core.Connection{ID: fmt.Sprint(i), Source: "shop/Deployment/app", Destination: fmt.Sprintf("host-%d.shop.svc.cluster.local", i), Protocol: "http", Status: "queued", CountSemantics: "log_records", PodUIDs: []string{"pod-uid"}})
		}
		return a
	}
	d := diagnosis(t, call(t, e, p, "start_diagnosis", startArgs("large-analysis")))
	d = settled(t, e, p, d.DiagnosisID)
	e.mu.Lock()
	used := e.memoryUsed()
	e.mu.Unlock()
	if used > e.cfg.Limits.MemoryBytes {
		t.Fatalf("retained %d > %d", used, e.cfg.Limits.MemoryBytes)
	}
	if len(d.Coverage.Limitations) == 0 || d.Jobs[0].Status != "partial" {
		t.Fatal("omitted queue was not explicit")
	}
}
func TestReviewDiscoveredIPPeer(t *testing.T) {
	c := core.Connection{Source: "ip:10.0.0.9", Destination: "shop/Deployment/app", Port: 8080, Protocol: "http"}
	p := peerFrom(c, "inbound")
	t.Logf("peer=%+v", p)
	if p.Kind != "ip" || net.ParseIP(p.Value) == nil {
		t.Error("a discovered IP peer is rejected by live.validatePeer")
	}
}
func TestReviewClarificationMemory(t *testing.T) {
	e, _, p := setup(t)
	e.cfg.Limits.MemoryBytes = 65536
	d := diagnosis(t, call(t, e, p, "start_diagnosis", map[string]any{"operation_id": "start"}))
	for i := 0; i < 100; i++ {
		call(t, e, p, "start_diagnosis", map[string]any{"diagnosis_id": d.DiagnosisID, "operation_id": fmt.Sprintf("more-%d", i)})
	}
	e.mu.Lock()
	used := e.memoryUsed()
	e.mu.Unlock()
	t.Logf("accounted=%d budget=%d", used, e.cfg.Limits.MemoryBytes)
	if used > e.cfg.Limits.MemoryBytes {
		t.Error("clarification retries bypass memory admission")
	}
}
func TestReviewRevokedCreateReplay(t *testing.T) {
	e, _, p := setup(t)
	args := startArgs("replay")
	d := diagnosis(t, call(t, e, p, "start_diagnosis", args))
	settled(t, e, p, d.DiagnosisID)
	p.Scopes = nil
	r := call(t, e, p, "start_diagnosis", args)
	t.Logf("replay outcome=%s error=%+v", r.Outcome, r.Error)
	if r.Error == nil || r.Error.Code != "SESSION_NOT_FOUND" {
		t.Error("creation replay bypasses revoked scope authorization")
	}
}
func TestReviewAnalysisMetadataMemory(t *testing.T) {
	e, _, p := setup(t)
	e.cfg.Limits.MemoryBytes = 65536
	e.collector = &reviewCollector{}
	e.analyze = func(s *core.Snapshot, c *core.Connection) core.Analysis {
		s.Pods[0].LogsCurrent = []byte(strings.Repeat(string(s.Pods[0].LogsCurrent)+"\n", 100))
		return diagnostics.Analyze(s, c)
	}
	d := diagnosis(t, call(t, e, p, "start_diagnosis", startArgs("metadata")))
	d = settled(t, e, p, d.DiagnosisID)
	e.mu.Lock()
	used := e.memoryUsed()
	e.mu.Unlock()
	t.Logf("accounted=%d budget=%d findings=%d", used, e.cfg.Limits.MemoryBytes, d.Totals.Findings)
	if used > e.cfg.Limits.MemoryBytes {
		t.Error("retained analysis metadata bypasses memory admission")
	}
}

type reviewProvider struct {
	started chan struct{}
	unblock chan struct{}
}

func (p *reviewProvider) Query(ctx context.Context, _ core.Principal, _ core.ProductRequest) (core.ProductResult, error) {
	close(p.started)
	select {
	case <-ctx.Done():
		return core.ProductResult{}, ctx.Err()
	case <-p.unblock:
	}
	return core.ProductResult{Knowledge: core.Knowledge{Action: "catalog", Status: "available", Summary: "catalog", EvidenceIDs: []string{}}}, nil
}
func TestReviewHistoricalKnowledgeCompletion(t *testing.T) {
	e, f, p := setup(t)
	e.cfg.Astra.Enabled = true
	provider := &reviewProvider{started: make(chan struct{}), unblock: make(chan struct{})}
	e.provider = provider
	d := diagnosis(t, call(t, e, p, "start_diagnosis", startArgs("first")))
	d = settled(t, e, p, d.DiagnosisID)
	old := d.AttemptID
	call(t, e, p, "get_product_context", map[string]any{"diagnosis_id": d.DiagnosisID, "operation_id": "knowledge", "action": "catalog"})
	<-provider.started
	f.block = make(chan struct{})
	call(t, e, p, "refresh_diagnosis", map[string]any{"diagnosis_id": d.DiagnosisID, "operation_id": "refresh", "time_window": map[string]any{"lookback_seconds": 900}})
	r := call(t, e, p, "get_product_context", map[string]any{"diagnosis_id": d.DiagnosisID, "operation_id": "second-knowledge", "action": "catalog"})
	if r.Error == nil || r.Error.Code != "OPERATION_IN_PROGRESS" {
		t.Fatalf("historical knowledge quota bypassed: %+v", r.Error)
	}
	close(provider.unblock)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		e.mu.Lock()
		a := e.sessions[d.DiagnosisID].attempts[old]
		done := !active(a, "knowledge")
		state := a.state
		e.mu.Unlock()
		if done {
			t.Logf("historical state=%s original=%s", state, d.State)
			if state != d.State {
				t.Error("old ASTRA job copied state of newer diagnostic attempt")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("knowledge operation did not finish")
}
