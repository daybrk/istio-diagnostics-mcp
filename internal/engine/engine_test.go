package engine

import (
	"context"
	"encoding/json"
	"github.com/daybrk/istio-diagnostics-mcp/docs/design"
	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

type fixtureCollector struct {
	calls atomic.Int32
	block chan struct{}
}

func (f *fixtureCollector) Resolve(ctx context.Context, p core.Principal, q core.WorkloadQuery) (core.Resolution, error) {
	return core.Resolution{Candidates: []core.Candidate{{Workload: core.WorkloadRef{Context: q.Context, Namespace: q.Namespace, Kind: q.Kind, Name: q.Name, UID: "workload-uid"}, PodCount: 1}}}, nil
}
func (f *fixtureCollector) Collect(ctx context.Context, p core.Principal, r core.CollectRequest, emit func(core.Progress)) (*core.Snapshot, error) {
	f.calls.Add(1)
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return &core.Snapshot{Request: r}, ctx.Err()
		}
	}
	entry := core.CoverageEntry{PodUID: "pod-uid", Namespace: "shop", Pod: "app-1", Source: "pod_status", Status: "collected", Detail: "observed"}
	emit(core.Progress{Completed: 1, Total: 1, Coverage: []core.CoverageEntry{entry}})
	return &core.Snapshot{Request: r, CollectedAt: core.Timestamp(time.Now()), Coverage: []core.CoverageEntry{entry}}, nil
}
func fixtureAnalysis(s *core.Snapshot, c *core.Connection) core.Analysis {
	cs := []core.Connection{{ID: "conn1", Source: "app.shop", Destination: "b.shop.svc.cluster.local", Protocol: "http", Status: "queued", CountSemantics: "log_records", ObservationCount: 1, PodUIDs: []string{"pod-uid"}}, {ID: "conn2", Source: "app.shop", Destination: "c.shop.svc.cluster.local", Protocol: "tcp", Status: "queued", CountSemantics: "log_records", ObservationCount: 2, PodUIDs: []string{"pod-uid"}}}
	ev := core.Evidence{ID: core.NewID("ev"), SourceType: "proxy_access", CollectedAt: core.Timestamp(time.Now()), SourceLocator: "pod/app-1/log", Lines: []string{"observation"}}
	return core.Analysis{Connections: cs, Evidence: []core.Evidence{ev}, Findings: []core.Finding{{ID: core.NewID("f"), RuleID: "UPSTREAM_FAILURE", CheckStatus: "UNKNOWN", Confidence: "unknown", Summary: "Observed failure", EvidenceIDs: []string{ev.ID}, AffectedPodUIDs: []string{"pod-uid"}, MissingEvidence: []string{"runtime network"}, Recommendation: "Inspect the selected connection", Validation: "Refresh after real traffic"}}}
}
func setup(t *testing.T) (*Engine, *fixtureCollector, core.Principal) {
	t.Helper()
	b, _ := os.ReadFile("../../docs/design/examples/server-config.json")
	cfg, e := core.ParseConfig(b)
	if e != nil {
		t.Fatal(e)
	}
	f := &fixtureCollector{}
	eng := New(cfg, f, nil, fixtureAnalysis, []string{"UPSTREAM_FAILURE"})
	t.Cleanup(eng.Close)
	return eng, f, cfg.LocalPrincipal()
}
func call(t *testing.T, e *Engine, p core.Principal, name string, args any) core.Envelope {
	t.Helper()
	b, _ := json.Marshal(args)
	out, err := e.Call(context.Background(), p, name, b)
	if err != nil {
		t.Fatal(err)
	}
	if err = design.Validate(name+"Output", out); err != nil {
		data, _ := json.Marshal(out)
		t.Fatalf("invalid %s output: %s: %v", name, data, err)
	}
	return out
}
func diagnosis(t *testing.T, r core.Envelope) core.Diagnosis {
	t.Helper()
	if r.Error != nil {
		t.Fatalf("tool error %+v", r.Error)
	}
	return core.Decode[core.Diagnosis](r.Data)
}
func startArgs(op string) map[string]any {
	return map[string]any{"operation_id": op, "workload": map[string]any{"kind": "Deployment", "name": "app", "context": "test-cluster", "namespace": "shop"}, "direction": "outbound"}
}
func settled(t *testing.T, e *Engine, p core.Principal, id string) core.Diagnosis {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		d := diagnosis(t, call(t, e, p, "get_diagnosis", map[string]any{"diagnosis_id": id}))
		active := false
		for _, j := range d.Jobs {
			active = active || j.Status == "queued" || j.Status == "running"
		}
		if !active {
			return d
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("job never settled")
	return core.Diagnosis{}
}
func TestClarificationDoesNotCollect(t *testing.T) {
	e, f, p := setup(t)
	d := diagnosis(t, call(t, e, p, "start_diagnosis", map[string]any{"operation_id": "missing"}))
	if d.State != "needs_clarification" || d.Question == nil || f.calls.Load() != 0 {
		t.Fatalf("unexpected %+v", d)
	}
	r := call(t, e, core.Principal{ID: "other", Scopes: p.Scopes}, "get_diagnosis", map[string]any{"diagnosis_id": d.DiagnosisID})
	if r.Error == nil || r.Error.Code != "SESSION_NOT_FOUND" {
		t.Fatal("ownership failure")
	}
}
func TestAsyncIdempotencySelectionAndRefresh(t *testing.T) {
	e, f, p := setup(t)
	a := startArgs("one")
	d := diagnosis(t, call(t, e, p, "start_diagnosis", a))
	repeat := diagnosis(t, call(t, e, p, "start_diagnosis", a))
	if d.DiagnosisID != repeat.DiagnosisID {
		t.Fatal("duplicate session")
	}
	d = settled(t, e, p, d.DiagnosisID)
	if d.State != "awaiting_selection" || len(d.Connections) != 2 || f.calls.Load() != 1 {
		t.Fatalf("%+v calls%d", d, f.calls.Load())
	}
	a["direction"] = "inbound"
	r := call(t, e, p, "start_diagnosis", a)
	if r.Error == nil || r.Error.Code != "IDEMPOTENCY_CONFLICT" {
		t.Fatal("missing conflict")
	}
	call(t, e, p, "investigate_connection", map[string]any{"diagnosis_id": d.DiagnosisID, "connection_id": "conn1", "operation_id": "select"})
	d = settled(t, e, p, d.DiagnosisID)
	if d.ResumeSummary.RemainingCount != 1 {
		t.Fatalf("lost queue: %+v", d)
	}
	old := d.AttemptID
	call(t, e, p, "refresh_diagnosis", map[string]any{"diagnosis_id": d.DiagnosisID, "operation_id": "refresh", "time_window": map[string]any{"lookback_seconds": 3600}, "compare_to_attempt_id": old})
	d = settled(t, e, p, d.DiagnosisID)
	if d.AttemptID == old || d.Comparison == nil {
		t.Fatal("refresh did not preserve attempts")
	}
	historical := diagnosis(t, call(t, e, p, "get_diagnosis", map[string]any{"diagnosis_id": d.DiagnosisID, "attempt_id": old}))
	if historical.AttemptID != old {
		t.Fatal("lost old attempt")
	}
}
func TestCursorRevisionAndEvidenceOwnership(t *testing.T) {
	e, _, p := setup(t)
	d := diagnosis(t, call(t, e, p, "start_diagnosis", startArgs("page")))
	d = settled(t, e, p, d.DiagnosisID)
	page := diagnosis(t, call(t, e, p, "get_diagnosis", map[string]any{"diagnosis_id": d.DiagnosisID, "limit": 1}))
	if page.NextCursor == "" || page.Totals.Connections != 2 {
		t.Fatal("no continuation")
	}
	next := diagnosis(t, call(t, e, p, "get_diagnosis", map[string]any{"diagnosis_id": d.DiagnosisID, "limit": 1, "cursor": page.NextCursor}))
	if len(next.Connections) != 1 || next.Connections[0].ID != "conn2" {
		t.Fatal("bad second page")
	}
	eid := d.Findings[0].EvidenceIDs[0]
	call(t, e, p, "get_evidence", map[string]any{"diagnosis_id": d.DiagnosisID, "evidence_id": eid})
	r := call(t, e, core.Principal{ID: "other", Scopes: p.Scopes}, "get_evidence", map[string]any{"diagnosis_id": d.DiagnosisID, "evidence_id": eid})
	if r.Error == nil || r.Error.Code != "EVIDENCE_NOT_FOUND" {
		t.Fatal("evidence leaked")
	}
	call(t, e, p, "investigate_connection", map[string]any{"diagnosis_id": d.DiagnosisID, "connection_id": "conn1", "operation_id": "stale"})
	r = call(t, e, p, "get_diagnosis", map[string]any{"diagnosis_id": d.DiagnosisID, "cursor": page.NextCursor})
	if r.Error == nil || r.Error.Code != "CURSOR_STALE" {
		t.Fatal("cursor was reused")
	}
}
func TestCancelAndClose(t *testing.T) {
	e, f, p := setup(t)
	f.block = make(chan struct{})
	d := diagnosis(t, call(t, e, p, "start_diagnosis", startArgs("blocked")))
	call(t, e, p, "cancel_operation", map[string]any{"diagnosis_id": d.DiagnosisID, "operation_id": "blocked"})
	d = settled(t, e, p, d.DiagnosisID)
	if d.Jobs[0].Status != "cancelled" {
		t.Fatalf("%+v", d.Jobs)
	}
	call(t, e, p, "close_diagnosis", map[string]any{"diagnosis_id": d.DiagnosisID})
	r := call(t, e, p, "refresh_diagnosis", map[string]any{"diagnosis_id": d.DiagnosisID, "operation_id": "later", "time_window": map[string]any{"lookback_seconds": 900}})
	if r.Error == nil || r.Error.Code != "SESSION_CLOSED" {
		t.Fatal("closed session reused")
	}
}
func TestScopeRevocationCannotReadSession(t *testing.T) {
	e, _, p := setup(t)
	d := diagnosis(t, call(t, e, p, "start_diagnosis", startArgs("revoke")))
	settled(t, e, p, d.DiagnosisID)
	p.Scopes = []core.Scope{{Context: "test-cluster", Namespaces: []string{"backend"}}}
	r := call(t, e, p, "get_diagnosis", map[string]any{"diagnosis_id": d.DiagnosisID})
	if r.Error == nil || r.Error.Code != "SESSION_NOT_FOUND" {
		t.Fatal("scope-revoked session remains readable")
	}
}
func TestExpiredSessionIsNotRecovered(t *testing.T) {
	e, _, p := setup(t)
	d := diagnosis(t, call(t, e, p, "start_diagnosis", startArgs("expiry")))
	settled(t, e, p, d.DiagnosisID)
	e.mu.Lock()
	future := time.Now().Add(time.Hour)
	e.now = func() time.Time { return future }
	e.mu.Unlock()
	r := call(t, e, p, "get_diagnosis", map[string]any{"diagnosis_id": d.DiagnosisID})
	if r.Error == nil || r.Error.Code != "SESSION_NOT_FOUND" {
		t.Fatal("expired data survived")
	}
}
func TestClientDisconnectDoesNotCancelJob(t *testing.T) {
	e, f, p := setup(t)
	f.block = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	b, _ := json.Marshal(startArgs("disconnect"))
	r, err := e.Call(ctx, p, "start_diagnosis", b)
	if err != nil {
		t.Fatal(err)
	}
	d := diagnosis(t, r)
	cancel()
	close(f.block)
	d = settled(t, e, p, d.DiagnosisID)
	if d.Jobs[0].Status == "cancelled" || f.calls.Load() != 1 {
		t.Fatalf("disconnect cancelled job %+v", d.Jobs)
	}
}
func TestMetadataMemoryLimitAndSmallResponses(t *testing.T) {
	e, _, p := setup(t)
	e.mu.Lock()
	e.cfg.Limits.MemoryBytes = 65536
	e.cfg.Limits.MaxSessions = 1
	e.mu.Unlock()
	r := call(t, e, p, "start_diagnosis", map[string]any{"operation_id": "first"})
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	r = call(t, e, p, "start_diagnosis", map[string]any{"operation_id": "second"})
	if r.Error == nil || r.Error.Code != "RESOURCE_LIMIT" {
		t.Fatal("unbounded sessions")
	}
	e.mu.Lock()
	e.cfg.Limits.MaxToolResponseBytes = 128
	e.mu.Unlock()
	r = call(t, e, p, "get_playbook", map[string]any{"module_id": "main"})
	if r.Error == nil || r.Error.Code != "RESOURCE_LIMIT" {
		t.Fatal("oversized tool response")
	}
}
func TestEvidenceMemoryBudgetExplicit(t *testing.T) {
	e, _, p := setup(t)
	d := diagnosis(t, call(t, e, p, "start_diagnosis", startArgs("evcap")))
	d = settled(t, e, p, d.DiagnosisID)
	e.mu.Lock()
	s := e.sessions[d.DiagnosisID]
	a := s.attempts[s.current]
	e.cfg.Limits.MemoryBytes = e.memoryUsed() + 100
	before := len(a.evidence)
	e.storeAnalysis(s, a, core.Analysis{Evidence: []core.Evidence{{ID: "large", SourceType: "envoy", CollectedAt: core.Timestamp(time.Now()), SourceLocator: "pod/config_dump", Lines: []string{string(make([]byte, 1000))}}}})
	after := len(a.evidence)
	lim := len(a.coverage.Limitations)
	e.mu.Unlock()
	if before != after || lim == 0 {
		t.Fatal("memory limit hidden")
	}
}
func TestUnknownInputAndFutureWindow(t *testing.T) {
	e, _, p := setup(t)
	_, err := e.Call(context.Background(), p, "get_capabilities", json.RawMessage(`{"exec":"curl"}`))
	if err == nil {
		t.Fatal("unknown input accepted")
	}
	a := startArgs("future")
	a["time_window"] = map[string]any{"start": "2026-01-01T00:00:00Z", "end": "2099-01-01T00:00:00Z"}
	r := call(t, e, p, "start_diagnosis", a)
	if r.Error == nil || r.Error.Code != "INVALID_TIME_WINDOW" {
		t.Fatal("future accepted")
	}
	r = call(t, e, p, "get_product_context", map[string]any{"diagnosis_id": "unknown", "operation_id": "product", "action": "catalog"})
	if r.Error == nil {
		t.Fatal("unknown product session accepted")
	}
}

type productFunc func(context.Context, core.Principal, core.ProductRequest) (core.ProductResult, error)

func (f productFunc) Query(c context.Context, p core.Principal, r core.ProductRequest) (core.ProductResult, error) {
	return f(c, p, r)
}
func TestOptionalProductFailureDoesNotEndDiagnosticJob(t *testing.T) {
	e, f, p := setup(t)
	f.block = make(chan struct{})
	e.mu.Lock()
	e.cfg.Astra = core.AstraConfig{AgentURL: "https://astra.example/mcp/agent", CredentialEnv: "ASTRA_TEST"}
	e.provider = productFunc(func(context.Context, core.Principal, core.ProductRequest) (core.ProductResult, error) {
		return core.ProductResult{}, &core.Fault{Code: "UPSTREAM_FORBIDDEN", Message: "Product access denied"}
	})
	e.mu.Unlock()
	d := diagnosis(t, call(t, e, p, "start_diagnosis", startArgs("parallel")))
	deadline := time.Now().Add(3 * time.Second)
	for d.Workload == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		d = diagnosis(t, call(t, e, p, "get_diagnosis", map[string]any{"diagnosis_id": d.DiagnosisID}))
	}
	if d.Workload == nil {
		t.Fatal("workload never resolved")
	}
	call(t, e, p, "get_product_context", map[string]any{"diagnosis_id": d.DiagnosisID, "operation_id": "knowledge", "action": "catalog"})
	for time.Now().Before(deadline) {
		d = diagnosis(t, call(t, e, p, "get_diagnosis", map[string]any{"diagnosis_id": d.DiagnosisID}))
		if len(d.Knowledge) > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(d.Knowledge) != 1 || d.State != "collecting" || d.Jobs[0].Status != "running" || len(d.Coverage.Limitations) != 0 {
		t.Fatalf("ASTRA changed diagnostic state: %+v", d)
	}
	close(f.block)
	settled(t, e, p, d.DiagnosisID)
}
func TestDirectPairSkipsSelectionAndPinsWindow(t *testing.T) {
	e, f, p := setup(t)
	args := startArgs("pair")
	args["peer"] = map[string]any{"kind": "service", "value": "b", "namespace": "backend", "port": 8080, "protocol": "http"}
	args["time_window"] = map[string]any{"lookback_seconds": 10800}
	d := diagnosis(t, call(t, e, p, "start_diagnosis", args))
	d = settled(t, e, p, d.DiagnosisID)
	if d.State != "awaiting_next" || len(d.Connections) != 1 || d.Connections[0].Status != "investigated" || f.calls.Load() != 1 {
		t.Fatalf("direct pair did not run: %+v", d)
	}
	from, _ := time.Parse(time.RFC3339Nano, d.Window.Start)
	to, _ := time.Parse(time.RFC3339Nano, d.Window.End)
	if to.Sub(from) != 3*time.Hour {
		t.Fatalf("window was narrowed: %+v", d.Window)
	}
}
