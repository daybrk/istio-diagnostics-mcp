package diagnostics

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
)

func obj(s string) map[string]any {
	var v map[string]any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		panic(err)
	}
	return v
}
func baseSnapshot() *core.Snapshot {
	return &core.Snapshot{Request: core.CollectRequest{Workload: core.WorkloadRef{Context: "test", Namespace: "shop", Kind: "Deployment", Name: "frontend", UID: "workload-1"}, Direction: "outbound", Window: core.ResolvedWindow{Start: "2026-10-22T10:00:00Z", End: "2026-10-22T10:10:00Z"}}, CollectedAt: "2026-10-22T10:11:00Z", Pods: []core.PodSnapshot{{Ref: core.WorkloadRef{Namespace: "shop", Name: "frontend-1", Kind: "Pod", UID: "pod-1"}, Role: "source", CollectedAt: "2026-10-22T10:11:00Z", Object: obj(`{"metadata":{"uid":"pod-1"},"spec":{"containers":[{"name":"app"},{"name":"istio-proxy"}]},"status":{"podIP":"10.0.0.1","containerStatuses":[{"name":"istio-proxy","ready":true,"restartCount":0,"state":{"running":{"startedAt":"2026-10-22T09:00:00Z"}}}]}}`), Envoy: map[string]json.RawMessage{}}}}
}
func jsonLog(ts, cluster, code, flags string) string {
	return ts + ` {"start_time":"2026-10-22T10:02:00Z","method":"GET","path":"/items","protocol":"HTTP/2","response_code":` + code + `,"response_flags":"` + flags + `","response_code_details":"upstream_reset_before_response_started{connection_failure}","upstream_cluster":"` + cluster + `","upstream_host":"10.0.0.2:8080","downstream_remote_address":"10.0.0.1:5000","authority":"backend.shop.svc.cluster.local"}`
}
func findings(a core.Analysis, rule string) []core.Finding {
	var out []core.Finding
	for _, f := range a.Findings {
		if f.RuleID == rule {
			out = append(out, f)
		}
	}
	return out
}
func hasStatus(a core.Analysis, rule, status string) bool {
	for _, f := range findings(a, rule) {
		if f.CheckStatus == status {
			return true
		}
	}
	return false
}
func requireStatus(t *testing.T, a core.Analysis, rule, status string) {
	t.Helper()
	if !hasStatus(a, rule, status) {
		t.Fatalf("%s needs %s, got %+v", rule, status, findings(a, rule))
	}
}

func TestDiscoveryWindowAndRecordCounts(t *testing.T) {
	s := baseSnapshot()
	line := jsonLog("2026-10-22T10:02:00Z", "outbound|80||backend.shop.svc.cluster.local", "503", "UF")
	s.Pods[0].LogsCurrent = []byte(strings.Join([]string{jsonLog("2026-10-22T09:59:59Z", "outbound|80||backend.shop.svc.cluster.local", "503", "UF"), line, line, jsonLog(s.Request.Window.End, "outbound|80||backend.shop.svc.cluster.local", "503", "UF")}, "\n"))
	a := Analyze(s, nil)
	if len(a.Connections) != 1 {
		t.Fatalf("connections: %+v", a.Connections)
	}
	c := a.Connections[0]
	if c.ObservationCount != 2 || c.CountSemantics != "log_records" || c.Port != 80 || c.Destination != "backend.shop.svc.cluster.local" {
		t.Fatalf("bad grouping: %+v", c)
	}
	if c.LastSeen != "2026-10-22T10:02:00Z" {
		t.Fatalf("last seen %s", c.LastSeen)
	}
	for _, f := range a.Findings {
		if f.Confidence == "confirmed" {
			t.Fatalf("flags cannot prove cause: %+v", f)
		}
	}
}
func TestDefaultTextAndTCP(t *testing.T) {
	s := baseSnapshot()
	s.Pods[0].LogsCurrent = []byte(`2026-10-22T10:03:00Z [2026-10-22T10:03:00.000Z] "- - -" 0 UF - - "delayed_connect_error:_111" 0 0 5 - "-" "-" "-" "-" "10.0.0.2:5432" outbound|5432||db.shop.svc.cluster.local 10.0.0.1:3333 10.1.0.1:5432 10.0.0.1:4444 - -`)
	a := Analyze(s, nil)
	if len(a.Connections) != 1 || a.Connections[0].Protocol != "tcp" {
		t.Fatalf("tcp: %+v", a.Connections)
	}
}
func TestInboundDoesNotReverseIdentities(t *testing.T) {
	s := baseSnapshot()
	s.Request.Direction = "inbound"
	s.Pods[0].Role = "destination"
	s.Pods[0].LogsCurrent = []byte(jsonLog("2026-10-22T10:02:00Z", "inbound|8080||", "503", "UF"))
	a := Analyze(s, nil)
	if len(a.Connections) != 1 {
		t.Fatalf("connections %+v", a.Connections)
	}
	if a.Connections[0].Source != "ip:10.0.0.1" || a.Connections[0].Destination != "shop/Deployment/frontend" {
		t.Fatalf("inbound: %+v", a.Connections[0])
	}
}
func TestPeerExactClusterFilter(t *testing.T) {
	s := baseSnapshot()
	s.Request.Peer = &core.PeerQuery{Kind: "service", Namespace: "shop", Value: "backend"}
	s.Pods[0].LogsCurrent = []byte(jsonLog("2026-10-22T10:02:00Z", "outbound|80||backend.shop.svc.cluster.local", "503", "UF") + "\n" + jsonLog("2026-10-22T10:02:00Z", "outbound|80||backend-other.shop.svc.cluster.local", "503", "UF"))
	a := Analyze(s, nil)
	if len(a.Connections) != 1 || a.Connections[0].ObservationCount != 1 {
		t.Fatalf("exact peer: %+v", a.Connections)
	}
}
func TestGRPCErrorWithHTTP200IsObservedFailure(t *testing.T) {
	s := baseSnapshot()
	s.Pods[0].LogsCurrent = []byte(`2026-10-22T10:02:00Z {"protocol":"HTTP/2","response_code":200,"grpc_status":"14","response_flags":"-","upstream_cluster":"outbound|80||backend.shop.svc.cluster.local"}`)
	a := Analyze(s, nil)
	if len(a.Connections) != 1 || a.Connections[0].Protocol != "grpc" {
		t.Fatalf("grpc: %+v", a.Connections)
	}
	requireStatus(t, a, "PROTOCOL_STATUS", "FAIL")
}
func TestNativeSidecarReadinessAndRestartNotCause(t *testing.T) {
	s := baseSnapshot()
	s.Pods[0].Object = obj(`{"spec":{"containers":[{"name":"app"}],"initContainers":[{"name":"istio-proxy","restartPolicy":"Always"}]},"status":{"initContainerStatuses":[{"name":"istio-proxy","ready":false,"restartCount":4,"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}}`)
	a := Analyze(s, nil)
	requireStatus(t, a, "WORKLOAD_PROXY_STATE", "FAIL")
	for _, f := range findings(a, "WORKLOAD_PROXY_STATE") {
		if f.Confidence == "confirmed" {
			t.Fatal("readiness is not root cause")
		}
		if len(f.EvidenceIDs) == 0 {
			t.Fatal("missing pod evidence")
		}
	}
}
func TestReadyAndMissingStatus(t *testing.T) {
	s := baseSnapshot()
	requireStatus(t, Analyze(s, nil), "WORKLOAD_PROXY_STATE", "PASS")
	delete(s.Pods[0].Object, "status")
	requireStatus(t, Analyze(s, nil), "WORKLOAD_PROXY_STATE", "UNKNOWN")
}
func TestDiagnosticAndUnknownFormatBoundaries(t *testing.T) {
	s := baseSnapshot()
	s.Pods[0].LogsPrevious = []byte("2026-10-22T10:01:00Z 2026-10-22T10:01:00Z\terror\tfailed to start envoy: invalid bootstrap configuration\n2026-10-22T10:02:00Z totally custom log")
	a := Analyze(s, nil)
	requireStatus(t, a, "PROXY_STARTUP_ERROR", "FAIL")
	if !strings.Contains(strings.Join(a.Limitations, " "), "Unsupported") {
		t.Fatalf("missing parse boundary: %+v", a.Limitations)
	}
}
func TestMissingSnapshotIsUnknownWithCatalogCoverage(t *testing.T) {
	a := Analyze(nil, nil)
	if len(SupportedChecks()) < 9 {
		t.Fatal("priority evaluator catalog missing")
	}
	requireStatus(t, a, "WORKLOAD_PROXY_STATE", "UNKNOWN")
}
func TestEvidenceLocatorsAndSelectionLinks(t *testing.T) {
	s := baseSnapshot()
	s.Pods[0].LogsCurrent = []byte(jsonLog("2026-10-22T10:02:00Z", "outbound|80||backend.shop.svc.cluster.local", "503", "UF"))
	first := Analyze(s, nil)
	if len(first.Connections) != 1 {
		t.Fatal("missing connection")
	}
	a := Analyze(s, &first.Connections[0])
	ids := map[string]bool{}
	for _, e := range a.Evidence {
		ids[e.ID] = true
		if e.SourceLocator == "" || e.CollectedAt == "" {
			t.Fatalf("unlocatable evidence: %+v", e)
		}
	}
	for _, f := range a.Findings {
		for _, id := range f.EvidenceIDs {
			if !ids[id] {
				t.Fatalf("dangling evidence %s", id)
			}
		}
	}
	if len(a.Connections) != 1 || a.Connections[0].ID != first.Connections[0].ID {
		t.Fatal("selection identity lost")
	}
}
