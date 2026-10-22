package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/daybrk/istio-diagnostics-mcp/internal/live"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPInitializeToolsAndCall(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	session, e := New(live.Collector{Config: live.Config{}}).Connect(ctx, serverTransport, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "integration-test", Version: "1.0.0"}, nil)
	cs, e := client.Connect(ctx, clientTransport, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer cs.Close()
	tools, e := cs.ListTools(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if len(tools.Tools) != 7 {
		t.Fatalf("tools=%d", len(tools.Tools))
	}
	for _, tool := range tools.Tools {
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Fatalf("not read-only: %s", tool.Name)
		}
	}
	r, e := cs.CallTool(ctx, &mcp.CallToolParams{Name: "get_capabilities", Arguments: map[string]any{}})
	if e != nil || r.IsError {
		t.Fatalf("%+v %v", r, e)
	}
	b, _ := json.Marshal(r.StructuredContent)
	var caps Capabilities
	if e = json.Unmarshal(b, &caps); e != nil || caps.Version != Version || caps.LiveEnabled {
		t.Fatalf("%s %v", b, e)
	}
	r, e = cs.CallTool(ctx, &mcp.CallToolParams{Name: "collect_snapshot", Arguments: map[string]any{"namespace": "apps", "pod": "api"}})
	if e != nil {
		t.Fatal(e)
	}
	if !r.IsError {
		t.Fatal("disabled live collection should fail")
	}
	r, e = cs.CallTool(ctx, &mcp.CallToolParams{Name: "analyze_config_dump", Arguments: map[string]any{"config_dump": map[string]any{"configs": []any{map[string]any{"@type": "type.googleapis.com/envoy.admin.v3.SecretsConfigDump"}}}}})
	if e != nil || r.IsError {
		t.Fatalf("%+v %v", r, e)
	}
}
func TestSnapshotExpiryAndBound(t *testing.T) {
	a := &API{snapshots: map[string]live.Snapshot{}}
	a.save(live.Snapshot{ID: "old", CollectedAt: time.Now().Add(-time.Hour).Format(time.RFC3339Nano)})
	if _, e := a.snapshot("old"); e == nil {
		t.Fatal("expired snapshot accepted")
	}
	for i := 0; i < 20; i++ {
		a.save(live.Snapshot{ID: time.Unix(int64(i), 0).String(), CollectedAt: time.Now().Format(time.RFC3339Nano)})
	}
	if len(a.snapshots) != 16 {
		t.Fatal(len(a.snapshots))
	}
}
func TestInputExclusivity(t *testing.T) {
	a := &API{}
	if _, _, e := a.dump(DumpInput{}); e == nil {
		t.Fatal("missing source accepted")
	}
	if _, _, e := a.dump(DumpInput{ConfigDump: map[string]any{"configs": []any{}}, SnapshotID: "x"}); e == nil {
		t.Fatal("ambiguous source accepted")
	}
	if _, e := evaluationTime("yesterday"); e == nil {
		t.Fatal("invalid time accepted")
	}
}
