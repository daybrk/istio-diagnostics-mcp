package transport

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/daybrk/istio-diagnostics-mcp/docs/design"
	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type handlerFunc func(context.Context, core.Principal, string, json.RawMessage) (core.Envelope, error)

func (f handlerFunc) Call(c context.Context, p core.Principal, n string, a json.RawMessage) (core.Envelope, error) {
	return f(c, p, n, a)
}
func connect(t *testing.T, h core.Handler) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := NewServer(h, core.Config{Kube: core.KubeConfig{Contexts: []core.Scope{{Context: "ctx", Namespaces: []string{"allowed"}}}}}).Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}
func TestHandshakeCatalogAndEnvelope(t *testing.T) {
	called := false
	cs := connect(t, handlerFunc(func(_ context.Context, p core.Principal, n string, _ json.RawMessage) (core.Envelope, error) {
		called = true
		if p.ID != "local" || !p.AllowsContext("ctx") {
			t.Errorf("principal %#v", p)
		}
		return core.Fail("TEST_ERROR", "test"), nil
	}))
	if cs.InitializeResult().Instructions == "" {
		t.Fatal("client receives no startup guidance before its first call")
	}
	list, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Tools) != 11 {
		t.Fatalf("tools=%d", len(list.Tools))
	}
	for _, tool := range list.Tools {
		b, _ := json.Marshal(tool.InputSchema)
		var s map[string]any
		json.Unmarshal(b, &s)
		if s["type"] != "object" || (s["properties"] == nil && s["oneOf"] == nil) || strings.Contains(string(b), `"$ref"`) {
			t.Fatalf("input schema must expose self-contained properties: %s", tool.Name)
		}
	}
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_capabilities", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if !called || !res.IsError {
		t.Fatalf("bad result %#v", res)
	}
	b, _ := json.Marshal(res.StructuredContent)
	var a, bv any
	json.Unmarshal(b, &a)
	json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &bv)
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(bv)
	if string(aa) != string(bb) {
		t.Fatal("text/structured mismatch")
	}
	p, err := cs.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: "diagnose_connectivity"})
	if err != nil || len(p.Messages) != 2 {
		t.Fatalf("prompt %v %v", p, err)
	}
	resources, err := cs.ListResources(context.Background(), nil)
	if err != nil || len(resources.Resources) != 7 {
		t.Fatalf("resources %v %v", resources, err)
	}
	for _, resource := range resources.Resources {
		if !strings.HasPrefix(resource.URI, "istio-diagnostics://playbook/"+design.PromptVersion+"/") {
			t.Fatalf("stale resource URI: %s", resource.URI)
		}
		content, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: resource.URI})
		if err != nil || len(content.Contents) != 1 || content.Contents[0].URI != resource.URI {
			t.Fatalf("resource mismatch: %+v %v", content, err)
		}
	}
}
func TestInvalidArgumentsAreProtocolError(t *testing.T) {
	called := false
	cs := connect(t, handlerFunc(func(context.Context, core.Principal, string, json.RawMessage) (core.Envelope, error) {
		called = true
		return core.Success(nil), nil
	}))
	_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_capabilities", Arguments: map[string]any{"unknown": true}})
	var rpc *jsonrpc.Error
	if !errors.As(err, &rpc) || rpc.Code != -32602 || called {
		t.Fatalf("called=%v err=%v", called, err)
	}
}

func TestResponseLimitCountsEscapedTextAndStructuredJSON(t *testing.T) {
	env := core.Success(map[string]any{"quoted": strings.Repeat("\"", 300)})
	b, _ := json.Marshal(env)
	limit := len(b)*2 + 128
	res := envelopeResult(env, core.Config{Limits: core.Limits{MaxToolResponseBytes: limit}})
	encoded, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > limit {
		t.Fatalf("wire response bytes=%d exceed configured=%d", len(encoded), limit)
	}
}
