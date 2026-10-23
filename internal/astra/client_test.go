package astra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daybrk/istio-diagnostics-mcp/docs/design"
	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func expectFault(t *testing.T, err error, code string) {
	t.Helper()
	var f *core.Fault
	if !errors.As(err, &f) || f.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}
func TestDisabledDoesNotReadCredentialsOrNetwork(t *testing.T) {
	disabled := false
	c := New(core.Config{Astra: core.AstraConfig{Enabled: &disabled, DefaultURL: "https://unreachable.invalid", CredentialEnv: "MISSING"}})
	_, err := c.Query(context.Background(), core.Principal{}, core.ProductRequest{Action: "catalog"})
	expectFault(t, err, "INTEGRATION_DISABLED")
}
func fixture(t *testing.T, respond func(string, map[string]any) *mcp.CallToolResult) (*Client, *[]string) {
	t.Helper()
	calls := []string{}
	var mu sync.Mutex
	s := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	schemas := map[string]map[string]string{
		"rag_catalog":     {"projectId": "string", "includeFullSpecification": "boolean"},
		"agent_loop":      {"message": "string", "projectId": "string", "repo": "string", "mode": "string"},
		"semantic_search": {"query": "string", "projectId": "string", "repo": "string", "top_k": "integer", "mode": "string"},
		"read_file":       {"projectId": "string", "repo": "string", "path": "string", "offset": "integer", "limit": "integer"},
	}
	for name, fields := range schemas {
		props := map[string]any{}
		for k, v := range fields {
			props[k] = map[string]any{"type": v}
		}
		name := name
		s.AddTool(&mcp.Tool{Name: name, InputSchema: map[string]any{"type": "object", "properties": props}}, func(_ context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var args map[string]any
			json.Unmarshal(r.Params.Arguments, &args)
			mu.Lock()
			calls = append(calls, name)
			mu.Unlock()
			return respond(name, args), nil
		})
	}
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{JSONResponse: true})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-secret" {
			t.Error("missing credential")
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	t.Setenv("ASTRA_FIXTURE_TOKEN", "fixture-secret")
	c := New(core.Config{Astra: core.AstraConfig{DefaultURL: server.URL + "/mcp", AgentURL: server.URL + "/mcp/agent", CredentialEnv: "ASTRA_FIXTURE_TOKEN", AllowedProjects: []string{"p1", "p2"}, MaxResponseBytes: 1 << 20}})
	c.httpClient = server.Client()
	return c, &calls
}
func result(v any) *mcp.CallToolResult {
	return &mcp.CallToolResult{StructuredContent: v, Content: []mcp.Content{}}
}

func TestUserSuppliedProjectWithoutCatalogOrOperatorList(t *testing.T) {
	c, calls := fixture(t, func(name string, args map[string]any) *mcp.CallToolResult {
		if name != "agent_loop" || args["projectId"] != "user-project" {
			t.Errorf("unexpected call: %s %v", name, args)
		}
		return result(map[string]any{"answer": "Documented TLS requirements"})
	})
	// JSON unmarshalling intentionally leaves the legacy switch and allowlist absent.
	var config core.Config
	b, _ := json.Marshal(map[string]any{"astra": map[string]any{"agent_url": c.cfg.AgentURL, "credential_env": c.cfg.CredentialEnv}})
	json.Unmarshal(b, &config)
	c.cfg = config.Astra
	r, err := c.Query(context.Background(), config.LocalPrincipal(), core.ProductRequest{Action: "ask", ProjectID: "user-project", Question: "Explain the Istio TLS settings"})
	if err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 || r.Knowledge.ProjectID != "user-project" {
		t.Fatalf("unexpected workflow: %v %+v", *calls, r.Knowledge)
	}
}
func TestCatalogFilteringAndRequestMapping(t *testing.T) {
	c, calls := fixture(t, func(name string, args map[string]any) *mcp.CallToolResult {
		switch name {
		case "rag_catalog":
			if args["includeFullSpecification"] != false {
				t.Error("full specifications requested")
			}
			return result(map[string]any{"projects": []any{map[string]any{"projectId": "p1", "repos": []any{map[string]any{"name": "repo"}}}, map[string]any{"projectId": "p2", "name": "SECRET_OTHER_PROJECT"}}})
		case "semantic_search":
			if args["projectId"] != "p1" || args["repo"] != "repo" || args["mode"] != "hybrid" || args["top_k"] != float64(5) {
				t.Errorf("mapping %#v", args)
			}
			if strings.Contains(args["query"].(string), "secret-token") {
				t.Fatal("query not redacted")
			}
			return result(map[string]any{"results": []any{map[string]any{"content": "expected behavior", "citation": "repo/a.go:1", "repo": "repo", "path": "a.go"}}, "total": 1})
		default:
			t.Errorf("unexpected tool %s", name)
			return result(nil)
		}
	})
	p := core.Principal{ID: "alice", AstraProjects: []string{"p1"}}
	r, err := c.Query(context.Background(), p, core.ProductRequest{Action: "catalog"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "SECRET_OTHER_PROJECT") {
		t.Fatal("catalog leaked forbidden project")
	}
	r, err = c.Query(context.Background(), p, core.ProductRequest{Action: "search", ProjectID: "p1", Repo: "repo", Query: "Authorization: Bearer secret-token"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Evidence) != 1 || r.Evidence[0].ProductSource.Citation != "repo/a.go:1" || r.Evidence[0].ProductSource.RevisionStatus != "unknown" {
		t.Fatalf("evidence %#v", r.Evidence)
	}
	before := len(*calls)
	_, err = c.Query(context.Background(), p, core.ProductRequest{Action: "search", ProjectID: "p2", Query: "q"})
	expectFault(t, err, "UPSTREAM_FORBIDDEN")
	if len(*calls) != before {
		t.Fatal("forbidden request contacted upstream")
	}
}
func TestSourcePathRepoAndAgentMapping(t *testing.T) {
	c, calls := fixture(t, func(name string, args map[string]any) *mcp.CallToolResult {
		switch name {
		case "rag_catalog":
			return result([]any{map[string]any{"projectId": "p1", "repos": []any{map[string]any{"name": "repo"}}}})
		case "agent_loop":
			if args["mode"] != "simple" || args["message"] != "question" || args["projectId"] != "p1" {
				t.Errorf("agent mapping %#v", args)
			}
			return result(map[string]any{"answer": "answer", "meta": map[string]any{}})
		case "read_file":
			if args["offset"] != float64(1) || args["limit"] != float64(400) {
				t.Errorf("source mapping %#v", args)
			}
			return result(map[string]any{"content": "token=topsecret\nline 2", "meta": map[string]any{"lineFrom": 1, "lineTo": 2}})
		default:
			t.Fatalf("unexpected tool %s", name)
			return nil
		}
	})
	p := core.Principal{ID: "alice", AstraProjects: []string{"p1"}}
	for _, path := range []string{"../secret", "/etc/passwd", "https://evil/file", "a/../b", "a\\b"} {
		_, err := c.Query(context.Background(), p, core.ProductRequest{Action: "source", ProjectID: "p1", Repo: "repo", Path: path})
		expectFault(t, err, "INVALID_ARGUMENT")
	}
	if len(*calls) != 0 {
		t.Fatal("invalid paths contacted upstream")
	}
	_, err := c.Query(context.Background(), p, core.ProductRequest{Action: "source", ProjectID: "p1", Repo: "forbidden", Path: "a.go"})
	expectFault(t, err, "UPSTREAM_FORBIDDEN")
	r, err := c.Query(context.Background(), p, core.ProductRequest{Action: "source", ProjectID: "p1", Repo: "repo", Path: "a.go"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "topsecret") {
		t.Fatal("result not redacted")
	}
	_, err = c.Query(context.Background(), p, core.ProductRequest{Action: "ask", ProjectID: "p1", Question: "question"})
	if err != nil {
		t.Fatal(err)
	}
}
func TestSelectionAndUnknownShapes(t *testing.T) {
	for _, meta := range []map[string]any{{"projects": []any{map[string]any{"projectId": "p1"}}, "projectSelectionRequired": true}, {"catalog": []any{map[string]any{"projectId": "p1"}}}} {
		t.Run("selection", func(t *testing.T) {
			c, _ := fixture(t, func(string, map[string]any) *mcp.CallToolResult {
				return result(map[string]any{"results": []any{}, "meta": meta})
			})
			_, err := c.Query(context.Background(), core.Principal{AstraProjects: []string{"p1"}}, core.ProductRequest{Action: "search", ProjectID: "p1", Query: "q"})
			expectFault(t, err, "PROJECT_SELECTION_REQUIRED")
		})
	}
	c, _ := fixture(t, func(string, map[string]any) *mcp.CallToolResult { return result(map[string]any{"surprise": true}) })
	_, err := c.Query(context.Background(), core.Principal{AstraProjects: []string{"p1"}}, core.ProductRequest{Action: "search", ProjectID: "p1", Query: "q"})
	expectFault(t, err, "UPSTREAM_CONTRACT_MISMATCH")
}

func TestEvidenceConformsToContractAndIsBounded(t *testing.T) {
	c, _ := fixture(t, func(string, map[string]any) *mcp.CallToolResult {
		return result(map[string]any{"answer": strings.Repeat("x", 9000) + "\n" + strings.Repeat("line\n", 500), "meta": map[string]any{}})
	})
	r, err := c.Query(context.Background(), core.Principal{AstraProjects: []string{"p1"}}, core.ProductRequest{Action: "ask", ProjectID: "p1", Question: "q"})
	if err != nil {
		t.Fatal(err)
	}
	e := r.Evidence[0]
	e.AttemptID = "attempt_test"
	if err := design.Validate("get_evidenceOutput", core.Success(e)); err != nil {
		t.Fatalf("evidence violates public schema: %v", err)
	}
	if !e.Truncated {
		t.Fatal("oversized response should expose truncation")
	}
}

func TestTransientRetryIsExactlyOnce(t *testing.T) {
	for _, failures := range []int{1, 3} {
		t.Run(fmt.Sprint(failures), func(t *testing.T) {
			count := 0
			c, _ := fixture(t, func(string, map[string]any) *mcp.CallToolResult {
				count++
				if count <= failures {
					return &mcp.CallToolResult{IsError: true, StructuredContent: map[string]any{"error": map[string]any{"code": "repo_reindexing"}}}
				}
				return result(map[string]any{"answer": "ok", "meta": map[string]any{}})
			})
			_, err := c.Query(context.Background(), core.Principal{AstraProjects: []string{"p1"}}, core.ProductRequest{Action: "ask", ProjectID: "p1", Question: "q"})
			if count != 2 {
				t.Fatalf("calls=%d", count)
			}
			if failures == 1 && err != nil {
				t.Fatal(err)
			}
			if failures > 1 {
				expectFault(t, err, "UPSTREAM_UNAVAILABLE")
			}
		})
	}
}
func TestContractCompatibilityFailsBeforeCall(t *testing.T) {
	tool := &mcp.Tool{Name: "semantic_search", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"query": map[string]any{"type": "integer"}}}}
	expectFault(t, compatible(tool, map[string]any{"query": "query"}), "UPSTREAM_CONTRACT_MISMATCH")
	tool.InputSchema = map[string]any{"type": "object", "properties": map[string]any{"query": map[string]any{"type": "string"}}, "required": []string{"unknown_required"}}
	expectFault(t, compatible(tool, map[string]any{"query": "query"}), "UPSTREAM_CONTRACT_MISMATCH")
}
func TestUpstreamResponseLimit(t *testing.T) {
	c, _ := fixture(t, func(string, map[string]any) *mcp.CallToolResult {
		return result(map[string]any{"answer": strings.Repeat("x", 100000), "meta": map[string]any{}})
	})
	c.cfg.MaxResponseBytes = 16 << 10
	_, err := c.Query(context.Background(), core.Principal{AstraProjects: []string{"p1"}}, core.ProductRequest{Action: "ask", ProjectID: "p1", Question: "q"})
	expectFault(t, err, "UPSTREAM_UNAVAILABLE")
}
func TestCancellationStopsProductRequest(t *testing.T) {
	c, calls := fixture(t, func(string, map[string]any) *mcp.CallToolResult {
		t.Fatal("canceled request contacted tool")
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Query(ctx, core.Principal{AstraProjects: []string{"p1"}}, core.ProductRequest{Action: "ask", ProjectID: "p1", Question: "q"})
	expectFault(t, err, "UPSTREAM_UNAVAILABLE")
	if len(*calls) != 0 {
		t.Fatal("canceled request made tool call")
	}
}

func TestSearchChunkIDAndProjectMetadataAreNotSelection(t *testing.T) {
	c, _ := fixture(t, func(string, map[string]any) *mcp.CallToolResult {
		return result(map[string]any{"results": []any{map[string]any{"id": "chunk-42", "content": "requirement"}}, "meta": map[string]any{"projects": []any{"p1"}}})
	})
	r, err := c.Query(context.Background(), core.Principal{AstraProjects: []string{"p1"}}, core.ProductRequest{Action: "search", ProjectID: "p1", Query: "q"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Evidence) != 1 {
		t.Fatalf("lost ordinary search chunk: %#v", r)
	}
}

func TestUnexpectedResultScopeAndCardinalityFailClosed(t *testing.T) {
	for name, value := range map[string]any{
		"foreign_project":  map[string]any{"results": []any{map[string]any{"projectId": "p2", "content": "foreign"}}},
		"too_many_results": map[string]any{"results": []any{map[string]any{"content": "1"}, map[string]any{"content": "2"}, map[string]any{"content": "3"}, map[string]any{"content": "4"}, map[string]any{"content": "5"}, map[string]any{"content": "6"}}},
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := fixture(t, func(string, map[string]any) *mcp.CallToolResult { return result(value) })
			_, err := c.Query(context.Background(), core.Principal{AstraProjects: []string{"p1"}}, core.ProductRequest{Action: "search", ProjectID: "p1", Query: "q"})
			expectFault(t, err, "UPSTREAM_CONTRACT_MISMATCH")
		})
	}
	c, _ := fixture(t, func(string, map[string]any) *mcp.CallToolResult { return result(map[string]any{"answer": ""}) })
	_, err := c.Query(context.Background(), core.Principal{AstraProjects: []string{"p1"}}, core.ProductRequest{Action: "ask", ProjectID: "p1", Question: "q"})
	expectFault(t, err, "UPSTREAM_UNAVAILABLE")
}

func TestHTTPFailuresRespectRetryAndRedirectPolicy(t *testing.T) {
	for _, tc := range []struct {
		status, calls int
		code          string
	}{{403, 1, "UPSTREAM_FORBIDDEN"}, {500, 2, "UPSTREAM_UNAVAILABLE"}, {302, 1, "UPSTREAM_CONTRACT_MISMATCH"}} {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			count := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count++
				w.Header().Set("Location", "https://unconfigured.invalid/steal")
				w.WriteHeader(tc.status)
			}))
			defer s.Close()
			t.Setenv("ASTRA_HTTP_TEST_TOKEN", "secret")
			c := New(core.Config{Astra: core.AstraConfig{DefaultURL: s.URL, CredentialEnv: "ASTRA_HTTP_TEST_TOKEN", AllowedProjects: []string{"p1"}}})
			c.httpClient = s.Client()
			_, err := c.Query(context.Background(), core.Principal{AstraProjects: []string{"p1"}}, core.ProductRequest{Action: "catalog"})
			expectFault(t, err, tc.code)
			if count != tc.calls {
				t.Fatalf("requests=%d want=%d", count, tc.calls)
			}
		})
	}
}

func TestBudgetIncludesSessionCleanup(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "agent_loop", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"projectId": map[string]any{"type": "string"}, "message": map[string]any{"type": "string"}, "mode": map[string]any{"type": "string"}}}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return result(map[string]any{"answer": "ok"}), nil
	})
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{JSONResponse: true})
	h := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
			return
		}
		mcpHandler.ServeHTTP(w, r)
	}))
	defer h.Close()
	t.Setenv("ASTRA_BUDGET_TEST_TOKEN", "secret")
	c := New(core.Config{Astra: core.AstraConfig{AgentURL: h.URL, AllowedProjects: []string{"p1"}, CredentialEnv: "ASTRA_BUDGET_TEST_TOKEN", RequestBudgetSeconds: 1}})
	c.httpClient = h.Client()
	start := time.Now()
	_, err := c.Query(context.Background(), core.Principal{AstraProjects: []string{"p1"}}, core.ProductRequest{Action: "ask", ProjectID: "p1", Question: "q"})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("operation budget extended by cleanup: %s", elapsed)
	}
}

func TestUserProjectAuthorizationModes(t *testing.T) {
	for _, tt := range []struct {
		name               string
		global             []string
		principal          core.Principal
		project, wantError string
	}{
		{"local-key-scope", nil, core.Principal{AstraCredentialScope: true}, "user-project", ""},
		{"local-empty-list", []string{}, core.Principal{AstraCredentialScope: true}, "p1", "UPSTREAM_FORBIDDEN"},
		{"local-explicit-list", []string{"p1"}, core.Principal{AstraCredentialScope: true}, "p2", "UPSTREAM_FORBIDDEN"},
		{"http-bound-project", nil, core.Principal{AstraProjects: []string{"p1"}}, "p1", ""},
		{"http-unbound", nil, core.Principal{}, "p1", "UPSTREAM_FORBIDDEN"},
		{"http-other-project", nil, core.Principal{AstraProjects: []string{"p1"}}, "p2", "UPSTREAM_FORBIDDEN"},
		{"http-global-intersection", []string{"p2"}, core.Principal{AstraProjects: []string{"p1"}}, "p1", "UPSTREAM_FORBIDDEN"},
		{"missing-project", nil, core.Principal{AstraCredentialScope: true}, "", "PROJECT_SELECTION_REQUIRED"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, calls := fixture(t, func(name string, args map[string]any) *mcp.CallToolResult {
				if name != "agent_loop" || args["projectId"] != tt.project {
					t.Errorf("unexpected request: %s %+v", name, args)
				}
				return result(map[string]any{"answer": "ok"})
			})
			c.cfg.AllowedProjects = tt.global
			_, err := c.Query(context.Background(), tt.principal, core.ProductRequest{Action: "ask", ProjectID: tt.project, Question: "q"})
			if tt.wantError != "" {
				expectFault(t, err, tt.wantError)
				if len(*calls) != 0 {
					t.Fatalf("forbidden/invalid call reached upstream: %v", *calls)
				}
			} else if err != nil || len(*calls) != 1 {
				t.Fatalf("err=%v calls=%v", err, *calls)
			}
		})
	}
}

func TestCatalogUsesCredentialScopeOnlyForLocalPrincipal(t *testing.T) {
	c, _ := fixture(t, func(string, map[string]any) *mcp.CallToolResult {
		return result(map[string]any{"projects": []any{map[string]any{"projectId": "p1"}, map[string]any{"projectId": "p2"}}})
	})
	c.cfg.AllowedProjects = nil
	for _, p := range []core.Principal{{AstraCredentialScope: true}, {AstraProjects: []string{"p1"}}} {
		r, err := c.Query(context.Background(), p, core.ProductRequest{Action: "catalog"})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(r)
		if strings.Contains(string(b), "p2") != p.AstraCredentialScope {
			t.Fatalf("catalog scope mismatch: %s", b)
		}
	}
}

func TestMissingCredentialDoesNotContactUpstream(t *testing.T) {
	c, calls := fixture(t, func(string, map[string]any) *mcp.CallToolResult {
		t.Error("unexpected upstream call")
		return result(nil)
	})
	t.Setenv(c.cfg.CredentialEnv, "")
	_, err := c.Query(context.Background(), core.Principal{AstraProjects: []string{"p1"}}, core.ProductRequest{Action: "ask", ProjectID: "p1", Question: "q"})
	expectFault(t, err, "UPSTREAM_UNAVAILABLE")
	if len(*calls) != 0 {
		t.Fatal("missing key caused I/O")
	}
}
