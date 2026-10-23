// Package astra implements the optional, fixed-action ASTRA knowledge adapter.
package astra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Client struct {
	cfg        core.AstraConfig
	httpClient *http.Client
}

var _ core.ProductProvider = (*Client)(nil)

// New does not access credentials or the network, including when disabled.
func New(c core.Config) *Client {
	return &Client{cfg: c.Astra, httpClient: &http.Client{Timeout: 45 * time.Second}}
}
func fault(code, message string, retry bool) error {
	return &core.Fault{Code: code, Message: message, Retryable: retry}
}
func (c *Client) Query(ctx context.Context, p core.Principal, r core.ProductRequest) (core.ProductResult, error) {
	if !c.cfg.Available() {
		return core.ProductResult{}, fault("INTEGRATION_DISABLED", "ASTRA endpoint/credentials are not configured or the legacy override disables it", false)
	}
	allowed := map[string]bool{}
	if p.AstraCredentialScope {
		if c.cfg.AllowedProjects == nil {
			allowed = nil
		} else {
			for _, project := range c.cfg.AllowedProjects {
				allowed[project] = true
			}
		}
	} else {
		for _, project := range p.AstraProjects {
			if c.cfg.ProjectAllowed(project) {
				allowed[project] = true
			}
		}
	}
	if allowed != nil && (len(allowed) == 0 || (r.ProjectID != "" && !allowed[r.ProjectID])) {
		return core.ProductResult{}, fault("UPSTREAM_FORBIDDEN", "Project is outside the authorized scope", false)
	}
	if err := validateRequest(r); err != nil {
		return core.ProductResult{}, err
	}
	if r.Action != "catalog" && r.ProjectID == "" {
		return core.ProductResult{}, fault("PROJECT_SELECTION_REQUIRED", "Select an authorized project for this request", false)
	}
	r.Question = clean(r.Question, 8192)
	r.Query = clean(r.Query, 8192)
	if r.Mode == "" {
		r.Mode = "simple"
	}
	if r.Offset == 0 {
		r.Offset = 1
	}
	if r.Limit == 0 {
		r.Limit = 400
	}
	token := os.Getenv(c.cfg.CredentialEnv)
	if strings.TrimSpace(token) == "" || strings.ContainsAny(token, "\r\n") {
		return core.ProductResult{}, fault("UPSTREAM_UNAVAILABLE", "ASTRA credentials are unavailable", false)
	}
	budget := 45 * time.Second
	if c.cfg.RequestBudgetSeconds > 0 && c.cfg.RequestBudgetSeconds < 45 {
		budget = time.Duration(c.cfg.RequestBudgetSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	for attempt := 0; attempt < 2; attempt++ {
		result, err := c.query(ctx, r, allowed, token)
		if err == nil {
			return result, nil
		}
		var f *core.Fault
		if attempt == 1 || ctx.Err() != nil || !errors.As(err, &f) || !f.Retryable {
			return core.ProductResult{}, err
		}
	}
	return core.ProductResult{}, fault("UPSTREAM_UNAVAILABLE", "ASTRA request unavailable", false)
}
func validateRequest(r core.ProductRequest) error {
	if len(r.Question) > 8192 || len(r.Query) > 8192 || len(r.ProjectID) > 32 || len(r.Repo) > 253 || len(r.Path) > 1024 {
		return fault("INVALID_ARGUMENT", "Product request exceeds its size limit", false)
	}
	switch r.Action {
	case "catalog":
	case "ask":
		if strings.TrimSpace(r.Question) == "" || r.Mode != "" && r.Mode != "simple" && r.Mode != "advanced" {
			return fault("INVALID_ARGUMENT", "A question and simple or advanced mode are required", false)
		}
	case "search":
		if strings.TrimSpace(r.Query) == "" {
			return fault("INVALID_ARGUMENT", "A search query is required", false)
		}
	case "source":
		if r.Repo == "" || !fs.ValidPath(r.Path) || r.Path == "." || strings.ContainsAny(r.Path, "\\\x00:") || r.Offset < 0 || r.Limit < 0 || r.Limit > 400 {
			return fault("INVALID_ARGUMENT", "Source requires a repository, safe relative POSIX path and a limit at most 400", false)
		}
	default:
		return fault("INVALID_ARGUMENT", "Unsupported product action", false)
	}
	return nil
}
func (c *Client) query(ctx context.Context, r core.ProductRequest, allowed map[string]bool, token string) (core.ProductResult, error) {
	if r.Repo != "" && r.Action != "catalog" {
		catalog, err := c.call(ctx, c.cfg.DefaultURL, "rag_catalog", map[string]any{"projectId": r.ProjectID, "includeFullSpecification": false}, token)
		if err != nil {
			return core.ProductResult{}, err
		}
		projects, err := filterCatalog(catalog, allowed, r.ProjectID)
		if err != nil {
			return core.ProductResult{}, err
		}
		repoAllowed := false
		for _, project := range projects {
			if projectID(project) == r.ProjectID {
				repos, _ := project["repos"].([]any)
				for _, entry := range repos {
					if repoName(entry) == r.Repo {
						repoAllowed = true
					}
				}
			}
		}
		if !repoAllowed {
			return core.ProductResult{}, fault("UPSTREAM_FORBIDDEN", "Repository is not in the authorized project catalog", false)
		}
	}
	name, endpoint := map[string]string{"catalog": "rag_catalog", "ask": "agent_loop", "search": "semantic_search", "source": "read_file"}[r.Action], c.cfg.DefaultURL
	args := map[string]any{}
	if r.ProjectID != "" {
		args["projectId"] = r.ProjectID
	}
	if r.Repo != "" {
		args["repo"] = r.Repo
	}
	switch r.Action {
	case "catalog":
		args["includeFullSpecification"] = false
		delete(args, "repo")
	case "ask":
		endpoint = c.cfg.AgentURL
		args["message"] = r.Question
		args["mode"] = r.Mode
	case "search":
		args["query"] = r.Query
		args["top_k"] = 5
		args["mode"] = "hybrid"
	case "source":
		args["path"] = r.Path
		args["offset"] = r.Offset
		args["limit"] = r.Limit
	}
	value, err := c.call(ctx, endpoint, name, args, token)
	if err != nil {
		return core.ProductResult{}, err
	}
	return normalize(r, value, allowed)
}

var toolFields = map[string]map[string]string{
	"rag_catalog":     {"projectId": "string", "includeFullSpecification": "boolean"},
	"agent_loop":      {"message": "string", "projectId": "string", "repo": "string", "mode": "string"},
	"semantic_search": {"query": "string", "projectId": "string", "repo": "string", "top_k": "integer", "mode": "string"},
	"read_file":       {"projectId": "string", "repo": "string", "path": "string", "offset": "integer", "limit": "integer"},
}

func (c *Client) call(ctx context.Context, endpoint, name string, args map[string]any, token string) (any, error) {
	if endpoint == "" || !core.HTTPSURL(endpoint) {
		return nil, fault("UPSTREAM_CONTRACT_MISMATCH", "The required ASTRA HTTPS endpoint is not configured", false)
	}
	limit := c.cfg.MaxResponseBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	if limit > 16<<20 {
		limit = 16 << 20
	}
	hc := *c.httpClient
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return fmt.Errorf("redirect disabled") }
	if hc.Timeout <= 0 || hc.Timeout > 45*time.Second {
		hc.Timeout = 45 * time.Second
	}
	base := hc.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	hc.Transport = &boundedTransport{base: base, endpoint: endpoint, token: token, limit: int64(limit), operation: ctx}
	client := mcp.NewClient(&mcp.Implementation{Name: "istio-diagnostics-astra", Version: core.Version}, &mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{}, MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true}})
	// Use the established initialize handshake to avoid SDK discovery fallback
	// issuing a second request after permanent HTTP authentication failures.
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: &hc, MaxRetries: -1, DisableStandaloneSSE: true, MaxEventSize: limit}, &mcp.ClientSessionOptions{ProtocolVersion: "2025-11-25"})
	if err != nil {
		return nil, upstreamError(err)
	}
	defer session.Close()
	var selected *mcp.Tool
	cursor := ""
	seen := map[string]bool{}
	for page := 0; page < 4; page++ {
		list, err := session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, upstreamError(err)
		}
		if len(list.Tools) > 128 {
			return nil, fault("UPSTREAM_CONTRACT_MISMATCH", "ASTRA tool catalog exceeds its limit", false)
		}
		for _, tool := range list.Tools {
			if tool.Name == name {
				if selected != nil {
					return nil, fault("UPSTREAM_CONTRACT_MISMATCH", "Duplicate ASTRA tool", false)
				}
				selected = tool
			}
		}
		cursor = list.NextCursor
		if cursor == "" {
			break
		}
		if seen[cursor] || page == 3 {
			return nil, fault("UPSTREAM_CONTRACT_MISMATCH", "ASTRA tool catalog pagination is invalid", false)
		}
		seen[cursor] = true
	}
	if selected == nil {
		return nil, fault("UPSTREAM_CONTRACT_MISMATCH", "The required ASTRA tool is unavailable", false)
	}
	if err := compatible(selected, args); err != nil {
		return nil, err
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return nil, upstreamError(err)
	}
	value, err := decodeResult(result)
	if err != nil {
		return nil, err
	}
	if result.IsError {
		return nil, resultFault(value)
	}
	if m, ok := value.(map[string]any); ok {
		if _, has := m["error"]; has {
			return nil, resultFault(m)
		}
	}
	return value, nil
}
func compatible(tool *mcp.Tool, args map[string]any) error {
	fail := func() error {
		return fault("UPSTREAM_CONTRACT_MISMATCH", "ASTRA tool schema is incompatible with the fixed adapter", false)
	}
	b, err := json.Marshal(tool.InputSchema)
	if err != nil {
		return fail()
	}
	var s map[string]any
	if json.Unmarshal(b, &s) != nil || s["type"] != "object" {
		return fail()
	}
	props, ok := s["properties"].(map[string]any)
	if !ok {
		return fail()
	}
	for field := range args {
		expected := toolFields[tool.Name][field]
		p, ok := props[field].(map[string]any)
		if !ok || p["type"] != expected {
			return fail()
		}
	}
	// Validate the exact fixed payload too, including enums and newly required fields.
	var schema jsonschema.Schema
	if json.Unmarshal(b, &schema) != nil {
		return fail()
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		return fail()
	}
	raw, _ := json.Marshal(args)
	var value any
	json.Unmarshal(raw, &value)
	if resolved.Validate(value) != nil {
		return fail()
	}
	return nil
}
func decodeResult(r *mcp.CallToolResult) (any, error) {
	if r == nil {
		return nil, fault("UPSTREAM_CONTRACT_MISMATCH", "ASTRA returned no result", false)
	}
	if r.StructuredContent != nil {
		b, err := json.Marshal(r.StructuredContent)
		if err == nil {
			var v any
			if json.Unmarshal(b, &v) == nil {
				return v, nil
			}
		}
	}
	if len(r.Content) == 1 {
		if text, ok := r.Content[0].(*mcp.TextContent); ok {
			var value any
			if json.Unmarshal([]byte(text.Text), &value) == nil {
				return value, nil
			}
		}
	}
	return nil, fault("UPSTREAM_CONTRACT_MISMATCH", "ASTRA returned an unknown response shape", false)
}

type statusError struct{ status int }

func (e *statusError) Error() string { return "upstream HTTP status" }

type boundedTransport struct {
	base            http.RoundTripper
	endpoint, token string
	limit           int64
	operation       context.Context
}

func (t *boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.String() != t.endpoint {
		return nil, fault("UPSTREAM_CONTRACT_MISMATCH", "ASTRA attempted an unconfigured endpoint", false)
	}
	// The SDK detaches session cleanup from Connect; reattach every request
	// to the one operation budget, including its DELETE.
	if err := t.operation.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(t.operation, cancel)
	finish := func() { stop(); cancel() }
	req := r.Clone(ctx)
	req.Header = r.Header.Clone()
	req.Header.Set("Authorization", "Bearer "+t.token)
	res, err := t.base.RoundTrip(req)
	if err != nil {
		finish()
		return nil, err
	}
	if res.StatusCode >= 300 && res.StatusCode != 304 {
		res.Body.Close()
		finish()
		return nil, &statusError{res.StatusCode}
	}
	if res.ContentLength > t.limit {
		res.Body.Close()
		finish()
		return nil, fault("UPSTREAM_UNAVAILABLE", "ASTRA response exceeds the configured limit", false)
	}
	res.Body = &limitedBody{ReadCloser: res.Body, left: t.limit, finish: finish}
	return res, nil
}

type limitedBody struct {
	io.ReadCloser
	left   int64
	finish func()
}

func (b *limitedBody) Close() error { defer b.finish(); return b.ReadCloser.Close() }

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		var probe [1]byte
		n, err := b.ReadCloser.Read(probe[:])
		if n > 0 {
			return 0, fault("UPSTREAM_UNAVAILABLE", "ASTRA response exceeds the configured limit", false)
		}
		return 0, err
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)
	return n, err
}
func upstreamError(err error) error {
	var f *core.Fault
	if errors.As(err, &f) {
		return f
	}
	var status *statusError
	if errors.As(err, &status) {
		if status.status == 401 || status.status == 403 {
			return fault("UPSTREAM_FORBIDDEN", "ASTRA access was denied", false)
		}
		if status.status == 409 || status.status == 429 || status.status >= 500 {
			return fault("UPSTREAM_UNAVAILABLE", "ASTRA is temporarily unavailable", true)
		}
		return fault("UPSTREAM_CONTRACT_MISMATCH", "ASTRA HTTP interface is incompatible", false)
	}
	return fault("UPSTREAM_UNAVAILABLE", "ASTRA could not complete the request", true)
}
func resultFault(value any) error {
	code := ""
	if m, ok := value.(map[string]any); ok {
		code, _ = m["code"].(string)
		switch e := m["error"].(type) {
		case string:
			code = e
		case map[string]any:
			code, _ = e["code"].(string)
		}
	}
	switch code {
	case "project_access_denied":
		return fault("UPSTREAM_FORBIDDEN", "ASTRA denied access to this project", false)
	case "project_not_found", "project_id_placeholder", "invalid":
		return fault("PROJECT_SELECTION_REQUIRED", "Select a valid authorized project", false)
	case "repo_reindexing":
		return fault("UPSTREAM_UNAVAILABLE", "The repository is being reindexed", true)
	case "project_has_no_enabled_repos", "repo_not_found", "file_not_found":
		return fault("UPSTREAM_UNAVAILABLE", "The requested product source is unavailable", false)
	default:
		return fault("UPSTREAM_UNAVAILABLE", "ASTRA reported an operation error", false)
	}
}
