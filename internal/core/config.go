package core

import (
	"encoding/json"
	"fmt"
	"github.com/daybrk/istio-diagnostics-mcp/docs/design"
	"net/url"
	"strings"
)

type Config struct {
	Warnings      []string    `json:"-"`
	SchemaVersion string      `json:"schema_version"`
	Transport     string      `json:"transport"`
	HTTP          *HTTPConfig `json:"http,omitempty"`
	Kube          KubeConfig  `json:"kube"`
	Limits        Limits      `json:"limits"`
	Astra         AstraConfig `json:"astra"`
}
type KubeConfig struct {
	KubeconfigPath string  `json:"kubeconfig_path"`
	Contexts       []Scope `json:"contexts"`
}
type Limits struct {
	MaxSessions            int `json:"max_sessions"`
	SessionIdleTTLSeconds  int `json:"session_idle_ttl_seconds"`
	MemoryBytes            int `json:"memory_bytes"`
	PodConcurrency         int `json:"pod_concurrency"`
	PortForwardConcurrency int `json:"port_forward_concurrency"`
	RequestTimeoutSeconds  int `json:"request_timeout_seconds"`
	OperationBudgetSeconds int `json:"operation_budget_seconds"`
	MaxLogBytes            int `json:"max_log_bytes"`
	MaxEnvoyResponseBytes  int `json:"max_envoy_response_bytes"`
	MaxToolResponseBytes   int `json:"max_tool_response_bytes"`
}
type HTTPConfig struct {
	Listen         string     `json:"listen"`
	PublicURL      string     `json:"public_url"`
	AllowedOrigins []string   `json:"allowed_origins"`
	Auth           AuthConfig `json:"auth"`
}
type AuthConfig struct {
	Mode     string    `json:"mode"`
	Issuer   string    `json:"issuer"`
	Audience string    `json:"audience"`
	Bindings []Binding `json:"bindings"`
}
type Binding struct {
	Subject       string   `json:"subject"`
	Contexts      []Scope  `json:"contexts"`
	AstraProjects []string `json:"astra_projects"`
}
type AstraConfig struct {
	Enabled              *bool    `json:"enabled,omitempty"` // Legacy override; nil means infer from settings.
	DefaultURL           string   `json:"default_url,omitempty"`
	AgentURL             string   `json:"agent_url,omitempty"`
	CredentialEnv        string   `json:"credential_env,omitempty"`
	AllowedProjects      []string `json:"allowed_projects,omitzero"` // nil: upstream credential scope; empty: deny all.
	RequestBudgetSeconds int      `json:"request_budget_seconds,omitempty"`
	MaxResponseBytes     int      `json:"max_response_bytes,omitempty"`
}

func (c AstraConfig) Available() bool {
	return (c.Enabled == nil || *c.Enabled) && c.CredentialEnv != "" && (c.DefaultURL != "" || c.AgentURL != "")
}

func (c AstraConfig) ProjectAllowed(id string) bool {
	if c.AllowedProjects == nil {
		return true
	}
	for _, allowed := range c.AllowedProjects {
		if allowed == id {
			return true
		}
	}
	return false
}

func ParseConfig(b []byte) (Config, error) {
	var c Config
	var raw any
	if e := json.Unmarshal(b, &raw); e != nil {
		return c, e
	}
	if e := design.Validate("config", raw); e != nil {
		return c, e
	}
	if e := json.Unmarshal(b, &c); e != nil {
		return c, e
	}
	if len(c.Kube.Contexts) == 0 {
		return c, fmt.Errorf("at least one Kubernetes scope is required")
	}
	normalize := func(scopes []Scope) ([]Scope, error) {
		for _, scope := range scopes {
			if strings.HasPrefix(scope.Context, "-") {
				return nil, fmt.Errorf("invalid context")
			}
			if scope.Namespaces != nil && len(c.Warnings) == 0 {
				c.Warnings = append(c.Warnings, "Legacy namespaces lists are ignored: all namespaces in assigned contexts are available, subject to Kubernetes RBAC. Remove namespaces from kube.contexts and HTTP bindings.")
			}
		}
		return ContextScopes(scopes), nil
	}
	var err error
	if c.Kube.Contexts, err = normalize(c.Kube.Contexts); err != nil {
		return c, err
	}
	if c.HTTP != nil {
		for i := range c.HTTP.Auth.Bindings {
			binding := &c.HTTP.Auth.Bindings[i]
			if binding.Contexts, err = normalize(binding.Contexts); err != nil {
				return c, err
			}
		}
	}
	if c.Transport == "streamable_http" {
		if c.HTTP == nil {
			return c, fmt.Errorf("HTTP configuration required")
		}
		for _, u := range []string{c.HTTP.PublicURL, c.HTTP.Auth.Issuer} {
			if !HTTPSURL(u) {
				return c, fmt.Errorf("HTTP public URL and OIDC issuer must be HTTPS")
			}
		}
	}
	if c.Astra.Available() {
		for _, u := range []string{c.Astra.DefaultURL, c.Astra.AgentURL} {
			if u != "" && !HTTPSURL(u) {
				return c, fmt.Errorf("ASTRA endpoints must be HTTPS")
			}
		}
	}
	if c.Astra.RequestBudgetSeconds == 0 {
		c.Astra.RequestBudgetSeconds = 45
	}
	if c.Astra.MaxResponseBytes == 0 {
		c.Astra.MaxResponseBytes = 1 << 20
	}
	return c, nil
}
func HTTPSURL(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}
func (c Config) LocalPrincipal() Principal {
	return Principal{ID: "local", Scopes: ContextScopes(c.Kube.Contexts), AstraProjects: c.Astra.AllowedProjects, AstraCredentialScope: c.Astra.AllowedProjects == nil}
}

// ContextScopes canonicalizes scope for capabilities and session authorization.
// Namespaces remains a wire compatibility field; "*" is never a workload namespace.
func ContextScopes(scopes []Scope) []Scope {
	out := []Scope{}
	seen := map[string]bool{}
	for _, s := range scopes {
		if !seen[s.Context] {
			out = append(out, Scope{Context: s.Context, Namespaces: []string{"*"}})
			seen[s.Context] = true
		}
	}
	return out
}
func IntersectScopes(a, b []Scope) []Scope {
	out := []Scope{}
	p := Principal{Scopes: b}
	for _, s := range ContextScopes(a) {
		if p.AllowsContext(s.Context) {
			out = append(out, s)
		}
	}
	return out
}
