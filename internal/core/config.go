package core

import (
	"encoding/json"
	"fmt"
	"github.com/daybrk/istio-diagnostics-mcp/docs/design"
	"net/url"
	"strings"
)

type Config struct {
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
	Enabled              bool     `json:"enabled"`
	DefaultURL           string   `json:"default_url,omitempty"`
	AgentURL             string   `json:"agent_url,omitempty"`
	CredentialEnv        string   `json:"credential_env,omitempty"`
	AllowedProjects      []string `json:"allowed_projects,omitempty"`
	RequestBudgetSeconds int      `json:"request_budget_seconds,omitempty"`
	MaxResponseBytes     int      `json:"max_response_bytes,omitempty"`
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
	for _, s := range c.Kube.Contexts {
		if strings.HasPrefix(s.Context, "-") {
			return c, fmt.Errorf("invalid context")
		}
		for _, n := range s.Namespaces {
			if !ValidName(n) {
				return c, fmt.Errorf("invalid namespace")
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
	if c.Astra.Enabled {
		for _, u := range []string{c.Astra.DefaultURL, c.Astra.AgentURL} {
			if u != "" && !HTTPSURL(u) {
				return c, fmt.Errorf("ASTRA endpoints must be HTTPS")
			}
		}
	}
	return c, nil
}
func HTTPSURL(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}
func (c Config) LocalPrincipal() Principal {
	return Principal{ID: "local", Scopes: c.Kube.Contexts, AstraProjects: c.Astra.AllowedProjects}
}
func IntersectScopes(a, b []Scope) []Scope {
	out := []Scope{}
	p := Principal{Scopes: b}
	for _, s := range a {
		n := []string{}
		for _, v := range s.Namespaces {
			if p.Allows(s.Context, v) {
				n = append(n, v)
			}
		}
		if len(n) > 0 {
			out = append(out, Scope{Context: s.Context, Namespaces: n})
		}
	}
	return out
}
