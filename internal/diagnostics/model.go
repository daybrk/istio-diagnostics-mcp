// Package diagnostics implements conservative, evidence-based Envoy diagnostics.
package diagnostics

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Object = map[string]any

type Evidence struct {
	Source      string `json:"source"`
	Path        string `json:"path"`
	Observation string `json:"observation"`
}

type Check struct {
	Code           string     `json:"code"`
	Status         string     `json:"status"`
	Severity       string     `json:"severity"`
	Summary        string     `json:"summary"`
	Evidence       []Evidence `json:"evidence"`
	Recommendation string     `json:"recommendation,omitempty"`
}

type Report struct {
	Verdict       string   `json:"verdict"`
	Summary       string   `json:"summary"`
	EvaluatedAt   string   `json:"evaluated_at"`
	Checks        []Check  `json:"checks"`
	ContextChecks []Check  `json:"context_checks,omitempty"`
	Path          []string `json:"path"`
	Limitations   []string `json:"limitations"`
}

type Request struct {
	Direction     string            `json:"direction" jsonschema:"inbound or outbound, relative to the inspected proxy"`
	Port          int               `json:"port" jsonschema:"Destination port as seen by this proxy; 1..65535"`
	Protocol      string            `json:"protocol" jsonschema:"HTTP, HTTPS, TLS, or TCP"`
	DestinationIP string            `json:"destination_ip,omitempty"`
	ListenerName  string            `json:"listener_name,omitempty"`
	Host          string            `json:"host,omitempty"`
	SNI           string            `json:"sni,omitempty"`
	Method        string            `json:"method,omitempty"`
	Path          string            `json:"path,omitempty"`
	ALPN          string            `json:"alpn,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
}

func (r *Request) Validate() error {
	if r.Direction != "inbound" && r.Direction != "outbound" {
		return fmt.Errorf("direction must be inbound or outbound")
	}
	if r.Port < 1 || r.Port > 65535 {
		return fmt.Errorf("port must be 1..65535")
	}
	r.Protocol = strings.ToUpper(r.Protocol)
	switch r.Protocol {
	case "HTTP", "HTTPS", "TLS", "TCP":
	default:
		return fmt.Errorf("protocol must be HTTP, HTTPS, TLS, or TCP")
	}
	if r.Method == "" {
		r.Method = "GET"
	}
	if r.Path == "" {
		r.Path = "/"
	}
	return nil
}

func newReport(at time.Time) Report {
	return Report{Verdict: "undetermined", Summary: "Configuration evidence only; network reachability is not established.", EvaluatedAt: at.UTC().Format(time.RFC3339), Checks: []Check{}, Path: []string{}, Limitations: []string{}}
}

func (r *Report) add(code, status, severity, summary, path, observation, fix string) {
	r.Checks = append(r.Checks, Check{code, status, severity, summary, []Evidence{{"config_dump", path, observation}}, fix})
}
func (r *Report) blocked(summary string) { r.Verdict = "configuration_blocked"; r.Summary = summary }
func (r *Report) unknown(code, summary, path string) {
	r.add(code, "UNKNOWN", "warning", summary, path, summary, "")
}
func (r *Report) unsupported(summary, path string) {
	r.add("UNSUPPORTED_CONFIGURATION", "UNSUPPORTED", "warning", summary, path, summary, "")
	r.Limitations = append(r.Limitations, summary)
}

func key(s string) string { return strings.ToLower(strings.ReplaceAll(s, "_", "")) }
func get(o Object, name string) any {
	if v, ok := o[name]; ok {
		return v
	}
	for k, v := range o {
		if key(k) == key(name) {
			return v
		}
	}
	return nil
}
func obj(v any) Object {
	if o, ok := v.(map[string]any); ok {
		return o
	}
	return Object{}
}
func arr(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	return nil
}
func str(v any) string { s, _ := v.(string); return s }
func num(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	}
	return 0
}
func truth(v any) bool                { b, _ := v.(bool); return b }
func field(o Object, n string) string { return str(get(o, n)) }
func name(o Object) string            { return field(o, "name") }
func actual(o Object, n string) string {
	for k := range o {
		if key(k) == key(n) {
			return k
		}
	}
	return n
}
func pointer(s string) string                      { return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1") }
func child(path string, o Object, k string) string { return path + "/" + pointer(actual(o, k)) }

type item struct {
	Value Object
	Path  string
}
type dump struct {
	Listeners, Clusters, Routes, Secrets, Endpoints []item
	Sections                                        map[string]bool
	Raw                                             Object
}

func parse(raw Object) (dump, error) {
	d := dump{Raw: raw, Sections: map[string]bool{}}
	b, err := json.Marshal(raw)
	if err != nil {
		return d, err
	}
	if len(b) > 20<<20 {
		return d, fmt.Errorf("dump exceeds 20 MiB")
	}
	configs, ok := get(raw, "configs").([]any)
	if !ok {
		return d, fmt.Errorf("expected a full Envoy config_dump object with a configs array")
	}
	for i, c := range configs {
		o := obj(c)
		p := fmt.Sprintf("/configs/%d", i)
		t := field(o, "@type")
		if !strings.Contains(t, "envoy.admin.v3.") {
			continue
		}
		switch {
		case strings.HasSuffix(t, "ListenersConfigDump"):
			d.Sections["listeners"] = true
			for _, x := range entries(o, p, "static_listeners") {
				d.Listeners = append(d.Listeners, item{obj(get(x.Value, "listener")), child(x.Path, x.Value, "listener")})
			}
			for _, x := range entries(o, p, "dynamic_listeners") {
				a := obj(get(x.Value, "active_state"))
				if len(a) > 0 {
					d.Listeners = append(d.Listeners, item{obj(get(a, "listener")), child(child(x.Path, x.Value, "active_state"), a, "listener")})
				}
			}
		case strings.HasSuffix(t, "ClustersConfigDump"):
			d.Sections["clusters"] = true
			for _, k := range []string{"static_clusters", "dynamic_active_clusters"} {
				for _, x := range entries(o, p, k) {
					d.Clusters = append(d.Clusters, item{obj(get(x.Value, "cluster")), child(x.Path, x.Value, "cluster")})
				}
			}
		case strings.HasSuffix(t, "RoutesConfigDump"):
			d.Sections["routes"] = true
			for _, k := range []string{"static_route_configs", "dynamic_route_configs"} {
				for _, x := range entries(o, p, k) {
					d.Routes = append(d.Routes, item{obj(get(x.Value, "route_config")), child(x.Path, x.Value, "route_config")})
				}
			}
		case strings.HasSuffix(t, "SecretsConfigDump"):
			d.Sections["secrets"] = true
			for _, k := range []string{"static_secrets", "dynamic_active_secrets"} {
				for _, x := range entries(o, p, k) {
					d.Secrets = append(d.Secrets, item{obj(get(x.Value, "secret")), child(x.Path, x.Value, "secret")})
				}
			}
		case strings.HasSuffix(t, "EndpointsConfigDump"):
			d.Sections["endpoints"] = true
			for _, k := range []string{"static_endpoint_configs", "dynamic_endpoint_configs"} {
				for _, x := range entries(o, p, k) {
					d.Endpoints = append(d.Endpoints, item{obj(get(x.Value, "endpoint_config")), child(x.Path, x.Value, "endpoint_config")})
				}
			}
		}
	}
	if len(d.Sections) == 0 {
		return d, fmt.Errorf("no supported Envoy v3 configuration sections found")
	}
	return d, nil
}
func entries(o Object, p, k string) []item {
	out := []item{}
	for i, v := range arr(get(o, k)) {
		out = append(out, item{obj(v), fmt.Sprintf("%s/%d", child(p, o, k), i)})
	}
	return out
}
func walk(v any, p string, f func(Object, string)) {
	switch x := v.(type) {
	case map[string]any:
		f(x, p)
		for k, c := range x {
			walk(c, p+"/"+pointer(k), f)
		}
	case []any:
		for i, c := range x {
			walk(c, fmt.Sprintf("%s/%d", p, i), f)
		}
	}
}
