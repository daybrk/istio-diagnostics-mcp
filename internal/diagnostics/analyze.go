// Package diagnostics evaluates collected snapshots without performing I/O.
package diagnostics

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
)

var catalog = []string{"WORKLOAD_PROXY_STATE", "PROXY_STARTUP_ERROR", "SERVICE_ENDPOINTS", "SERVICE_PORT_MAPPING", "ROUTE_SELECTION", "CLUSTER_REFERENCE", "LISTENER_CONFLICT", "ROUTE_SHADOWING", "XDS_APPLY_STATE", "TLS_VALIDITY", "TLS_MODE_COMPATIBILITY", "SDS_DELIVERY", "ISTIO_AUTHORIZATION", "JWT_VALIDATION", "NETWORK_POLICY_SCOPE", "UPSTREAM_FAILURE", "PROTOCOL_STATUS", "REPLICA_DIVERGENCE", "DNS_CONTEXT", "PRODUCT_EXPECTATION"}

// SupportedChecks lists rules with implemented, bounded evaluators. A particular
// snapshot can still yield UNKNOWN or UNSUPPORTED within a supported rule.
func SupportedChecks() []string { return append([]string(nil), catalog[:len(catalog)-1]...) }

type analyzer struct {
	s                    *core.Snapshot
	selected             *core.Connection
	out                  core.Analysis
	events               []accessEvent
	diagnostics          []diagnosticEvent
	configs              []proxyConfig
	start, end           time.Time
	validWindow          bool
	usedBytes, byteLimit int
	limited              bool
}

// Analyze is a pure snapshot evaluation. It never probes endpoints or mutates the
// snapshot. PASS/FAIL describe observations, not proof of incident causality.
func Analyze(s *core.Snapshot, selected *core.Connection) core.Analysis {
	if s == nil {
		s = &core.Snapshot{}
	}
	if selected != nil {
		local := *selected
		selected = &local
	}
	a := &analyzer{s: s, selected: selected, out: core.Analysis{Connections: []core.Connection{}, Findings: []core.Finding{}, Evidence: []core.Evidence{}, Limitations: append([]string{}, s.Limitations...)}}
	a.byteLimit = s.AnalysisByteLimit
	if a.byteLimit <= 0 {
		a.byteLimit = 8 << 20
	}
	var e1, e2 error
	a.start, e1 = time.Parse(time.RFC3339Nano, s.Request.Window.Start)
	a.end, e2 = time.Parse(time.RFC3339Nano, s.Request.Window.End)
	a.validWindow = e1 == nil && e2 == nil && a.start.Before(a.end)
	if !a.validWindow {
		a.limit("A valid frozen [start,end) window is unavailable; log records cannot be assigned to this attempt.")
	}
	a.readLogs()
	a.discover()
	a.proxyState()
	a.startup()
	a.symptoms()
	a.services()
	a.envoy()
	a.secondary()
	for _, rule := range catalog {
		found := false
		for _, f := range a.out.Findings {
			if f.RuleID == rule {
				found = true
				break
			}
		}
		if !found {
			status := "UNKNOWN"
			gap := ruleGap[rule]
			why := "This check cannot be completed without " + gap + "."
			if rule == "PRODUCT_EXPECTATION" {
				status = "UNSUPPORTED"
				why = "Product expectations require separately collected, versioned product knowledge."
			}
			a.add(rule, status, "unknown", why, nil, nil, []string{gap})
		}
	}
	sort.SliceStable(a.out.Connections, func(i, j int) bool { return connectionKey(a.out.Connections[i]) < connectionKey(a.out.Connections[j]) })
	a.out.Limitations = unique(a.out.Limitations)
	return a.out
}

func (a *analyzer) add(rule, status, confidence, summary string, ids, pods, missing []string) {
	recommendation := ruleRecommendation[rule]
	if recommendation == "" {
		recommendation = "Inspect the linked observations and the stated evidence gaps before changing configuration."
	}
	f := core.Finding{ID: core.NewID("finding"), RuleID: rule, CheckStatus: status, Confidence: confidence, Summary: summary, EvidenceIDs: unique(ids), AffectedPodUIDs: unique(pods), MissingEvidence: unique(missing), Recommendation: recommendation, Validation: "Collect a fresh snapshot with an explicit window; verify the relevant configuration and observed traffic. Configuration changes or absence of traffic alone do not establish recovery."}
	if a.reserve(f) {
		a.out.Findings = append(a.out.Findings, f)
	}
}

var ruleGap = map[string]string{
	"WORKLOAD_PROXY_STATE":   "pod spec, UID, and proxy container statuses",
	"PROXY_STARTUP_ERROR":    "supported current and available previous proxy diagnostic logs",
	"SERVICE_ENDPOINTS":      "selected Service identity and complete EndpointSlice readiness data",
	"SERVICE_PORT_MAPPING":   "Service ports, backend pod named ports, and endpoint ports",
	"ROUTE_SELECTION":        "selected active listeners/routes and sufficient request attributes",
	"CLUSTER_REFERENCE":      "active route/TCP proxy references and complete active cluster sections",
	"LISTENER_CONFLICT":      "explicit rejected listener overlap or equivalent diagnostic evidence",
	"ROUTE_SHADOWING":        "ordered active routes with supported matcher semantics",
	"XDS_APPLY_STATE":        "recognized active, warming, and rejected Envoy config sections",
	"TLS_VALIDITY":           "certificate validity metadata tied to the selected active TLS context",
	"TLS_MODE_COMPATIBILITY": "unambiguous selected TLS contexts on both sides",
	"SDS_DELIVERY":           "selected secret references, active/warming secret state, or recognized SDS errors",
	"ISTIO_AUTHORIZATION":    "effective namespace/root policy scope, active RBAC, and request attributes",
	"JWT_VALIDATION":         "a recognized JWT/JWKS error tied to the request and active provider",
	"NETWORK_POLICY_SCOPE":   "complete both-side policy scopes and observed peer/port metadata",
	"UPSTREAM_FAILURE":       "a supported access/diagnostic record identifying the upstream failure segment",
	"PROTOCOL_STATUS":        "supported HTTP/gRPC outcome fields; TCP does not supply an HTTP status",
	"REPLICA_DIVERGENCE":     "comparable selected active configurations from at least two replicas",
	"DNS_CONTEXT":            "a named cluster/service and a recognized DNS-related observation",
	"PRODUCT_EXPECTATION":    "separately collected versioned product knowledge and live observations",
}
var ruleRecommendation = map[string]string{
	"WORKLOAD_PROXY_STATE":   "Review injection/revision, proxy readiness, and linked startup or termination evidence for the affected pod UID.",
	"PROXY_STARTUP_ERROR":    "Review the exact startup/configuration error and corresponding proxy process generation before changing workload configuration.",
	"SERVICE_ENDPOINTS":      "Reconcile the selected Service selector, backend readiness, and EndpointSlice membership at the incident time.",
	"SERVICE_PORT_MAPPING":   "Reconcile Service port/targetPort, backend named ports, and EndpointSlice ports; verify application listening separately.",
	"ROUTE_SELECTION":        "Compare the selected listener/filter chain and ordered routes with the observed Host, path, SNI, and destination address.",
	"CLUSTER_REFERENCE":      "Reconcile active route/TCP proxy cluster names with active cluster configuration; inspect rejected and warming objects separately.",
	"LISTENER_CONFLICT":      "Inspect the exact rejected overlap, including listener addresses and filter-chain matches, before changing ports.",
	"ROUTE_SHADOWING":        "Check whether the unreachable branch is intentional before reordering the applicable route list.",
	"XDS_APPLY_STATE":        "Inspect the rejection/warming reason and compare versions with the still-active configuration.",
	"TLS_VALIDITY":           "Verify the selected certificate's issuer/rotation state, serial, validity interval, and TLS context at handshake time.",
	"TLS_MODE_COMPATIBILITY": "Reconcile the selected transport sockets with both-side TLS policy, trust, and identity; collect the actual handshake error.",
	"SDS_DELIVERY":           "Inspect the referenced secret and proxy delivery errors; obtain authorized control-plane evidence before assigning a CA or token cause.",
	"ISTIO_AUTHORIZATION":    "Identify the denying active RBAC rule and its effective namespace/root policy scope and request attributes.",
	"JWT_VALIDATION":         "Inspect the active JWT provider and the exact validation/JWKS error without fetching arbitrary JWKS URLs from this server.",
	"NETWORK_POLICY_SCOPE":   "Review the aggregate ingress and egress policy result for the observed peer and backend port; verify runtime enforcement separately.",
	"UPSTREAM_FAILURE":       "Correlate the upstream address and timestamp with remote proxy/application evidence to distinguish refusal, reset, and timeout causes.",
	"PROTOCOL_STATUS":        "Distinguish gRPC status, upstream application replies, and proxy-local failures before attributing a network cause.",
	"REPLICA_DIVERGENCE":     "Compare the differing selected configuration fields and traffic distribution across affected replica UIDs.",
	"DNS_CONTEXT":            "Inspect the named cluster's DNS configuration and contemporaneous resolver/proxy observations; missing access logs do not test DNS.",
}

func (a *analyzer) limit(s string) { a.out.Limitations = append(a.out.Limitations, s) }
func (a *analyzer) evidence(p *core.PodSnapshot, kind, locator, observed string, v any) string {
	lines := []string{}
	switch x := v.(type) {
	case string:
		lines = []string{core.RedactString(x)}
	default:
		b, _ := json.Marshal(core.RedactObject(v))
		lines = []string{string(b)}
	}
	e := core.Evidence{ID: core.NewID("evidence"), SourceType: kind, CollectedAt: a.s.CollectedAt, ObservedAt: observed, SourceLocator: locator, Lines: lines}
	if p != nil {
		e.PodUID = p.Ref.UID
		e.Namespace = p.Ref.Namespace
		if p.CollectedAt != "" {
			e.CollectedAt = p.CollectedAt
		}
	}
	if !a.reserve(e) {
		return ""
	}
	a.out.Evidence = append(a.out.Evidence, e)
	return e.ID
}
func (a *analyzer) podEvidence(p *core.PodSnapshot, path string, v any) string {
	return a.evidence(p, "kubernetes", fmt.Sprintf("pod/%s/%s?uid=%s#%s", p.Ref.Namespace, p.Ref.Name, p.Ref.UID, path), "", v)
}
func unique(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
func m(v any) map[string]any { x, _ := v.(map[string]any); return x }
func list(v any) []any       { x, _ := v.([]any); return x }
func at(v any, keys ...string) any {
	for _, k := range keys {
		v = m(v)[k]
	}
	return v
}
func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return fmt.Sprint(x)
	case json.Number:
		return x.String()
	case int:
		return fmt.Sprint(x)
	}
	return ""
}
func number(v any) int                           { var n int; fmt.Sscan(str(v), &n); return n }
func truth(v any) (bool, bool)                   { b, ok := v.(bool); return b, ok }
func workloadIdentity(w core.WorkloadRef) string { return core.WorkloadIdentity(w) }
func (a *analyzer) podIdentity(p *core.PodSnapshot) string {
	primaryRole := "source"
	if a.s.Request.Direction == "inbound" {
		primaryRole = "destination"
	}
	if p.Role == primaryRole {
		return workloadIdentity(a.s.Request.Workload)
	}
	if q := a.s.Request.Peer; q != nil && q.Kind == "workload" {
		return core.PeerIdentity(*q)
	}
	if q := a.s.Request.Peer; q != nil && (q.Kind == "service" || q.Kind == "host") {
		for _, r := range a.s.Resources {
			selector := m(at(r.Object, "spec", "selector"))
			matches := q.Kind == "service" && r.Name == q.Value && r.Namespace == q.Namespace || q.Kind == "host" && includes(serviceHosts(&r), q.Value)
			if r.Kind == "Service" && r.Namespace == p.Ref.Namespace && matches && len(selector) > 0 && selectorMatches(selector, m(at(p.Object, "metadata", "labels"))) {
				return r.Name + "." + r.Namespace + ".svc.cluster.local"
			}
		}
	}
	return workloadIdentity(p.Ref)
}
func connectionKey(c core.Connection) string {
	return fmt.Sprintf("%s\x00%s\x00%05d\x00%s", c.Source, c.Destination, c.Port, c.Protocol)
}
func (a *analyzer) proxyState() {
	if len(a.s.Pods) == 0 {
		a.add("WORKLOAD_PROXY_STATE", "UNKNOWN", "unknown", "No pod status was collected.", nil, nil, []string{"Pod spec and container statuses"})
		return
	}
	for i := range a.s.Pods {
		p := &a.s.Pods[i]
		spec := m(p.Object["spec"])
		declared := false
		for _, k := range []string{"containers", "initContainers"} {
			for _, v := range list(spec[k]) {
				if str(m(v)["name"]) == "istio-proxy" {
					declared = true
				}
			}
		}
		if !declared {
			status, summary := "FAIL", "The collected Pod spec has no istio-proxy container; injection and workload mode need verification."
			if spec == nil {
				status = "UNKNOWN"
				summary = "Pod spec is unavailable; proxy presence cannot be evaluated."
			}
			id := a.podEvidence(p, "/spec", spec)
			a.add("WORKLOAD_PROXY_STATE", status, "unknown", summary, []string{id}, []string{p.Ref.UID}, nil)
			continue
		}
		found := false
		for _, k := range []string{"containerStatuses", "initContainerStatuses"} {
			for j, v := range list(at(p.Object, "status", k)) {
				s := m(v)
				if str(s["name"]) != "istio-proxy" {
					continue
				}
				found = true
				id := a.podEvidence(p, fmt.Sprintf("/status/%s/%d", k, j), s)
				ready, known := truth(s["ready"])
				status, summary := "PASS", "Proxy is ready in the collected Pod status; this does not establish network health."
				if !known {
					status = "UNKNOWN"
					summary = "Proxy status has no readiness value."
				} else if !ready {
					status = "FAIL"
					summary = "Proxy is not ready in the collected Pod status."
				}
				if number(s["restartCount"]) > 0 {
					summary += " Restart history is present; a restart alone does not identify its cause."
				}
				a.add("WORKLOAD_PROXY_STATE", status, "unknown", summary, []string{id}, []string{p.Ref.UID}, nil)
			}
		}
		if !found {
			id := a.podEvidence(p, "/status", p.Object["status"])
			a.add("WORKLOAD_PROXY_STATE", "UNKNOWN", "unknown", "Proxy is declared but its container status is unavailable.", []string{id}, []string{p.Ref.UID}, []string{"istio-proxy container status"})
		}
	}
}

func (a *analyzer) startup() {
	for _, d := range a.diagnostics {
		lower := strings.ToLower(d.message)
		if !d.errorLevel {
			continue
		}
		if containsAny(lower, "failed to start envoy", "invalid bootstrap", "bootstrap configuration is invalid", "error initializing configuration", "failed to create envoy", "envoy exited with error") {
			a.add("PROXY_STARTUP_ERROR", "FAIL", "probable", "The proxy emitted a recognized startup/configuration error in the requested window; linkage to a particular traffic failure remains unproven.", []string{d.evidence}, []string{a.s.Pods[d.pod].Ref.UID}, []string{"Process generation and incident correlation"})
		}
	}
	if len(findingsFor(a.out.Findings, "PROXY_STARTUP_ERROR")) == 0 {
		if a.logsComplete() {
			a.add("PROXY_STARTUP_ERROR", "PASS", "unknown", "No recognized startup error occurs in the collected log window; earlier or rotated logs may differ.", nil, nil, nil)
		} else {
			a.add("PROXY_STARTUP_ERROR", "UNKNOWN", "unknown", "Startup history is incomplete or unavailable.", nil, nil, []string{"Complete current and available previous proxy diagnostic logs"})
		}
	}
}
func containsAny(s string, parts ...string) bool {
	for _, p := range parts {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}
func findingsFor(fs []core.Finding, rule string) []core.Finding {
	out := []core.Finding{}
	for _, f := range fs {
		if f.RuleID == rule {
			out = append(out, f)
		}
	}
	return out
}
func (a *analyzer) logsComplete() bool {
	if len(a.s.Pods) == 0 || !a.validWindow {
		return false
	}
	for _, p := range a.s.Pods {
		found := false
		for _, c := range a.s.Coverage {
			if c.PodUID == p.Ref.UID && c.Source == "logs_current" && c.Status == "collected" {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Limit intermediate observations as well as retained coordinator state. The
// explicit limitation means truncated log discovery is never complete/healthy.
func (a *analyzer) reserve(v any) bool {
	b, _ := json.Marshal(v)
	if a.usedBytes+len(b)+256 > a.byteLimit {
		if !a.limited {
			a.limit("RESOURCE_LIMIT: analyzer materialization budget reached; some log records, findings or evidence were omitted. Discovery is incomplete.")
			a.limited = true
		}
		return false
	}
	a.usedBytes += len(b) + 256
	return true
}
