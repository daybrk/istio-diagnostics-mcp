package diagnostics

import (
	"fmt"
	"strings"

	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
)

func (a *analyzer) resourceEvidence(r *core.Resource, path string, v any) string {
	id := a.evidence(nil, "kubernetes", fmt.Sprintf("%s/%s/%s?uid=%s#%s", r.Kind, r.Namespace, r.Name, r.UID, path), "", v)
	if id == "" {
		return ""
	}
	e := &a.out.Evidence[len(a.out.Evidence)-1]
	e.Namespace = r.Namespace
	e.ResourceUID = r.UID
	if r.CollectedAt != "" {
		e.CollectedAt = r.CollectedAt
	}
	return id
}
func (a *analyzer) listComplete(kind, namespace string) (*core.Resource, bool) {
	for i := range a.s.Resources {
		r := &a.s.Resources[i]
		if r.Kind == kind+"List" && r.Namespace == namespace {
			if _, ok := r.Object["items"].([]any); ok {
				return r, true
			}
		}
	}
	return nil, false
}
func (a *analyzer) target() (string, int) {
	if a.selected != nil {
		return a.selected.Destination, a.selected.Port
	}
	if q := a.s.Request.Peer; q != nil && a.s.Request.Direction == "outbound" {
		switch q.Kind {
		case "service":
			return q.Value + "." + q.Namespace + ".svc.cluster.local", q.Port
		case "host":
			return q.Value, q.Port
		}
	}
	if len(a.out.Connections) == 1 {
		return a.out.Connections[0].Destination, a.out.Connections[0].Port
	}
	return "", 0
}
func serviceHosts(r *core.Resource) []string {
	return []string{r.Name + "." + r.Namespace + ".svc.cluster.local", r.Name + "." + r.Namespace + ".svc", r.Name + "." + r.Namespace}
}
func includes(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func selectorMatches(selector, labels map[string]any) bool {
	for k, v := range selector {
		if str(labels[k]) != str(v) {
			return false
		}
	}
	return true
}
func (a *analyzer) serviceRelevant(r *core.Resource) bool {
	host, _ := a.target()
	if host != "" {
		return includes(serviceHosts(r), host)
	}
	// Without a selected pair, only services explicitly selecting the primary pods
	// are in scope; an unrelated namespace service is not evidence for this path.
	if a.s.Request.Direction != "inbound" {
		return false
	}
	sel := m(at(r.Object, "spec", "selector"))
	if len(sel) == 0 {
		return false
	}
	for _, p := range a.s.Pods {
		if p.Role == "destination" && p.Ref.Namespace == r.Namespace && selectorMatches(sel, m(at(p.Object, "metadata", "labels"))) {
			return true
		}
	}
	return false
}
func (a *analyzer) services() {
	for i := range a.s.Resources {
		r := &a.s.Resources[i]
		if r.Kind != "Service" || !a.serviceRelevant(r) {
			continue
		}
		serviceID := a.resourceEvidence(r, "/spec", r.Object["spec"])
		ids := []string{serviceID}
		slices := []*core.Resource{}
		for j := range a.s.Resources {
			sl := &a.s.Resources[j]
			if sl.Kind == "EndpointSlice" && sl.Namespace == r.Namespace && str(at(sl.Object, "metadata", "labels", "kubernetes.io/service-name")) == r.Name {
				slices = append(slices, sl)
				ids = append(ids, a.resourceEvidence(sl, "/endpoints", sl.Object))
			}
		}
		marker, complete := a.listComplete("EndpointSlice", r.Namespace)
		if complete {
			ids = append(ids, a.resourceEvidence(marker, "/items", map[string]any{"complete_list": true, "item_count": len(list(marker.Object["items"]))}))
		}
		ready, unknown := 0, 0
		for _, sl := range slices {
			for _, v := range list(sl.Object["endpoints"]) {
				ep := m(v)
				if len(list(ep["addresses"])) == 0 {
					continue
				}
				b, known := truth(at(ep, "conditions", "ready"))
				if !known {
					unknown++
				} else if b {
					ready++
				}
			}
		}
		status, summary := "UNKNOWN", "EndpointSlice collection is incomplete; missing endpoints cannot be treated as absent."
		switch {
		case str(at(r.Object, "spec", "type")) == "ExternalName":
			status = "UNSUPPORTED"
			summary = "ExternalName services require DNS context; EndpointSlice emptiness is not a backend failure."
		case ready > 0:
			status = "PASS"
			summary = fmt.Sprintf("Service %s/%s has %d ready endpoint entries in the collected snapshot; reachability and historical membership remain unproven.", r.Namespace, r.Name, ready)
		case complete && unknown == 0:
			status = "FAIL"
			summary = fmt.Sprintf("Service %s/%s currently has no ready endpoints in the complete collected EndpointSlice list; historical incident causality is not established.", r.Namespace, r.Name)
		case unknown > 0:
			summary = "Endpoint readiness is unspecified in the collected slices; effective backend availability is unknown."
		}
		missing := []string{}
		if !complete {
			missing = append(missing, "Complete namespace EndpointSlice list")
		}
		a.add("SERVICE_ENDPOINTS", status, "unknown", summary, ids, nil, missing)
		a.servicePorts(r, slices, complete, serviceID)
	}
}
func (a *analyzer) servicePorts(r *core.Resource, slices []*core.Resource, complete bool, serviceID string) {
	_, selectedPort := a.target()
	for i, v := range list(at(r.Object, "spec", "ports")) {
		port := m(v)
		servicePort := number(port["port"])
		if selectedPort > 0 && selectedPort != servicePort {
			continue
		}
		ids := []string{serviceID}
		pods := []string{}
		target := port["targetPort"]
		if target == nil {
			target = port["port"]
		}
		expected := map[int]bool{}
		bad, unknown := false, false
		if named, ok := target.(string); ok {
			matches := 0
			selector := m(at(r.Object, "spec", "selector"))
			if len(selector) == 0 {
				unknown = true
			}
			for j := range a.s.Pods {
				p := &a.s.Pods[j]
				if p.Ref.Namespace != r.Namespace || len(selector) == 0 || !selectorMatches(selector, m(at(p.Object, "metadata", "labels"))) {
					continue
				}
				matches++
				pods = append(pods, p.Ref.UID)
				ids = append(ids, a.podEvidence(p, "/spec/containers", at(p.Object, "spec", "containers")))
				found := false
				containers, have := at(p.Object, "spec", "containers").([]any)
				if !have {
					unknown = true
					continue
				}
				for _, cv := range containers {
					for _, pv := range list(m(cv)["ports"]) {
						cp := m(pv)
						proto := str(cp["protocol"])
						if proto == "" {
							proto = "TCP"
						}
						sp := str(port["protocol"])
						if sp == "" {
							sp = "TCP"
						}
						if str(cp["name"]) == named && proto == sp && number(cp["containerPort"]) > 0 {
							expected[number(cp["containerPort"])] = true
							found = true
						}
					}
				}
				if !found {
					bad = true
				}
			}
			if matches == 0 {
				unknown = true
			}
		} else {
			n := number(target)
			if n < 1 || n > 65535 {
				bad = true
			} else {
				expected[n] = true
			}
		}
		endpointPortCount := 0
		for _, sl := range slices {
			for _, pv := range list(sl.Object["ports"]) {
				sp := m(pv)
				if str(sp["name"]) != str(port["name"]) {
					continue
				}
				n := number(sp["port"])
				if n == 0 {
					unknown = true
					continue
				}
				endpointPortCount++
				ids = append(ids, a.resourceEvidence(sl, "/ports", sl.Object["ports"]))
				if len(expected) > 0 && !expected[n] {
					bad = true
				}
			}
		}
		status, summary := "PASS", fmt.Sprintf("Collected Service port %d resolves consistently to the observed endpoint port metadata; declared container ports do not prove a process is listening.", servicePort)
		if bad {
			status = "FAIL"
			summary = fmt.Sprintf("Service port %d has an unresolved named targetPort or disagrees with collected endpoint port metadata.", servicePort)
		} else if unknown || !complete || endpointPortCount == 0 {
			status = "UNKNOWN"
			summary = fmt.Sprintf("Service port %d cannot be fully reconciled with pod named ports and endpoint ports from the collected evidence.", servicePort)
		}
		a.add("SERVICE_PORT_MAPPING", status, "unknown", summary, ids, pods, func() []string {
			if status == "UNKNOWN" {
				return []string{"Complete backend pod/EndpointSlice port metadata"}
			}
			return nil
		}())
		_ = i
	}
}
func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
