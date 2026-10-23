package diagnostics

import (
	"fmt"
	"net"
	"strings"

	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
)

func (a *analyzer) authorization() {
	for i := range a.s.Resources {
		r := &a.s.Resources[i]
		if r.Kind != "AuthorizationPolicy" {
			continue
		}
		spec := m(r.Object["spec"])
		id := a.resourceEvidence(r, "/spec", spec)
		version := str(r.Object["apiVersion"])
		if version != "security.istio.io/v1" && version != "security.istio.io/v1beta1" {
			a.add("ISTIO_AUTHORIZATION", "UNSUPPORTED", "unknown", "AuthorizationPolicy API version is outside the supported v1/v1beta1 subset.", []string{id}, nil, nil)
			continue
		}
		if str(spec["action"]) == "CUSTOM" || spec["targetRefs"] != nil || spec["targetRef"] != nil {
			a.add("ISTIO_AUTHORIZATION", "UNSUPPORTED", "unknown", "CUSTOM authorization providers and targetRefs require semantics not evaluated by this ruleset.", []string{id}, nil, []string{"Effective external provider or targetRefs semantics"})
			continue
		}
		if str(spec["action"]) != "DENY" {
			continue
		} // No claim of full ALLOW scope without mesh root configuration.
		for _, e := range a.relevantEvents() {
			p := &a.s.Pods[e.pod]
			if p.Role != "destination" || p.Ref.Namespace != r.Namespace {
				continue
			}
			selector := m(at(spec, "selector", "matchLabels"))
			if !selectorMatches(selector, m(at(p.Object, "metadata", "labels"))) {
				continue
			}
			status := ""
			matched := false
			for _, rv := range list(spec["rules"]) {
				match, boundary := denyRule(m(rv), e)
				if boundary != "" {
					status = boundary
				}
				if match {
					matched = true
					break
				}
			}
			if matched {
				summary := "A namespace-scoped DENY rule statically matches the observed request attributes; active RBAC and historical policy identity are required to establish enforcement."
				if e.protocol == "tcp" {
					summary = "A namespace-scoped DENY rule matches TCP under Istio DENY missing-HTTP-attribute semantics; HTTP conditions are not silently discarded. Active RBAC enforcement remains unproven."
				}
				a.add("ISTIO_AUTHORIZATION", "FAIL", "unknown", summary, []string{id, e.evidence}, []string{p.Ref.UID}, []string{"Active RBAC rule and historical effective namespace/root policy scope"})
			} else if status != "" {
				a.add("ISTIO_AUTHORIZATION", status, "unknown", "DENY evaluation requires unsupported conditions or missing request/source attributes.", []string{id, e.evidence}, []string{p.Ref.UID}, nil)
			}
		}
	}
}
func denyRule(rule map[string]any, e accessEvent) (bool, string) {
	for k := range rule {
		if k != "to" {
			return false, "UNSUPPORTED"
		}
	}
	to := list(rule["to"])
	if len(to) == 0 {
		return true, ""
	}
	boundary := ""
	for _, tv := range to {
		op := m(at(tv, "operation"))
		ok := true
		for k, v := range op {
			value := ""
			switch k {
			case "methods":
				value = e.method
			case "paths":
				value = e.path
			case "hosts":
				value = e.authority
			case "ports":
				value = fmt.Sprint(e.connection.Port)
			default:
				return false, "UNSUPPORTED"
			}
			if k != "ports" && e.protocol == "tcp" {
				continue
			} // In DENY, missing HTTP attributes match.
			if value == "" || value == "-" || k == "ports" && e.connection.Port == 0 {
				boundary = "UNKNOWN"
				ok = false
				continue
			}
			matches := false
			for _, pv := range list(v) {
				if wildcard(str(pv), value) {
					matches = true
				}
			}
			if !matches {
				ok = false
			}
		}
		if ok {
			return true, ""
		}
	}
	return false, boundary
}
func wildcard(pattern, value string) bool {
	if pattern == "*" {
		return value != ""
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(value, pattern[1:])
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == value
}
func (a *analyzer) networkPolicies() {
	for i := range a.s.Pods {
		p := &a.s.Pods[i]
		if p.Role != "source" && p.Role != "destination" {
			continue
		}
		direction, policyType, peerKey := "ingress", "Ingress", "from"
		if p.Role == "source" {
			direction, policyType, peerKey = "egress", "Egress", "to"
		}
		marker, complete := a.listComplete("NetworkPolicy", p.Ref.Namespace)
		ids, pods := []string{}, []string{p.Ref.UID}
		isolated, allowed := false, false
		boundary := ""
		for j := range a.s.Resources {
			r := &a.s.Resources[j]
			if r.Kind != "NetworkPolicy" || r.Namespace != p.Ref.Namespace {
				continue
			}
			spec := m(r.Object["spec"])
			selector := m(spec["podSelector"])
			if len(list(selector["matchExpressions"])) > 0 {
				boundary = "UNSUPPORTED"
				continue
			}
			if !selectorMatches(m(selector["matchLabels"]), m(at(p.Object, "metadata", "labels"))) {
				continue
			}
			types := list(spec["policyTypes"])
			applies := false
			if len(types) == 0 {
				applies = policyType == "Ingress" || spec["egress"] != nil
			} else {
				for _, typ := range types {
					if str(typ) == policyType {
						applies = true
					}
				}
			}
			if !applies {
				continue
			}
			isolated = true
			ids = append(ids, a.resourceEvidence(r, "/spec", spec))
			for _, rv := range list(spec[direction]) {
				ok, status := a.networkRule(m(rv), p, peerKey)
				if status != "" {
					if boundary != "UNSUPPORTED" {
						boundary = status
					}
				}
				if ok {
					allowed = true
				}
			}
		}
		if marker != nil {
			ids = append(ids, a.resourceEvidence(marker, "/items", map[string]any{"complete_list": true, "item_count": len(list(marker.Object["items"]))}))
		}
		status, summary := "UNKNOWN", "Complete NetworkPolicy scope is unavailable; absence or one isolating policy cannot establish the aggregate result."
		if complete {
			switch {
			case allowed:
				status = "PASS"
				summary = fmt.Sprintf("Collected NetworkPolicies statically permit %s for this pod in the evaluated rule subset; this does not verify CNI, NAT, conntrack, or runtime connectivity.", direction)
			case boundary != "":
				status = boundary
				summary = "NetworkPolicy evaluation needs unsupported selectors or unavailable peer/port metadata; such rules were not ignored."
			case !isolated:
				status = "PASS"
				summary = fmt.Sprintf("The complete namespace policy list contains no policy isolating this pod's %s direction; other controls and runtime networking remain untested.", direction)
			default:
				status = "FAIL"
				summary = fmt.Sprintf("The complete collected NetworkPolicy set statically isolates this pod's %s direction without a matching allow rule; this is not proof of the runtime incident cause.", direction)
			}
		}
		a.add("NETWORK_POLICY_SCOPE", status, "unknown", summary, ids, pods, func() []string {
			if status == "UNKNOWN" {
				return []string{"Complete both-side NetworkPolicy and peer attributes"}
			}
			return nil
		}())
	}
}
func (a *analyzer) networkRule(rule map[string]any, p *core.PodSnapshot, peerKey string) (bool, string) {
	for key := range rule {
		if key != peerKey && key != "ports" {
			return false, "UNSUPPORTED"
		}
	}
	if ports := list(rule["ports"]); len(ports) > 0 {
		targetPort := a.observedBackendPort(p)
		if targetPort == 0 {
			return false, "UNKNOWN"
		}
		portOK := false
		for _, pv := range ports {
			port := m(pv)
			if end := port["endPort"]; end != nil {
				return false, "UNSUPPORTED"
			}
			if _, named := port["port"].(string); named {
				return false, "UNSUPPORTED"
			}
			protocol := str(port["protocol"])
			if protocol != "" && protocol != "TCP" {
				return false, "UNKNOWN"
			}
			n := number(port["port"])
			if n == 0 || n == targetPort {
				portOK = true
			}
		}
		if !portOK {
			return false, ""
		}
	}
	peers := list(rule[peerKey])
	if len(peers) == 0 {
		return true, ""
	}
	boundary := ""
	for _, pv := range peers {
		peer := m(pv)
		if len(peer) == 0 {
			return true, ""
		}
		for k := range peer {
			if k != "podSelector" && k != "namespaceSelector" && k != "ipBlock" {
				return false, "UNSUPPORTED"
			}
		}
		for _, key := range []string{"podSelector", "namespaceSelector"} {
			if len(list(at(peer, key, "matchExpressions"))) > 0 {
				return false, "UNSUPPORTED"
			}
		}
		if peer["ipBlock"] != nil {
			block := m(peer["ipBlock"])
			_, cidr, err := net.ParseCIDR(str(block["cidr"]))
			if err != nil {
				return false, "UNSUPPORTED"
			}
			matched := false
			ip := net.ParseIP(a.observedPeerIP(p))
			if ip != nil {
				ok := cidr.Contains(ip)
				for _, ex := range list(block["except"]) {
					_, exclude, err := net.ParseCIDR(str(ex))
					if err != nil {
						return false, "UNSUPPORTED"
					}
					if exclude.Contains(ip) {
						ok = false
					}
				}
				matched = ok
			}
			if matched {
				return true, ""
			}
			if ip == nil {
				boundary = "UNKNOWN"
			}
			continue
		}
		observedIP := a.observedPeerIP(p)
		if observedIP == "" {
			boundary = "UNKNOWN"
			continue
		}
		havePeer := false
		for i := range a.s.Pods {
			other := &a.s.Pods[i]
			if other.Role == p.Role || str(at(other.Object, "status", "podIP")) != observedIP {
				continue
			}
			havePeer = true
			namespaceMatch := other.Ref.Namespace == p.Ref.Namespace
			if selector, exists := peer["namespaceSelector"]; exists {
				nsLabels, found := a.namespaceLabels(other.Ref.Namespace)
				if !found {
					boundary = "UNKNOWN"
					continue
				}
				namespaceMatch = selectorMatches(m(m(selector)["matchLabels"]), nsLabels)
			}
			if !namespaceMatch {
				continue
			}
			if selector, exists := peer["podSelector"]; exists && !selectorMatches(m(m(selector)["matchLabels"]), m(at(other.Object, "metadata", "labels"))) {
				continue
			}
			return true, ""
		}
		if !havePeer {
			boundary = "UNKNOWN"
		}
	}
	return false, boundary
}
func (a *analyzer) observedPeerIP(p *core.PodSnapshot) string {
	ips := map[string]bool{}
	for _, e := range a.relevantEvents() {
		if a.s.Pods[e.pod].Ref.UID != p.Ref.UID {
			continue
		}
		address := e.downstream
		if p.Role == "source" {
			address = e.upstream
		}
		host, _ := hostPort(address)
		if net.ParseIP(host) != nil {
			ips[host] = true
		}
	}
	if len(ips) != 1 {
		return ""
	}
	for ip := range ips {
		return ip
	}
	return ""
}
func (a *analyzer) observedBackendPort(p *core.PodSnapshot) int {
	ports := map[int]bool{}
	for _, e := range a.relevantEvents() {
		if a.s.Pods[e.pod].Ref.UID != p.Ref.UID {
			continue
		}
		address := e.downstream
		if p.Role == "source" {
			address = e.upstream
		} else {
			address = e.local
		}
		_, port := hostPort(address)
		if port != 0 {
			ports[port] = true
		}
	}
	if len(ports) != 1 {
		return 0
	}
	for port := range ports {
		return port
	}
	return 0
}
func (a *analyzer) namespaceLabels(namespace string) (map[string]any, bool) {
	for _, r := range a.s.Resources {
		if r.Kind == "Namespace" && r.Name == namespace {
			return m(at(r.Object, "metadata", "labels")), true
		}
	}
	return nil, false
}
