package diagnostics

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func (a *analyzer) secondary() {
	a.mechanisms()
	a.authorization()
	a.networkPolicies()
	for _, d := range a.configs {
		a.shadowing(d)
		a.sds(d)
	}
	a.replicaDivergence()
	a.tlsModes()
}
func (a *analyzer) mechanisms() {
	for _, d := range a.diagnostics {
		if !d.errorLevel {
			continue
		}
		lower := strings.ToLower(d.message)
		rule, summary := "", ""
		switch {
		case containsAny(lower, "sds", "secret") && containsAny(lower, "failed to fetch", "failed to get secret", "secret is not supplied", "secret not found", "sds stream closed", "failed to generate workload certificate"):
			rule = "SDS_DELIVERY"
			summary = "The proxy recorded an SDS/secret delivery failure; the originating CA, JWT, filesystem, or control-plane cause is not established."
		case containsAny(lower, "jwks", "jwt") && containsAny(lower, "fetch is failed", "failed to fetch", "verification failed", "jwt verification fails", "jwks remote fetch is failed"):
			rule = "JWT_VALIDATION"
			summary = "The proxy recorded a JWT/JWKS failure; provider availability and token validity require further correlated evidence. No JWKS URI was fetched by the analyzer."
		case containsAny(lower, "dns resolution failed", "dns resolution failure", "dns lookup failed"):
			rule = "DNS_CONTEXT"
			summary = "The proxy recorded a DNS-resolution failure symptom; DNS before the sidecar and the underlying resolver cause are not established."
		}
		if rule != "" {
			a.add(rule, "FAIL", "unknown", summary, []string{d.evidence}, []string{a.s.Pods[d.pod].Ref.UID}, []string{"Selected request/secret/host and diagnostic-time correlation"})
		}
	}
	for _, e := range a.relevantEvents() {
		pods := []string{a.s.Pods[e.pod].Ref.UID}
		ids := []string{e.evidence}
		lower := strings.ToLower(e.details)
		if strings.Contains(lower, "rbac_access_denied") {
			a.add("ISTIO_AUTHORIZATION", "FAIL", "probable", "Envoy reports an RBAC denial for this record; effective policy identity and scope need correlation with active RBAC configuration.", ids, pods, []string{"Effective namespace/root policies and matching active RBAC rule"})
		}
		if containsAny(lower, "jwt_authn_access_denied", "jwt_verification_failed", "jwt_expired") {
			a.add("JWT_VALIDATION", "FAIL", "probable", "Envoy reports JWT validation denial for this record; exact token/provider failure is not inferred from status alone.", ids, pods, []string{"Active JWT provider and detailed validation error"})
		}
		if strings.Contains(lower, "dns_resolution_failure") || hasFlag(e.flags, "DF") {
			a.add("DNS_CONTEXT", "FAIL", "unknown", "Envoy reports a DNS-related upstream failure symptom; the resolver/root cause is unknown.", ids, pods, []string{"Selected cluster DNS diagnostic and resolver evidence"})
		}
	}
}
func hasFlag(flags, want string) bool {
	for _, f := range strings.Split(flags, ",") {
		if strings.TrimSpace(f) == want {
			return true
		}
	}
	return false
}
func tlsRefs(cluster configNode) []configNode {
	ctx := child(child(child(cluster, "transport_socket"), "typed_config"), "common_tls_context")
	out := children(ctx, "tls_certificate_sds_secret_configs")
	for _, n := range []configNode{child(ctx, "validation_context_sds_secret_config"), child(child(ctx, "combined_validation_context"), "validation_context_sds_secret_config")} {
		if str(n.value["name"]) != "" {
			out = append(out, n)
		}
	}
	return out
}
func (a *analyzer) sds(d proxyConfig) {
	if !d.hasSecrets {
		return
	}
	for _, c := range a.selectedClusters(d) {
		for _, ref := range tlsRefs(c) {
			name := str(ref.value["name"])
			if name == "" {
				continue
			}
			ids := []string{a.envoyEvidence(d, ref)}
			found := false
			for _, secret := range d.secrets {
				if str(secret.value["name"]) == name || str(child(secret, "secret").value["name"]) == name {
					found = true
					ids = append(ids, a.envoyEvidence(d, secret))
				}
			}
			status, summary := "PASS", fmt.Sprintf("Selected TLS context references SDS secret %q and an active secret with that name is present; freshness and handshake success are separate checks.", name)
			if !found {
				status = "FAIL"
				summary = fmt.Sprintf("Selected TLS context references SDS secret %q but the complete SecretsConfigDump contains no active secret with that name; delivery/root cause remains unknown.", name)
				for _, w := range d.warming {
					if str(w.value["name"]) == name {
						status = "UNKNOWN"
						summary = fmt.Sprintf("Selected secret %q is warming; delivery has not been established in this snapshot.", name)
					}
				}
			}
			a.add("SDS_DELIVERY", status, "unknown", summary, ids, []string{a.s.Pods[d.pod].Ref.UID}, nil)
		}
	}
}
func (a *analyzer) shadowing(d proxyConfig) {
	visited := map[string]bool{}
	for _, l := range a.applicableListeners(d) {
		for _, f := range filters(l) {
			if str(f.value["name"]) != "envoy.filters.network.http_connection_manager" {
				continue
			}
			for _, r := range a.hcmRoutes(d, child(f, "typed_config")) {
				if visited[r.path] {
					continue
				}
				visited[r.path] = true
				for _, v := range children(r, "virtual_hosts") {
					routes := children(v, "routes")
					supported := true
					shadow := false
					ids := []string{}
					for i, route := range routes {
						current := m(route.value["match"])
						if !simplePathMatch(current) {
							supported = false
							continue
						}
						for j := 0; j < i; j++ {
							earlier := m(routes[j].value["match"])
							if simplePathMatch(earlier) && pathSuperset(earlier, current) {
								shadow = true
								ids = append(ids, a.envoyEvidence(d, routes[j]), a.envoyEvidence(d, route))
								break
							}
						}
					}
					if len(routes) < 2 {
						continue
					}
					status, summary := "PASS", "No fully shadowed route was found in the supported unconditional exact/prefix match subset."
					if shadow {
						status = "FAIL"
						summary = "An earlier unconditional exact/prefix route makes a later branch unreachable in the current ordered route list; this may be intentional and is not an incident cause by itself."
					} else if !supported {
						status = "UNSUPPORTED"
						summary = "Route shadowing cannot be fully evaluated because matchers extend beyond unconditional exact/prefix semantics."
					}
					if len(ids) == 0 {
						ids = append(ids, a.envoyEvidence(d, v))
					}
					a.add("ROUTE_SHADOWING", status, "unknown", summary, ids, []string{a.s.Pods[d.pod].Ref.UID}, nil)
				}
			}
		}
	}
}
func simplePathMatch(match map[string]any) bool {
	if match == nil {
		return false
	}
	for k := range match {
		if k != "path" && k != "prefix" {
			return false
		}
	}
	return match["path"] != nil || match["prefix"] != nil
}
func pathSuperset(earlier, later map[string]any) bool {
	if prefix, ok := earlier["prefix"]; ok {
		if p, ok := later["path"]; ok {
			return strings.HasPrefix(str(p), str(prefix))
		}
		return strings.HasPrefix(str(later["prefix"]), str(prefix))
	}
	return earlier["path"] != nil && later["path"] != nil && str(earlier["path"]) == str(later["path"])
}
func (a *analyzer) replicaDivergence() {
	for _, role := range []string{"source", "destination"} {
		count := 0
		for _, p := range a.s.Pods {
			if p.Role == role {
				count++
			}
		}
		if count < 2 {
			continue
		}
		signatures := map[string]bool{}
		pods, ids := []string{}, []string{}
		collected := 0
		for _, d := range a.configs {
			p := &a.s.Pods[d.pod]
			if p.Role != role {
				continue
			}
			nodes := a.selectedClusters(d)
			if len(nodes) == 0 {
				continue
			}
			collected++
			pods = append(pods, p.Ref.UID)
			parts := []string{}
			for _, n := range nodes {
				b, _ := json.Marshal(n.value)
				parts = append(parts, string(b))
				ids = append(ids, a.envoyEvidence(d, n))
			}
			if info := p.Envoy["server_info"]; len(info) > 0 {
				var v map[string]any
				if json.Unmarshal(info, &v) == nil {
					parts = append(parts, "envoy_version="+str(v["version"]))
				}
			}
			sort.Strings(parts)
			signatures[strings.Join(parts, "\n")] = true
		}
		status, summary := "UNKNOWN", "Some replica snapshots lack selected active cluster data; equality or divergence across all replicas is unknown."
		if len(signatures) > 1 {
			status = "FAIL"
			summary = "Collected replicas differ in selected active cluster semantics or Envoy version; correlation does not establish a version bug or incident cause."
		} else if collected == count {
			status = "PASS"
			summary = "Collected replicas have equal selected active cluster semantics and available Envoy versions; other configuration and traffic may differ."
		}
		a.add("REPLICA_DIVERGENCE", status, "unknown", summary, ids, pods, nil)
	}
}
func socketTLS(n configNode) (bool, bool) {
	if len(list(field(n.value, "transport_socket_matches"))) > 0 {
		return false, false
	}
	s := child(n, "transport_socket")
	name := str(s.value["name"])
	if name == "" || name == "envoy.transport_sockets.raw_buffer" {
		return false, true
	}
	if name == "envoy.transport_sockets.tls" {
		return true, true
	}
	return false, false
}

// A Service's frontend port cannot select a destination listener. Require an
// EndpointSlice association with this pod and the resolved backend port. Capture
// listeners and conditional chains need original-destination matching, which
// this bounded evaluator deliberately leaves UNKNOWN.
func (a *analyzer) destinationListeners(d proxyConfig) []configNode {
	p := &a.s.Pods[d.pod]
	ip := str(at(p.Object, "status", "podIP"))
	if ip == "" {
		return nil
	}
	host, servicePort := a.target()
	ports := map[int]bool{}
	for _, svc := range a.s.Resources {
		if svc.Kind != "Service" || svc.Namespace != p.Ref.Namespace || !includes(serviceHosts(&svc), host) {
			continue
		}
		for _, sp := range list(at(svc.Object, "spec", "ports")) {
			if servicePort > 0 && number(m(sp)["port"]) != servicePort {
				continue
			}
			name := str(m(sp)["name"])
			for _, sl := range a.s.Resources {
				if sl.Kind != "EndpointSlice" || sl.Namespace != svc.Namespace || str(at(sl.Object, "metadata", "labels", "kubernetes.io/service-name")) != svc.Name {
					continue
				}
				for _, ep := range list(sl.Object["endpoints"]) {
					uid := str(at(ep, "targetRef", "uid"))
					if uid != "" && uid != p.Ref.UID {
						continue
					}
					member := false
					for _, address := range list(m(ep)["addresses"]) {
						member = member || str(address) == ip
					}
					if !member {
						continue
					}
					for _, port := range list(sl.Object["ports"]) {
						if str(m(port)["name"]) == name && number(m(port)["port"]) > 0 {
							ports[number(m(port)["port"])] = true
						}
					}
				}
			}
		}
	}
	if len(ports) != 1 {
		return nil
	}
	out := []configNode{}
	for _, listener := range d.listeners {
		address := child(child(listener, "address"), "socket_address")
		bind := number(field(address.value, "port_value"))
		ipBind := str(address.value["address"])
		direction := str(field(listener.value, "traffic_direction"))
		if !ports[bind] || bind == 15001 || bind == 15006 || direction == "OUTBOUND" {
			continue
		}
		if ipBind == ip || ipBind == "0.0.0.0" || ipBind == "::" {
			out = append(out, listener)
		}
	}
	return out
}
func (a *analyzer) tlsModes() {
	// Deliberately bounded to one source cluster and one peer listener/chain. More
	// complex endpoint/socket/filter-chain selection is represented as UNKNOWN.
	sources, dests := []configNode{}, []configNode{}
	sourceConfigs, destConfigs := []proxyConfig{}, []proxyConfig{}
	for _, d := range a.configs {
		role := a.s.Pods[d.pod].Role
		if role == "source" {
			for _, c := range a.selectedClusters(d) {
				sources = append(sources, c)
				sourceConfigs = append(sourceConfigs, d)
			}
		} else if role == "destination" {
			for _, l := range a.destinationListeners(d) {
				if len(children(l, "filter_chains")) == 1 {
					fc := children(l, "filter_chains")[0]
					if len(m(field(fc.value, "filter_chain_match"))) == 0 && field(l.value, "filter_chain_matcher") == nil {
						dests = append(dests, fc)
						destConfigs = append(destConfigs, d)
					}
				}
			}
		}
	}
	if len(sources) != 1 || len(dests) != 1 {
		return
	}
	sourceTLS, sk := socketTLS(sources[0])
	destTLS, dk := socketTLS(dests[0])
	if !sk || !dk {
		return
	}
	status, summary := "PASS", "Selected current source and destination contexts agree on transport encryption mode; trust, identity, policy, and handshake success remain unproven."
	if sourceTLS != destTLS {
		status = "FAIL"
		summary = "Selected current source cluster and destination filter chain disagree on TLS versus plaintext transport; historical handshakes and effective identities remain unproven."
	}
	ids := []string{a.envoyEvidence(sourceConfigs[0], sources[0]), a.envoyEvidence(destConfigs[0], dests[0])}
	pods := []string{a.s.Pods[sourceConfigs[0].pod].Ref.UID, a.s.Pods[destConfigs[0].pod].Ref.UID}
	a.add("TLS_MODE_COMPATIBILITY", status, "unknown", summary, ids, pods, []string{"Correlated handshake and endpoint selection at incident time"})
}
