package diagnostics

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

func (a *analyzer) routing(d proxyConfig) {
	if !d.hasListeners {
		return
	}
	for _, e := range a.relevantEvents() {
		if e.pod != d.pod {
			continue
		}
		a.routeEvent(d, e)
	}
}
func (a *analyzer) routeEvent(d proxyConfig, e accessEvent) {
	pods := []string{a.s.Pods[d.pod].Ref.UID}
	candidates := []configNode{}
	unresolved := ""
	for _, l := range a.applicableListeners(d) {
		bind := m(field(m(field(l.value, "address")), "socket_address"))
		port := number(field(bind, "port_value"))
		if port != 0 && port != e.connection.Port && port != 15001 && port != 15006 {
			continue
		}
		address := str(bind["address"])
		if address != "" && address != "0.0.0.0" && address != "::" {
			observed, _ := hostPort(e.local)
			if observed == "" || observed == "-" {
				unresolved = "UNKNOWN"
				continue
			}
			if address != observed {
				continue
			}
		}
		if field(l.value, "filter_chain_matcher") != nil {
			unresolved = "UNSUPPORTED"
			continue
		}
		chains := children(l, "filter_chains")
		if len(chains) == 0 && field(l.value, "default_filter_chain") != nil {
			chains = append(chains, child(l, "default_filter_chain"))
		}
		for _, fc := range chains {
			match, status := filterChainMatches(m(field(fc.value, "filter_chain_match")), e)
			if status != "" {
				unresolved = status
				continue
			}
			if match {
				candidates = append(candidates, fc)
			}
		}
	}
	if unresolved != "" {
		a.add("ROUTE_SELECTION", unresolved, "unknown", "Listener/filter-chain selection requires an unsupported matcher or missing request attributes; it was not skipped as a match.", []string{e.evidence}, pods, []string{"Supported listener matcher and destination address/SNI/ALPN"})
		return
	}
	if len(candidates) != 1 {
		a.add("ROUTE_SELECTION", "UNKNOWN", "unknown", fmt.Sprintf("Current listener selection has %d candidates; a unique active filter chain was not established.", len(candidates)), []string{e.evidence}, pods, []string{"Unique listener/filter chain and destination address"})
		return
	}
	fc := candidates[0]
	for _, f := range children(fc, "filters") {
		name := str(f.value["name"])
		cfg := child(f, "typed_config")
		ids := []string{e.evidence, a.envoyEvidence(d, fc)}
		switch name {
		case "envoy.filters.network.tcp_proxy":
			if e.protocol != "tcp" && e.protocol != "unknown" {
				a.add("ROUTE_SELECTION", "UNKNOWN", "unknown", "Current filter chain uses TCP proxy while the historical record contains L7 fields; configuration-time correspondence is unknown.", ids, pods, []string{"Matching historical listener"})
				return
			}
			if len(clusterRefs(cfg)) == 0 {
				a.add("ROUTE_SELECTION", "UNSUPPORTED", "unknown", "TCP proxy cluster selection is dynamic or unsupported.", ids, pods, nil)
			} else {
				a.add("ROUTE_SELECTION", "PASS", "unknown", "A current TCP proxy filter chain is selected; HTTP path and status are not inferred for raw TCP.", ids, pods, nil)
			}
			return
		case "envoy.filters.network.http_connection_manager":
			for _, hf := range children(cfg, "http_filters") {
				switch str(hf.value["name"]) {
				case "envoy.filters.http.router", "envoy.filters.http.cors", "envoy.filters.http.fault", "envoy.filters.http.jwt_authn", "envoy.filters.http.rbac", "istio.metadata_exchange", "istio.stats":
				default:
					a.add("ROUTE_SELECTION", "UNSUPPORTED", "unknown", "An HTTP extension can alter request routing; its behavior is not evaluated.", append(ids, a.envoyEvidence(d, hf)), pods, []string{"Supported HTTP filter semantics"})
					return
				}
			}
			routes := a.hcmRoutes(d, cfg)
			if len(routes) != 1 {
				a.add("ROUTE_SELECTION", "UNKNOWN", "unknown", "The selected HTTP connection manager does not resolve to one collected active route configuration.", ids, pods, []string{"Active RDS route configuration"})
				return
			}
			a.selectRoute(d, routes[0], e, ids)
			return
		case "envoy.filters.network.rbac", "istio.metadata_exchange":
		default:
			a.add("ROUTE_SELECTION", "UNSUPPORTED", "unknown", "An unsupported network filter may alter the selected path.", append(ids, a.envoyEvidence(d, f)), pods, []string{"Supported network filter semantics"})
			return
		}
	}
	a.add("ROUTE_SELECTION", "UNKNOWN", "unknown", "No supported terminal routing filter was collected in the candidate chain.", []string{e.evidence, a.envoyEvidence(d, fc)}, pods, nil)
}
func filterChainMatches(match map[string]any, e accessEvent) (bool, string) {
	for k := range match {
		switch k {
		case "destination_port", "destinationPort", "server_names", "serverNames", "transport_protocol", "transportProtocol":
		default:
			return false, "UNSUPPORTED"
		}
	}
	if port := number(field(match, "destination_port")); port != 0 && port != e.connection.Port {
		return false, ""
	}
	if names := list(field(match, "server_names")); len(names) > 0 {
		if e.sni == "" || e.sni == "-" {
			return false, "UNKNOWN"
		}
		ok := false
		for _, v := range names {
			if domainRank(str(v), e.sni) > 0 {
				ok = true
			}
		}
		if !ok {
			return false, ""
		}
	}
	if t := str(field(match, "transport_protocol")); t != "" {
		return false, "UNKNOWN"
	} // Access log protocol does not identify listener transport socket selection.
	return true, ""
}
func domainRank(pattern, host string) int {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)
	if pattern == host {
		return 100000 + len(pattern)
	}
	if pattern == "*" {
		return 1
	}
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(host, pattern[1:]) && len(host) > len(pattern)-1 {
		return 10000 + len(pattern)
	}
	if strings.HasSuffix(pattern, "*") && strings.HasPrefix(host, strings.TrimSuffix(pattern, "*")) && len(host) > len(pattern)-1 {
		return 1000 + len(pattern)
	}
	return 0
}
func (a *analyzer) selectRoute(d proxyConfig, config configNode, e accessEvent, ids []string) {
	pods := []string{a.s.Pods[d.pod].Ref.UID}
	ids = append(ids, a.envoyEvidence(d, config))
	host := e.authority
	if host == "" || host == "-" {
		a.add("ROUTE_SELECTION", "UNKNOWN", "unknown", "Host/:authority is missing; virtual-host selection is unknown.", ids, pods, []string{"Request authority"})
		return
	}
	if b, _ := truth(field(config.value, "ignore_port_in_host_matching")); b {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	type candidate struct {
		node configNode
		rank int
	}
	hosts := []candidate{}
	for _, v := range children(config, "virtual_hosts") {
		rank := 0
		for _, domain := range list(v.value["domains"]) {
			if r := domainRank(str(domain), host); r > rank {
				rank = r
			}
		}
		if rank > 0 {
			hosts = append(hosts, candidate{v, rank})
		}
	}
	sort.SliceStable(hosts, func(i, j int) bool { return hosts[i].rank > hosts[j].rank })
	if len(hosts) == 0 {
		a.add("ROUTE_SELECTION", "FAIL", "unknown", "No current virtual host matches the observed authority in the selected route configuration; historical causality remains unproven.", ids, pods, nil)
		return
	}
	if len(hosts) > 1 && hosts[0].rank == hosts[1].rank {
		a.add("ROUTE_SELECTION", "UNKNOWN", "unknown", "Multiple current virtual hosts have the same matching specificity.", ids, pods, []string{"Unambiguous virtual-host selection"})
		return
	}
	vh := hosts[0].node
	if field(vh.value, "matcher") != nil {
		a.add("ROUTE_SELECTION", "UNSUPPORTED", "unknown", "Virtual host uses the extension matcher API.", ids, pods, nil)
		return
	}
	for _, route := range children(vh, "routes") {
		matched, status := routeMatches(m(route.value["match"]), e)
		if status != "" {
			a.add("ROUTE_SELECTION", status, "unknown", "An earlier route depends on unsupported match semantics or unavailable request attributes; later routes cannot be assumed selected.", append(ids, a.envoyEvidence(d, route)), pods, []string{"Supported route match and required request attributes"})
			return
		}
		if !matched {
			continue
		}
		if field(child(route, "route").value, "cluster_header") != nil || field(child(route, "route").value, "cluster_specifier_plugin") != nil {
			a.add("ROUTE_SELECTION", "UNSUPPORTED", "unknown", "The route selects a dynamic cluster using a request header or extension.", append(ids, a.envoyEvidence(d, route)), pods, nil)
			return
		}
		a.add("ROUTE_SELECTION", "PASS", "unknown", "A current active route matches the observed request attributes; this snapshot cannot reconstruct a previous configuration.", append(ids, a.envoyEvidence(d, route)), pods, nil)
		return
	}
	a.add("ROUTE_SELECTION", "FAIL", "unknown", "No current route matches the observed request attributes in the selected virtual host; historical causality remains unproven.", ids, pods, nil)
}
func routeMatches(match map[string]any, e accessEvent) (bool, string) {
	if match == nil {
		return false, "UNSUPPORTED"
	}
	for k := range match {
		switch k {
		case "prefix", "path", "case_sensitive", "caseSensitive", "headers":
		default:
			return false, "UNSUPPORTED"
		}
	}
	path := strings.SplitN(e.path, "?", 2)[0]
	if path == "" || path == "-" {
		return false, "UNKNOWN"
	}
	sensitive := true
	if b, ok := truth(field(match, "case_sensitive")); ok {
		sensitive = b
	}
	normalize := func(s string) string {
		if !sensitive {
			return strings.ToLower(s)
		}
		return s
	}
	path = normalize(path)
	if p, ok := match["prefix"]; ok {
		if !strings.HasPrefix(path, normalize(str(p))) {
			return false, ""
		}
	} else if p, ok := match["path"]; ok {
		if path != normalize(str(p)) {
			return false, ""
		}
	} else {
		return false, "UNSUPPORTED"
	}
	for _, hv := range list(match["headers"]) {
		h := m(hv)
		name := strings.ToLower(str(h["name"]))
		value := ""
		known := true
		switch name {
		case ":method":
			value = e.method
		case ":path":
			value = e.path
		case ":authority", "host":
			value = e.authority
		default:
			known = false
		}
		if !known || value == "" || value == "-" {
			return false, "UNKNOWN"
		}
		matched, status := headerMatches(h, value)
		if status != "" {
			return false, status
		}
		if !matched {
			return false, ""
		}
	}
	return true, ""
}
func headerMatches(h map[string]any, value string) (bool, string) {
	for k := range h {
		switch k {
		case "name", "exact_match", "exactMatch", "prefix_match", "prefixMatch", "suffix_match", "suffixMatch", "present_match", "presentMatch", "invert_match", "invertMatch":
		default:
			return false, "UNSUPPORTED"
		}
	}
	result := false
	switch {
	case field(h, "exact_match") != nil:
		result = value == str(field(h, "exact_match"))
	case field(h, "prefix_match") != nil:
		result = strings.HasPrefix(value, str(field(h, "prefix_match")))
	case field(h, "suffix_match") != nil:
		result = strings.HasSuffix(value, str(field(h, "suffix_match")))
	case field(h, "present_match") != nil:
		b, _ := truth(field(h, "present_match"))
		result = b
	default:
		return false, "UNSUPPORTED"
	}
	if b, _ := truth(field(h, "invert_match")); b {
		result = !result
	}
	return result, ""
}
