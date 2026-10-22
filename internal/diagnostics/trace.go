package diagnostics

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// Trace deliberately stops on unknown selectors instead of guessing Envoy's decision.
func Trace(raw Object, q Request, at time.Time) (Report, error) {
	r := newReport(at)
	if err := q.Validate(); err != nil {
		return r, err
	}
	d, err := parse(raw)
	if err != nil {
		return r, err
	}
	r.Limitations = append(r.Limitations, "Single-proxy configuration trace. DNS, traffic capture, policy enforcement, runtime endpoint selection and network reachability require additional evidence.")
	candidates := []item{}
	best := -1
	for _, l := range d.Listeners {
		if q.ListenerName != "" && name(l.Value) != q.ListenerName {
			continue
		}
		dir := field(l.Value, "traffic_direction")
		if (dir == "INBOUND" && q.Direction != "inbound") || (dir == "OUTBOUND" && q.Direction != "outbound") {
			continue
		}
		sa := obj(get(obj(get(l.Value, "address")), "socket_address"))
		port := num(get(sa, "port_value"))
		address := field(sa, "address")
		rank := 0
		if q.ListenerName == "" {
			if port != q.Port {
				if !(q.Direction == "inbound" && port == 15006) {
					continue
				}
			} else {
				rank = 1
			}
			if address != "0.0.0.0" && address != "::" && address != "" {
				if q.DestinationIP == "" {
					r.unknown("DESTINATION_IP_REQUIRED", "Supply destination_ip or listener_name to distinguish address-specific listeners.", l.Path)
					return r, nil
				}
				if address != q.DestinationIP {
					continue
				}
				rank += 2
			}
		}
		if rank > best {
			candidates = nil
			best = rank
		}
		if rank == best {
			candidates = append(candidates, l)
		}
	}
	if len(candidates) == 0 {
		r.unknown("LISTENER_NOT_FOUND", "No matching listener was identified. Capture/original-destination dispatch and dump completeness need verification.", "")
		return r, nil
	}
	if len(candidates) > 1 {
		r.unknown("LISTENER_AMBIGUOUS", "Multiple listeners are possible; supply listener_name and the original destination IP.", "")
		return r, nil
	}
	l := candidates[0]
	r.Path = append(r.Path, "listener: "+name(l.Value))
	r.add("LISTENER_SELECTED", "PASS", "info", "Selected listener.", l.Path, name(l.Value), "")
	if get(l.Value, "filter_chain_matcher") != nil {
		r.unsupported("Generic filter_chain_matcher trees are not evaluated in v0.1.", l.Path)
		return r, nil
	}
	// Envoy prunes candidates at each specificity stage. It does not fall back
	// to a less-specific SNI chain after the best SNI chain fails ALPN matching.
	choices := entries(l.Value, l.Path, "filter_chains")
	for stage, k := range []string{"destination_port", "prefix_ranges", "server_names", "transport_protocol", "application_protocols"} {
		next := []item{}
		bestScore := -1
		for _, fc := range choices {
			m := obj(get(fc.Value, "filter_chain_match"))
			criterion := Object{}
			if v := get(m, k); v != nil {
				criterion[k] = v
			}
			ok, unknown, score := matchChain(criterion, q)
			if unknown {
				r.unsupported("Filter-chain selection requires missing connection attributes.", fc.Path)
				return r, nil
			}
			if !ok {
				continue
			}
			if score[stage] > bestScore {
				next = nil
				bestScore = score[stage]
			}
			if score[stage] == bestScore {
				next = append(next, fc)
			}
		}
		choices = next
		if len(choices) == 0 {
			break
		}
	}
	for _, fc := range choices {
		for k := range obj(get(fc.Value, "filter_chain_match")) {
			switch key(k) {
			case "destinationport", "prefixranges", "servernames", "transportprotocol", "applicationprotocols":
			default:
				r.unsupported("Filter-chain selection uses unsupported source or connection criteria.", fc.Path)
				return r, nil
			}
		}
	}
	if len(choices) == 0 {
		if def := obj(get(l.Value, "default_filter_chain")); len(def) > 0 {
			choices = append(choices, item{def, child(l.Path, l.Value, "default_filter_chain")})
		} else {
			r.add("FILTER_CHAIN_NOT_FOUND", "FAIL", "error", "No filter chain matches the supplied connection attributes.", l.Path, fmt.Sprintf("port=%d protocol=%s sni=%s", q.Port, q.Protocol, q.SNI), "Check listener port, SNI, transport protocol and ALPN.")
			r.blocked("The selected listener has no matching filter chain.")
			return r, nil
		}
	}
	if len(choices) > 1 {
		r.unknown("FILTER_CHAIN_AMBIGUOUS", "Multiple equally specific filter chains match.", l.Path)
		return r, nil
	}
	fc := choices[0]
	r.Path = append(r.Path, "filter_chain: "+name(fc.Value))
	r.add("FILTER_CHAIN_SELECTED", "PASS", "info", "Selected filter chain.", fc.Path, "Matched supplied connection attributes.", "")
	if get(fc.Value, "transport_socket") != nil {
		r.Limitations = append(r.Limitations, "Downstream TLS context is configured; this trace does not establish handshake success. Use inspect_tls and handshake evidence.")
	}
	for _, f := range entries(fc.Value, fc.Path, "filters") {
		cfg := obj(get(f.Value, "typed_config"))
		t := field(cfg, "@type")
		switch {
		case strings.HasSuffix(t, "HttpConnectionManager"):
			if q.Protocol != "HTTP" && q.Protocol != "HTTPS" {
				r.unsupported("Selected chain requires HTTP request attributes; supplied protocol is opaque TCP/TLS.", f.Path)
				return r, nil
			}
			if q.Protocol == "HTTPS" && get(fc.Value, "transport_socket") == nil {
				r.unknown("TLS_TERMINATION_UNKNOWN", "HTTPS was supplied but the selected chain has no downstream TLS context. Verify which proxy terminates TLS.", fc.Path)
				return r, nil
			}
			return traceHTTP(r, d, f, cfg, q)
		case strings.HasSuffix(t, "TcpProxy"):
			refs := forwardingRefs(cfg)
			return traceClusters(r, d, refs, f.Path)
		case strings.Contains(field(f.Value, "name"), "metadata_exchange"):
			continue
		default:
			r.unsupported("Network filter must be evaluated before continuing: "+field(f.Value, "name"), f.Path)
			return r, nil
		}
	}
	r.unsupported("No supported HTTP connection manager or TCP proxy filter found.", fc.Path)
	return r, nil
}

func matchChain(m Object, q Request) (bool, bool, [5]int) {
	s := [5]int{}
	unknown := false
	for k := range m {
		switch key(k) {
		case "destinationport", "prefixranges", "servernames", "transportprotocol", "applicationprotocols":
		default:
			unknown = true
		}
	}
	if p := num(get(m, "destination_port")); p != 0 {
		if p != q.Port {
			return false, false, s
		}
		s[0] = 1
	}
	if ranges := arr(get(m, "prefix_ranges")); len(ranges) > 0 {
		ip := net.ParseIP(q.DestinationIP)
		if ip == nil {
			unknown = true
		} else {
			max := -1
			for _, v := range ranges {
				o := obj(v)
				prefix := num(get(o, "prefix_len"))
				if wrapper := obj(get(o, "prefix_len")); len(wrapper) > 0 {
					prefix = num(get(wrapper, "value"))
				}
				_, cidr, err := net.ParseCIDR(fmt.Sprintf("%s/%d", field(o, "address_prefix"), prefix))
				if err != nil {
					unknown = true
					continue
				}
				if cidr.Contains(ip) && prefix > max {
					max = prefix
				}
			}
			if max < 0 {
				return false, false, s
			}
			s[1] = max + 1
		}
	}
	if names := arr(get(m, "server_names")); len(names) > 0 {
		best := -1
		for _, n := range names {
			score := domainScore(str(n), q.SNI)
			if score > best {
				best = score
			}
		}
		if best < 0 {
			return false, false, s
		}
		s[2] = best
	}
	if t := field(m, "transport_protocol"); t != "" {
		actual := "raw_buffer"
		if q.Protocol == "TLS" || q.Protocol == "HTTPS" {
			actual = "tls"
		}
		if t != actual {
			return false, false, s
		}
		s[3] = 1
	}
	if alpn := arr(get(m, "application_protocols")); len(alpn) > 0 {
		if q.ALPN == "" {
			unknown = true
		} else {
			matched := false
			for _, a := range alpn {
				if str(a) == q.ALPN {
					matched = true
				}
			}
			if !matched {
				return false, false, s
			}
			s[4] = 1
		}
	}
	return true, unknown, s
}

func domainScore(pattern, host string) int {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)
	if pattern == host && pattern != "" {
		return 300000 + len(pattern)
	}
	if pattern == "*" {
		return 0
	}
	if strings.HasPrefix(pattern, "*") && len(host) > len(pattern)-1 && strings.HasSuffix(host, pattern[1:]) {
		return 200000 + len(pattern)
	}
	if strings.HasSuffix(pattern, "*") && len(host) > len(pattern)-1 && strings.HasPrefix(host, pattern[:len(pattern)-1]) {
		return 100000 + len(pattern)
	}
	return -1
}

func traceHTTP(r Report, d dump, f item, cfg Object, q Request) (Report, error) {
	cfgPath := child(f.Path, f.Value, "typed_config")
	// Only canonical request paths are modelled. Do not guess how HCM normalizes
	// escaped slashes, dot segments, duplicate slashes or early header mutations.
	pathOnly := strings.SplitN(q.Path, "?", 2)[0]
	if strings.ContainsAny(pathOnly, "%\\") || strings.Contains(pathOnly, "//") || strings.Contains("/"+strings.Trim(pathOnly, "/")+"/", "/../") || strings.Contains("/"+strings.Trim(pathOnly, "/")+"/", "/./") || get(cfg, "early_header_mutation_extensions") != nil {
		r.unsupported("Request path/header normalization requires additional HCM processing; use an observed canonical path.", f.Path)
		return r, nil
	}
	if q.Host == "" {
		r.unknown("HTTP_HOST_REQUIRED", "Supply the exact HTTP Host/:authority, including a port if sent.", f.Path)
		return r, nil
	}
	for _, hf := range entries(cfg, cfgPath, "http_filters") {
		n := field(hf.Value, "name")
		switch n {
		case "envoy.filters.http.router", "envoy.filters.http.cors", "istio.stats", "envoy.filters.http.grpc_stats", "istio.metadata_exchange":
		case "envoy.filters.http.rbac", "envoy.filters.http.jwt_authn", "envoy.filters.http.ext_authz":
			r.unknown("AUTHORIZATION_NOT_EVALUATED", "Routing is evaluated, but this authorization filter may reject the request: "+n, hf.Path)
		default:
			r.unsupported("HTTP filter may change routing or reject the request: "+n, hf.Path)
			return r, nil
		}
	}
	rc := item{obj(get(cfg, "route_config")), child(cfgPath, cfg, "route_config")}
	if len(rc.Value) == 0 {
		n := field(obj(get(cfg, "rds")), "route_config_name")
		for _, v := range d.Routes {
			if name(v.Value) == n {
				rc = v
				break
			}
		}
		if len(rc.Value) == 0 {
			r.unknown("ROUTE_CONFIGURATION_UNAVAILABLE", "Referenced RDS configuration is absent or not collected: "+n, f.Path)
			return r, nil
		}
	}
	host := q.Host
	if truth(get(rc.Value, "ignore_port_in_host_matching")) {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		} else if strings.Count(host, ":") == 1 {
			host = strings.SplitN(host, ":", 2)[0]
		}
	}
	best := -1
	var vh item
	ties := 0
	for _, v := range entries(rc.Value, rc.Path, "virtual_hosts") {
		for _, domain := range arr(get(v.Value, "domains")) {
			rank := domainScore(str(domain), host)
			if rank > best {
				best = rank
				vh = v
				ties = 1
			} else if rank >= 0 && rank == best && v.Path != vh.Path {
				ties++
			}
		}
	}
	if best < 0 {
		r.add("HTTP_VIRTUAL_HOST_NOT_FOUND", "FAIL", "error", "No virtual host matches Host/:authority.", rc.Path, host, "Check VirtualService hosts and Gateway host bindings.")
		r.blocked("No virtual host matches the HTTP request.")
		return r, nil
	}
	if ties > 1 {
		r.unknown("VIRTUAL_HOST_AMBIGUOUS", "Multiple equally specific virtual hosts match.", rc.Path)
		return r, nil
	}
	r.Path = append(r.Path, "virtual_host: "+name(vh.Value))
	if get(vh.Value, "matcher") != nil {
		r.unsupported("Generic HTTP matcher trees are not evaluated in v0.1.", vh.Path)
		return r, nil
	}
	for _, rt := range entries(vh.Value, vh.Path, "routes") {
		matched, unknown := matchRoute(obj(get(rt.Value, "match")), q)
		if unknown {
			r.unsupported("Route has unsupported matching conditions; a later route cannot safely be selected.", rt.Path)
			return r, nil
		}
		if !matched {
			continue
		}
		r.Path = append(r.Path, "route: "+name(rt.Value))
		r.add("HTTP_ROUTE_SELECTED", "PASS", "info", "First matching HTTP route selected.", rt.Path, q.Method+" "+q.Path, "")
		if a := obj(get(rt.Value, "direct_response")); len(a) > 0 {
			r.Verdict = "local_response"
			r.Summary = fmt.Sprintf("Envoy is configured to return HTTP %d locally.", num(get(a, "status")))
			return r, nil
		}
		if get(rt.Value, "redirect") != nil {
			r.Verdict = "redirect"
			r.Summary = "The selected route redirects the client; it does not forward this request upstream."
			return r, nil
		}
		if get(rt.Value, "typed_per_filter_config") != nil {
			r.Limitations = append(r.Limitations, "Per-route filter configuration is not evaluated.")
		}
		return traceClusters(r, d, forwardingRefs(rt.Value), rt.Path)
	}
	r.add("HTTP_ROUTE_NOT_FOUND", "FAIL", "error", "No HTTP route matches the supplied request.", vh.Path, q.Method+" "+q.Path, "Check path, method, headers and route order.")
	r.blocked("No HTTP route matches the request.")
	return r, nil
}

func forwardingRefs(o Object) []string {
	a := o
	if route := obj(get(o, "route")); len(route) > 0 {
		a = route
	}
	if c := field(a, "cluster"); c != "" {
		return []string{c}
	}
	w := obj(get(a, "weighted_clusters"))
	if get(w, "runtime_key_prefix") != nil {
		return nil
	}
	refs := []string{}
	for _, v := range arr(get(w, "clusters")) {
		c := obj(v)
		weight := get(c, "weight")
		if wrapper := obj(weight); len(wrapper) > 0 {
			weight = get(wrapper, "value")
		}
		if weight != nil && num(weight) == 0 {
			continue
		}
		if n := name(c); n != "" {
			refs = append(refs, n)
		}
	}
	return refs
}

func matchRoute(m Object, q Request) (bool, bool) {
	unknown := false
	for k := range m {
		switch key(k) {
		case "prefix", "path", "saferegex", "pathseparatedprefix", "casesensitive", "headers":
		default:
			unknown = true
		}
	}
	path := strings.SplitN(q.Path, "?", 2)[0]
	sensitive := true
	if v := get(m, "case_sensitive"); v != nil {
		sensitive = truth(v)
		if o := obj(v); len(o) > 0 {
			sensitive = truth(get(o, "value"))
		}
	}
	compare := func(s string) string {
		if !sensitive {
			return strings.ToLower(s)
		}
		return s
	}
	matched := false
	switch {
	case get(m, "prefix") != nil:
		matched = strings.HasPrefix(compare(path), compare(field(m, "prefix")))
	case get(m, "path") != nil:
		matched = compare(path) == compare(field(m, "path"))
	case get(m, "path_separated_prefix") != nil:
		p := compare(field(m, "path_separated_prefix"))
		v := compare(path)
		matched = v == p || strings.HasPrefix(v, p+"/")
	case get(m, "safe_regex") != nil:
		re, err := regexp.Compile("^(?:" + field(obj(get(m, "safe_regex")), "regex") + ")$")
		if err != nil {
			return false, true
		}
		matched = re.MatchString(path)
	default:
		return false, true
	}
	if !matched {
		return false, false
	}
	for _, v := range arr(get(m, "headers")) {
		h := obj(v)
		n := strings.ToLower(name(h))
		value := ""
		exists := false
		switch n {
		case ":method":
			value = q.Method
			exists = true
		case ":authority", "host":
			value = q.Host
			exists = q.Host != ""
		case ":path":
			value = q.Path
			exists = true
		default:
			for k, v := range q.Headers {
				if strings.ToLower(k) == n {
					value = v
					exists = true
				}
			}
		}
		for k := range h {
			switch key(k) {
			case "name", "exactmatch", "prefixmatch", "suffixmatch", "presentmatch", "invertmatch", "saferegexmatch", "stringmatch":
			default:
				return false, true
			}
		}
		var ok bool
		switch {
		case get(h, "present_match") != nil:
			ok = exists == truth(get(h, "present_match"))
		case get(h, "exact_match") != nil:
			ok = exists && value == field(h, "exact_match")
		case get(h, "prefix_match") != nil:
			ok = exists && strings.HasPrefix(value, field(h, "prefix_match"))
		case get(h, "suffix_match") != nil:
			ok = exists && strings.HasSuffix(value, field(h, "suffix_match"))
		case get(h, "safe_regex_match") != nil:
			re, err := regexp.Compile("^(?:" + field(obj(get(h, "safe_regex_match")), "regex") + ")$")
			if err != nil {
				return false, true
			}
			ok = exists && re.MatchString(value)
		case get(h, "string_match") != nil:
			s := obj(get(h, "string_match"))
			if get(s, "exact") == nil || len(s) > 2 {
				return false, true
			}
			expected := field(s, "exact")
			if truth(get(s, "ignore_case")) {
				ok = exists && strings.EqualFold(value, expected)
			} else {
				ok = exists && value == expected
			}
		default:
			return false, true
		}
		if truth(get(h, "invert_match")) {
			ok = !ok
		}
		if !ok {
			return false, false
		}
	}
	return true, unknown
}

func traceClusters(r Report, d dump, refs []string, p string) (Report, error) {
	if len(refs) == 0 {
		r.unsupported("Cluster selection uses an unsupported dynamic action or no forwarding cluster.", p)
		return r, nil
	}
	issues := false
	missing := false
	for _, ref := range refs {
		var selected *item
		for _, c := range d.Clusters {
			if name(c.Value) == ref {
				v := c
				selected = &v
				break
			}
		}
		if selected == nil {
			if !d.Sections["clusters"] {
				missing = true
				r.unknown("CLUSTERS_NOT_COLLECTED", "Cluster section is missing; cannot establish whether "+ref+" exists.", p)
				continue
			}
			issues = true
			r.add("CLUSTER_NOT_FOUND", "FAIL", "error", "Selected cluster is absent from the active snapshot.", p, ref, "Check destination host/port/subset and xDS delivery.")
			continue
		}
		r.Path = append(r.Path, "cluster candidate: "+ref)
		r.add("CLUSTER_PRESENT", "PASS", "info", "Selected cluster exists.", selected.Path, ref, "")
		if ref == "BlackHoleCluster" {
			issues = true
			r.add("BLACKHOLE_CLUSTER", "FAIL", "error", "Traffic selects Istio's BlackHoleCluster.", selected.Path, ref, "Check service discovery, ServiceEntry visibility and outbound traffic policy.")
		}
		endpointCheck(&r, d, *selected)
		if get(selected.Value, "transport_socket") != nil || get(selected.Value, "transport_socket_matches") != nil {
			r.Limitations = append(r.Limitations, "Upstream transport/TLS selection must be checked against endpoint metadata and peer handshake evidence.")
		}
	}
	for _, c := range r.Checks {
		if c.Code == "NO_ENDPOINTS" {
			issues = true
		}
	}
	if issues {
		r.Verdict = "configuration_issues"
		r.Summary = "At least one selected forwarding branch has a configuration problem; inspect evidence and branch weights."
	} else if !missing {
		r.Verdict = "configuration_path_found"
		r.Summary = "A configuration path was resolved. This does not prove authorization, TLS handshake, endpoint health, or network reachability."
	}
	return r, nil
}
