package diagnostics

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

func Analyze(raw Object, at time.Time) (Report, error) {
	d, err := parse(raw)
	r := newReport(at)
	if err != nil {
		return r, err
	}
	r.Summary = "Static audit of the supplied snapshot; findings are not automatically causes of a particular failed request."
	walk(raw, "", func(o Object, p string) {
		if e := obj(get(o, "error_state")); len(e) > 0 {
			r.add("XDS_UPDATE_REJECTED", "FAIL", "warning", "A configuration update was rejected; inspect the active version.", child(p, o, "error_state"), field(e, "details"), "Correct the rejected resource and verify a subsequent successful update.")
		}
		if a := get(o, "warming_state"); a != nil {
			r.add("RESOURCE_WARMING", "UNKNOWN", "warning", "Listener is warming; duration and dependency state are not known.", child(p, o, "warming_state"), "Warming is not by itself a persistent fault.", "Compare snapshots and check RDS/SDS dependencies.")
		}
		if a := arr(get(o, "dynamic_warming_clusters")); len(a) > 0 {
			r.unknown("CLUSTERS_WARMING", "Clusters are warming; inspect dependency delivery and elapsed time.", child(p, o, "dynamic_warming_clusters"))
		}
	})
	clusters := map[string]bool{}
	for _, c := range d.Clusters {
		clusters[name(c.Value)] = true
	}
	for _, collection := range [][]item{d.Listeners, d.Routes} {
		for _, x := range collection {
			walk(x.Value, x.Path, func(o Object, p string) {
				for _, ref := range clusterRefs(o) {
					if clusters[ref] {
						continue
					}
					if d.Sections["clusters"] {
						r.add("CLUSTER_REFERENCE_MISSING", "FAIL", "error", "Referenced cluster is absent from the active snapshot.", p, ref, "Check generated routes, destination ports/subsets and xDS delivery.")
					} else {
						r.unknown("CLUSTERS_NOT_COLLECTED", "Cannot verify cluster reference: "+ref, p)
					}
				}
			})
		}
	}
	for _, l := range d.Listeners {
		seen := map[string]string{}
		for _, fc := range entries(l.Value, l.Path, "filter_chains") {
			match := obj(get(fc.Value, "filter_chain_match"))
			b, _ := json.Marshal(match)
			k := string(b)
			if prev, ok := seen[k]; ok && get(l.Value, "filter_chain_matcher") == nil {
				r.add("DUPLICATE_FILTER_CHAIN_MATCH", "FAIL", "error", "Two filter chains have identical match conditions.", fc.Path, "Also present at "+prev, "Check Gateway/EnvoyFilter sources and rejected LDS updates.")
			}
			seen[k] = fc.Path
		}
	}
	for _, route := range d.Routes {
		domains := map[string]string{}
		for _, vh := range entries(route.Value, route.Path, "virtual_hosts") {
			for _, domain := range arr(get(vh.Value, "domains")) {
				k := strings.ToLower(str(domain))
				if prev, ok := domains[k]; ok {
					r.add("DUPLICATE_VIRTUAL_HOST_DOMAIN", "FAIL", "error", "A domain appears more than once in one route configuration.", vh.Path, k+" also at "+prev, "Resolve the overlapping VirtualService/Gateway configuration.")
				}
				domains[k] = vh.Path
			}
			catchAll := false
			for _, rt := range entries(vh.Value, vh.Path, "routes") {
				if catchAll {
					r.add("ROUTE_SHADOWED", "FAIL", "warning", "A preceding unconditional route shadows this route.", rt.Path, "An earlier route matches every request path.", "Move specific routes before the catch-all route.")
				}
				m := obj(get(rt.Value, "match"))
				if len(m) == 1 && (field(m, "prefix") == "/" || field(m, "prefix") == "") && get(m, "prefix") != nil {
					catchAll = true
				}
			}
		}
	}
	tls := inspectTLS(d, at)
	r.Checks = append(r.Checks, tls.Checks...)
	r.Limitations = append(r.Limitations, tls.Limitations...)
	r.Limitations = append(r.Limitations, "Config dump cannot identify every discarded source resource, socket owner, network drop, or application failure.", "Identical port numbers across different services are not inherently a conflict.")
	sort.SliceStable(r.Checks, func(i, j int) bool {
		a, b := r.Checks[i], r.Checks[j]
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.Evidence[0].Path < b.Evidence[0].Path
	})
	return r, nil
}

// Only inspect route and TCP proxy actions, not similarly named metadata fields.
func clusterRefs(o Object) []string {
	out := []string{}
	if a := obj(get(o, "route")); len(a) > 0 {
		if c := field(a, "cluster"); c != "" {
			out = append(out, c)
		}
		for _, c := range arr(get(obj(get(a, "weighted_clusters")), "clusters")) {
			if n := name(obj(c)); n != "" {
				out = append(out, n)
			}
		}
	}
	if strings.HasSuffix(field(o, "@type"), "TcpProxy") {
		if c := field(o, "cluster"); c != "" {
			out = append(out, c)
		}
		for _, c := range arr(get(obj(get(o, "weighted_clusters")), "clusters")) {
			if n := name(obj(c)); n != "" {
				out = append(out, n)
			}
		}
	}
	return out
}

func endpointCheck(r *Report, d dump, c item) {
	t := field(c.Value, "type")
	assignment := obj(get(c.Value, "load_assignment"))
	path := child(c.Path, c.Value, "load_assignment")
	if t == "EDS" || get(c.Value, "eds_cluster_config") != nil {
		edName := field(obj(get(c.Value, "eds_cluster_config")), "service_name")
		if edName == "" {
			edName = name(c.Value)
		}
		assignment = nil
		for _, e := range d.Endpoints {
			if field(e.Value, "cluster_name") == edName {
				assignment = e.Value
				path = e.Path
				break
			}
		}
		if assignment == nil {
			r.unknown("ENDPOINTS_UNKNOWN", "No endpoint assignment available for "+edName+"; verify EDS completeness and runtime state.", c.Path)
			return
		}
	} else if t == "STRICT_DNS" || t == "LOGICAL_DNS" || t == "ORIGINAL_DST" || get(c.Value, "cluster_type") != nil {
		r.unknown("DYNAMIC_ENDPOINTS", "Endpoint reachability depends on runtime DNS/original destination or a custom cluster.", c.Path)
		return
	}
	if len(assignment) == 0 {
		r.unknown("ENDPOINTS_UNKNOWN", "No endpoint assignment supplied for "+name(c.Value), c.Path)
		return
	}
	total, eligible := 0, 0
	for _, loc := range arr(get(assignment, "endpoints")) {
		for _, ep := range arr(get(obj(loc), "lb_endpoints")) {
			total++
			h := field(obj(ep), "health_status")
			if h == "" || h == "UNKNOWN" || h == "HEALTHY" || h == "DEGRADED" {
				eligible++
			}
		}
	}
	if total == 0 {
		r.add("NO_ENDPOINTS", "FAIL", "error", "The selected cluster has an explicitly empty endpoint assignment.", path, name(c.Value), "Check Service selectors, readiness, subset labels and EndpointSlices.")
	} else if eligible == 0 {
		r.unknown("ENDPOINTS_UNHEALTHY", "All endpoints are marked unhealthy; runtime panic/failover settings can affect routing.", path)
	} else {
		r.add("ENDPOINTS_PRESENT", "PASS", "info", "Configured endpoint candidates exist; runtime health and reachability remain unverified.", path, fmt.Sprintf("%d/%d candidates", eligible, total), "")
	}
}
