package diagnostics

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"
)

type configNode struct {
	value map[string]any
	path  string
}
type proxyConfig struct {
	pod                                                   int
	clusters, listeners, routes, secrets, warming, errors []configNode
	hasClusters, hasListeners, hasRoutes, hasSecrets      bool
	unsupported                                           bool
}

func field(v map[string]any, snake string) any {
	if x, ok := v[snake]; ok {
		return x
	}
	parts := strings.Split(snake, "_")
	for i := 1; i < len(parts); i++ {
		if parts[i] != "" {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return v[strings.Join(parts, "")]
}
func fieldName(v map[string]any, snake string) string {
	if _, ok := v[snake]; ok {
		return snake
	}
	parts := strings.Split(snake, "_")
	for i := 1; i < len(parts); i++ {
		if parts[i] != "" {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}
func child(n configNode, key string) configNode {
	return configNode{m(field(n.value, key)), n.path + "/" + fieldName(n.value, key)}
}
func children(n configNode, key string) []configNode {
	out := []configNode{}
	for i, v := range list(field(n.value, key)) {
		out = append(out, configNode{m(v), fmt.Sprintf("%s/%s/%d", n.path, fieldName(n.value, key), i)})
	}
	return out
}
func parseConfig(raw json.RawMessage, pod int) (proxyConfig, error) {
	d := proxyConfig{pod: pod}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return d, err
	}
	configs, ok := root["configs"].([]any)
	if !ok {
		return d, fmt.Errorf("config dump lacks configs array")
	}
	for i, v := range configs {
		n := configNode{m(v), fmt.Sprintf("/configs/%d", i)}
		typ := str(n.value["@type"])
		if !strings.HasPrefix(typ, "type.googleapis.com/envoy.admin.v3.") {
			d.unsupported = true
			continue
		}
		if err := validateConfigSection(n); err != nil {
			return d, err
		}
		switch {
		case strings.HasSuffix(typ, "ClustersConfigDump"):
			d.hasClusters = true
			for _, key := range []string{"dynamic_active_clusters", "static_clusters"} {
				for _, x := range children(n, key) {
					d.clusters = append(d.clusters, child(x, "cluster"))
				}
			}
			d.warming = append(d.warming, children(n, "dynamic_warming_clusters")...)
		case strings.HasSuffix(typ, "ListenersConfigDump"):
			d.hasListeners = true
			for _, x := range children(n, "static_listeners") {
				d.listeners = append(d.listeners, child(x, "listener"))
			}
			for _, x := range children(n, "dynamic_listeners") {
				if field(x.value, "active_state") != nil {
					d.listeners = append(d.listeners, child(child(x, "active_state"), "listener"))
				}
				if field(x.value, "warming_state") != nil {
					d.warming = append(d.warming, child(x, "warming_state"))
				}
				if field(x.value, "error_state") != nil {
					d.errors = append(d.errors, child(x, "error_state"))
				}
			}
		case strings.HasSuffix(typ, "RoutesConfigDump"):
			d.hasRoutes = true
			for _, key := range []string{"dynamic_route_configs", "static_route_configs"} {
				for _, x := range children(n, key) {
					d.routes = append(d.routes, child(x, "route_config"))
				}
			}
		case strings.HasSuffix(typ, "SecretsConfigDump"):
			d.hasSecrets = true
			d.secrets = append(d.secrets, children(n, "dynamic_active_secrets")...)
			d.secrets = append(d.secrets, children(n, "static_secrets")...)
			d.warming = append(d.warming, children(n, "dynamic_warming_secrets")...)
		case strings.HasSuffix(typ, "BootstrapConfigDump"), strings.HasSuffix(typ, "EndpointsConfigDump"), strings.HasSuffix(typ, "ScopedRoutesConfigDump"): // recognized but not a path evaluator input
		default:
			d.unsupported = true
		}
	}
	return d, nil
}

// Omitted protobuf repeated fields mean empty. Present values of the wrong
// shape must never establish that an active object or secret is absent.
func validateConfigSection(n configNode) error {
	arrays := map[string]string{
		"dynamic_active_clusters": "cluster", "static_clusters": "cluster", "dynamic_warming_clusters": "cluster",
		"static_listeners": "listener", "dynamic_listeners": "",
		"dynamic_route_configs": "route_config", "static_route_configs": "route_config",
		"dynamic_active_secrets": "", "static_secrets": "", "dynamic_warming_secrets": "",
	}
	for key, wrapped := range arrays {
		value, present := n.value[fieldName(n.value, key)]
		if !present {
			continue
		}
		items, ok := value.([]any)
		if !ok {
			return fmt.Errorf("%s/%s must be an array", n.path, key)
		}
		for i, item := range items {
			entry, ok := item.(map[string]any)
			if !ok {
				return fmt.Errorf("%s/%s/%d must be an object", n.path, key, i)
			}
			named := entry
			if wrapped != "" {
				named = m(field(entry, wrapped))
			}
			if name, ok := named["name"].(string); !ok || name == "" {
				return fmt.Errorf("%s/%s/%d lacks object identity", n.path, key, i)
			}
			if key == "dynamic_listeners" {
				for _, state := range []string{"active_state", "warming_state", "draining_state"} {
					if v, exists := entry[fieldName(entry, state)]; exists {
						listener := m(field(m(v), "listener"))
						if name, ok := listener["name"].(string); !ok || name == "" {
							return fmt.Errorf("%s/%s/%d has malformed %s", n.path, key, i, state)
						}
					}
				}
			}
		}
	}
	var walk func(map[string]any) error
	walk = func(object map[string]any) error {
		for _, key := range []string{"filter_chains", "filters", "virtual_hosts", "routes", "transport_socket_matches", "tls_certificate_sds_secret_configs"} {
			if value, exists := object[fieldName(object, key)]; exists {
				items, ok := value.([]any)
				if !ok {
					return fmt.Errorf("%s: %s must be an array", n.path, key)
				}
				for _, item := range items {
					if m(item) == nil {
						return fmt.Errorf("%s: %s contains a malformed object", n.path, key)
					}
				}
			}
		}
		for _, key := range []string{"secret", "transport_socket", "error_state", "filter_chain_match", "default_filter_chain", "socket_address"} {
			if value, exists := object[fieldName(object, key)]; exists && m(value) == nil {
				return fmt.Errorf("%s: %s must be an object", n.path, key)
			}
		}
		for _, value := range object {
			if child := m(value); child != nil {
				if err := walk(child); err != nil {
					return err
				}
			}
			for _, item := range list(value) {
				if child := m(item); child != nil {
					if err := walk(child); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	return walk(n.value)
}
func (a *analyzer) envoyEvidence(d proxyConfig, n configNode) string {
	p := &a.s.Pods[d.pod]
	return a.evidence(p, "envoy", fmt.Sprintf("pod/%s/%s?uid=%s/envoy/config_dump#%s", p.Ref.Namespace, p.Ref.Name, p.Ref.UID, n.path), "", n.value)
}
func (a *analyzer) envoy() {
	for i := range a.s.Pods {
		p := &a.s.Pods[i]
		raw := p.Envoy["config_dump"]
		if len(raw) == 0 {
			continue
		}
		d, err := parseConfig(raw, i)
		if err != nil {
			a.limit(fmt.Sprintf("Unsupported config_dump on pod %s: %s", p.Ref.Name, err))
			a.add("ROUTE_SELECTION", "UNSUPPORTED", "unknown", "Envoy config_dump is malformed or uses an unsupported envelope.", nil, []string{p.Ref.UID}, []string{"Envoy admin v3 config dump"})
			continue
		}
		if d.unsupported {
			a.limit("Unrecognized Envoy config sections were not interpreted; extension semantics remain unsupported.")
		}
		a.configs = append(a.configs, d)
		a.xds(d)
		a.references(d)
		a.routing(d)
		a.tls(d)
	}
}
func (a *analyzer) xds(d proxyConfig) {
	pods := []string{a.s.Pods[d.pod].Ref.UID}
	ids := []string{}
	for _, n := range d.errors {
		id := a.envoyEvidence(d, n)
		ids = append(ids, id)
		a.add("XDS_APPLY_STATE", "FAIL", "unknown", "Envoy reports a rejected update; existing active configuration remains independently evaluated.", []string{id}, pods, nil)
		details := strings.ToLower(str(field(n.value, "details")))
		if containsAny(details, "duplicate listener", "duplicate address", "overlapping filter chain", "multiple filter chains with overlapping matching rules") {
			a.add("LISTENER_CONFLICT", "FAIL", "probable", "Envoy explicitly rejected a listener/filter-chain overlap; rejection does not prove the selected active path stopped serving.", []string{id}, pods, []string{"Selected-path and rejection-time correlation"})
		}
	}
	for _, n := range d.warming {
		id := a.envoyEvidence(d, n)
		ids = append(ids, id)
		a.add("XDS_APPLY_STATE", "UNKNOWN", "unknown", "A configuration object is warming; active configuration may still serve traffic.", []string{id}, pods, []string{"Completion of warming and selected active path"})
	}
	if len(d.errors) == 0 && len(d.warming) == 0 && (d.hasClusters || d.hasListeners) {
		a.add("XDS_APPLY_STATE", "PASS", "unknown", "No rejected or warming objects are reported in the available supported config sections; this does not prove control-plane synchronization across omitted sections.", nil, pods, nil)
	}
	if len(findingsFor(a.out.Findings, "LISTENER_CONFLICT")) == 0 && d.hasListeners {
		a.add("LISTENER_CONFLICT", "UNKNOWN", "unknown", "No explicit rejected listener overlap was collected; equal numeric ports alone are not conflicts.", nil, pods, []string{"Complete rejected-listener state and conflict mechanism"})
	}
}
func clusterRefs(n configNode) []configNode {
	out := []configNode{}
	if name := str(n.value["cluster"]); name != "" {
		out = append(out, configNode{map[string]any{"cluster": name}, n.path + "/cluster"})
	}
	for _, c := range children(child(n, "weighted_clusters"), "clusters") {
		if name := str(c.value["name"]); name != "" {
			out = append(out, configNode{map[string]any{"cluster": name}, c.path + "/name"})
		}
	}
	return out
}
func (a *analyzer) applicableListeners(d proxyConfig) []configNode {
	_, port := a.target()
	out := []configNode{}
	for _, n := range d.listeners {
		bind := number(field(m(field(m(field(n.value, "address")), "socket_address")), "port_value"))
		if port == 0 || bind == port || bind == 15001 || bind == 15006 {
			out = append(out, n)
		}
	}
	return out
}
func filters(listener configNode) []configNode {
	out := []configNode{}
	for _, fc := range children(listener, "filter_chains") {
		out = append(out, children(fc, "filters")...)
	}
	out = append(out, children(child(listener, "default_filter_chain"), "filters")...)
	return out
}
func (a *analyzer) references(d proxyConfig) {
	if !d.hasClusters {
		return
	}
	active := map[string]configNode{}
	for _, n := range d.clusters {
		active[str(n.value["name"])] = n
	}
	refs := []configNode{}
	for _, l := range a.applicableListeners(d) {
		for _, f := range filters(l) {
			cfg := child(f, "typed_config")
			if str(f.value["name"]) == "envoy.filters.network.tcp_proxy" {
				refs = append(refs, clusterRefs(cfg)...)
			} else if str(f.value["name"]) == "envoy.filters.network.http_connection_manager" {
				for _, r := range a.hcmRoutes(d, cfg) {
					for _, v := range children(r, "virtual_hosts") {
						for _, route := range children(v, "routes") {
							refs = append(refs, clusterRefs(child(route, "route"))...)
						}
					}
				}
			}
		}
	}
	for _, ref := range refs {
		name := str(ref.value["cluster"])
		id := a.envoyEvidence(d, ref)
		status, summary := "PASS", fmt.Sprintf("Active route/TCP proxy reference %q resolves to an active cluster in the current dump.", name)
		ids := []string{id}
		if n, ok := active[name]; ok {
			ids = append(ids, a.envoyEvidence(d, n))
		} else {
			status = "FAIL"
			summary = fmt.Sprintf("Active route/TCP proxy references cluster %q, absent from the collected active cluster section; a rejected or warming cluster is not a replacement.", name)
		}
		a.add("CLUSTER_REFERENCE", status, "unknown", summary, ids, []string{a.s.Pods[d.pod].Ref.UID}, nil)
	}
}
func (a *analyzer) hcmRoutes(d proxyConfig, hcm configNode) []configNode {
	if field(hcm.value, "route_config") != nil {
		return []configNode{child(hcm, "route_config")}
	}
	name := str(field(m(field(hcm.value, "rds")), "route_config_name"))
	out := []configNode{}
	for _, r := range d.routes {
		if str(r.value["name"]) == name {
			out = append(out, r)
		}
	}
	return out
}
func (a *analyzer) selectedClusters(d proxyConfig) []configNode {
	host, port := a.target()
	out := []configNode{}
	for _, n := range d.clusters {
		name := str(n.value["name"])
		h, p, ok := clusterDestination(name)
		if ok && h == host && (port == 0 || p == port) {
			out = append(out, n)
			continue
		}
		for _, e := range a.relevantEvents() {
			if e.pod == d.pod && e.cluster == name {
				out = append(out, n)
				break
			}
		}
	}
	return out
}
func (a *analyzer) tls(d proxyConfig) {
	p := &a.s.Pods[d.pod]
	clusters := a.selectedClusters(d)
	refs := map[string]configNode{}
	for _, n := range clusters {
		socket := child(n, "transport_socket")
		if len(list(field(n.value, "transport_socket_matches"))) > 0 {
			a.add("TLS_MODE_COMPATIBILITY", "UNKNOWN", "unknown", "Cluster uses transport socket matches; endpoint metadata is required to select the effective TLS context.", []string{a.envoyEvidence(d, n)}, []string{p.Ref.UID}, []string{"Selected endpoint transport socket metadata"})
			continue
		}
		ctx := child(child(socket, "typed_config"), "common_tls_context")
		for _, r := range children(ctx, "tls_certificate_sds_secret_configs") {
			refs[str(r.value["name"])] = r
		}
	}
	if len(refs) == 0 {
		return
	}
	var certs map[string]any
	if json.Unmarshal(p.Envoy["certs"], &certs) != nil {
		return
	}
	now, err := time.Parse(time.RFC3339Nano, p.CollectedAt)
	if err != nil {
		now, err = time.Parse(time.RFC3339Nano, a.s.CollectedAt)
	}
	if err != nil {
		return
	}
	names := make([]string, 0, len(refs))
	for name := range refs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ref := refs[name]
		serials := secretSerials(d, name)
		found := false
		for i, v := range list(certs["certificates"]) {
			cert := m(v)
			for j, cv := range list(field(cert, "cert_chain")) {
				c := m(cv)
				if str(cert["name"]) != name && !serials[normalizeSerial(str(field(c, "serial_number")))] {
					continue
				}
				expires, e1 := time.Parse(time.RFC3339Nano, str(field(c, "expiration_time")))
				starts, e2 := time.Parse(time.RFC3339Nano, str(field(c, "valid_from")))
				if e1 != nil || e2 != nil {
					continue
				}
				found = true
				id := a.evidence(p, "envoy", fmt.Sprintf("pod/%s/%s?uid=%s/envoy/certs#/certificates/%d/%s/%d", p.Ref.Namespace, p.Ref.Name, p.Ref.UID, i, fieldName(cert, "cert_chain"), j), "", c)
				status, summary := "PASS", "The certificate metadata associated by secret name or active-secret serial with the selected TLS context is time-valid at collection; historical handshake validity is not established."
				if !now.Before(expires) || now.Before(starts) {
					status = "FAIL"
					summary = "The certificate associated by secret name or active-secret serial with the selected TLS context is expired or not-yet-valid at collection; this alone does not prove a historical handshake failure or termination of existing connections."
				}
				a.add("TLS_VALIDITY", status, "unknown", summary, []string{id, a.envoyEvidence(d, ref)}, []string{p.Ref.UID}, []string{"Certificate serial and TLS context at the observed handshake time"})
			}
		}
		if !found {
			a.add("TLS_VALIDITY", "UNKNOWN", "unknown", "Certificate validity cannot be associated with the selected TLS secret by available certificate metadata; unrelated expired certificates are not causes.", []string{a.envoyEvidence(d, ref)}, []string{p.Ref.UID}, []string{"Certificate metadata tied to selected secret " + name})
		}
	}
}
func normalizeSerial(s string) string {
	return strings.TrimLeft(strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(s, "0x"), ":", "")), "0")
}
func secretSerials(d proxyConfig, name string) map[string]bool {
	out := map[string]bool{}
	for _, n := range d.secrets {
		secret := child(n, "secret")
		if str(n.value["name"]) != name && str(secret.value["name"]) != name {
			continue
		}
		chain := child(child(secret, "tls_certificate"), "certificate_chain")
		data := []byte(str(field(chain.value, "inline_string")))
		if len(data) == 0 {
			data, _ = base64.StdEncoding.DecodeString(str(field(chain.value, "inline_bytes")))
		}
		for len(data) > 0 {
			block, rest := pem.Decode(data)
			if block == nil {
				break
			}
			data = rest
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				out[normalizeSerial(cert.SerialNumber.Text(16))] = true
			}
		}
	}
	return out
}
