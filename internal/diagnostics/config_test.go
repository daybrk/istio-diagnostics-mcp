package diagnostics

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
)

func addResource(s *core.Snapshot, kind, name, raw string) {
	s.Resources = append(s.Resources, core.Resource{Kind: kind, Name: name, Namespace: "shop", UID: kind + "-" + name, CollectedAt: s.CollectedAt, Object: obj(raw)})
}
func serviceSnapshot() *core.Snapshot {
	s := baseSnapshot()
	s.Request.Peer = &core.PeerQuery{Kind: "service", Namespace: "shop", Value: "backend", Port: 80}
	addResource(s, "Service", "backend", `{"metadata":{"name":"backend","namespace":"shop"},"spec":{"selector":{"app":"backend"},"ports":[{"name":"http","port":80,"targetPort":8080}]}}`)
	return s
}
func endpointList(s *core.Snapshot, raw string) {
	addResource(s, "EndpointSliceList", "", `{"items":[]}`)
	if raw != "" {
		addResource(s, "EndpointSlice", "backend-a", raw)
	}
}
func TestServiceEndpointsCompleteness(t *testing.T) {
	for _, tt := range []struct {
		name, raw, want string
		complete        bool
	}{{"missing", "", "UNKNOWN", false}, {"empty", "", "FAIL", true}, {"ready", `{"metadata":{"labels":{"kubernetes.io/service-name":"backend"}},"ports":[{"name":"http","port":8080}],"endpoints":[{"addresses":["10.0.0.2"],"conditions":{"ready":true}}]}`, "PASS", true}, {"unready", `{"metadata":{"labels":{"kubernetes.io/service-name":"backend"}},"endpoints":[{"addresses":["10.0.0.2"],"conditions":{"ready":false}}]}`, "FAIL", true}} {
		t.Run(tt.name, func(t *testing.T) {
			s := serviceSnapshot()
			if tt.complete {
				endpointList(s, tt.raw)
			}
			a := Analyze(s, nil)
			requireStatus(t, a, "SERVICE_ENDPOINTS", tt.want)
			for _, f := range findings(a, "SERVICE_ENDPOINTS") {
				if f.Confidence == "confirmed" {
					t.Fatal("current endpoints cannot prove historical cause")
				}
			}
		})
	}
}
func TestNamedTargetPort(t *testing.T) {
	for _, tt := range []struct {
		name, ports, want string
		pod               bool
	}{{"wrong name", `[{"name":"web","containerPort":8080}]`, "FAIL", true}, {"right name", `[{"name":"http","containerPort":8080}]`, "PASS", true}, {"missing pods", "[]", "UNKNOWN", false}} {
		t.Run(tt.name, func(t *testing.T) {
			s := serviceSnapshot()
			s.Resources[0].Object["spec"].(map[string]any)["ports"] = []any{obj(`{"name":"http","port":80,"targetPort":"http"}`)}
			endpointList(s, `{"metadata":{"labels":{"kubernetes.io/service-name":"backend"}},"ports":[{"name":"http","port":8080}],"endpoints":[{"addresses":["10.0.0.2"],"conditions":{"ready":true}}]}`)
			if tt.pod {
				s.Pods = append(s.Pods, core.PodSnapshot{Role: "destination", Ref: core.WorkloadRef{Namespace: "shop", Kind: "Pod", Name: "backend-1", UID: "pod-2"}, Object: obj(`{"metadata":{"labels":{"app":"backend"}},"spec":{"containers":[{"name":"app","ports":` + tt.ports + `}]},"status":{"podIP":"10.0.0.2"}}`)})
			}
			requireStatus(t, Analyze(s, nil), "SERVICE_PORT_MAPPING", tt.want)
		})
	}
}
func putDump(s *core.Snapshot, body string) { s.Pods[0].Envoy["config_dump"] = json.RawMessage(body) }
func clusterDump(extra string) string {
	return `{"configs":[{"@type":"type.googleapis.com/envoy.admin.v3.ClustersConfigDump","dynamic_active_clusters":[{"version_info":"c1","cluster":{"name":"outbound|80||backend.shop.svc.cluster.local"}}]}` + extra + `]}`
}
func TestClusterReferencesAndRejectedState(t *testing.T) {
	for _, tt := range []struct{ name, target, want string }{{"missing", "absent", "FAIL"}, {"present", "outbound|80||backend.shop.svc.cluster.local", "PASS"}} {
		t.Run(tt.name, func(t *testing.T) {
			s := serviceSnapshot()
			putDump(s, clusterDump(`,{"@type":"type.googleapis.com/envoy.admin.v3.ListenersConfigDump","dynamic_listeners":[{"name":"listener","active_state":{"listener":{"name":"listener","address":{"socket_address":{"address":"0.0.0.0","port_value":80}},"filter_chains":[{"filters":[{"name":"envoy.filters.network.tcp_proxy","typed_config":{"cluster":"`+tt.target+`"}}]}]}},"error_state":{"details":"duplicate listener rejected"}}]}`))
			a := Analyze(s, nil)
			requireStatus(t, a, "CLUSTER_REFERENCE", tt.want)
			requireStatus(t, a, "XDS_APPLY_STATE", "FAIL")
			for _, f := range findings(a, "XDS_APPLY_STATE") {
				if f.Confidence == "confirmed" || strings.Contains(f.Summary, "not serving") {
					t.Fatal("rejection replaced active state")
				}
			}
		})
	}
}
func routeDump(match string) string {
	return clusterDump(`,{"@type":"type.googleapis.com/envoy.admin.v3.ListenersConfigDump","static_listeners":[{"listener":{"name":"http","address":{"socket_address":{"address":"0.0.0.0","port_value":80}},"filter_chains":[{"filters":[{"name":"envoy.filters.network.http_connection_manager","typed_config":{"rds":{"route_config_name":"routes"}}}]}]}}]},{"@type":"type.googleapis.com/envoy.admin.v3.RoutesConfigDump","dynamic_route_configs":[{"route_config":{"name":"routes","virtual_hosts":[{"name":"backend","domains":["backend.shop.svc.cluster.local"],"routes":[{"name":"route1","match":` + match + `,"route":{"cluster":"outbound|80||backend.shop.svc.cluster.local"}}]}]}}]}`)
}
func TestRouteMatchersConservatively(t *testing.T) {
	for _, tt := range []struct{ name, match, want string }{{"match", `{"prefix":"/"}`, "PASS"}, {"miss", `{"path":"/other"}`, "FAIL"}, {"custom", `{"path_separated_prefix":"/items"}`, "UNSUPPORTED"}, {"missing header", `{"prefix":"/","headers":[{"name":"x-tenant","exact_match":"blue"}]}`, "UNKNOWN"}} {
		t.Run(tt.name, func(t *testing.T) {
			s := serviceSnapshot()
			s.Pods[0].LogsCurrent = []byte(jsonLog("2026-10-22T10:02:00Z", "outbound|80||backend.shop.svc.cluster.local", "503", "UF"))
			putDump(s, routeDump(tt.match))
			requireStatus(t, Analyze(s, nil), "ROUTE_SELECTION", tt.want)
		})
	}
}
func TestSamePortNotListenerConflict(t *testing.T) {
	s := serviceSnapshot()
	putDump(s, `{"configs":[{"@type":"type.googleapis.com/envoy.admin.v3.ListenersConfigDump","static_listeners":[{"listener":{"name":"a","address":{"socket_address":{"address":"10.0.0.1","port_value":80}}}},{"listener":{"name":"b","address":{"socket_address":{"address":"10.0.0.2","port_value":80}}}}]}]}`)
	a := Analyze(s, nil)
	if hasStatus(a, "LISTENER_CONFLICT", "FAIL") {
		t.Fatal("same port alone isn't conflict")
	}
}
func TestTLSUnusedExpiredCertificateNotSelectedCause(t *testing.T) {
	s := serviceSnapshot()
	putDump(s, clusterDump(""))
	s.Pods[0].Envoy["certs"] = json.RawMessage(`{"certificates":[{"cert_chain":[{"serial_number":"old","expiration_time":"2020-01-01T00:00:00Z","valid_from":"2019-01-01T00:00:00Z"}]}]}`)
	a := Analyze(s, nil)
	if hasStatus(a, "TLS_VALIDITY", "FAIL") {
		t.Fatal("unassociated expired cert became failure")
	}
	requireStatus(t, a, "TLS_VALIDITY", "UNKNOWN")
}
func TestTLSSelectedSDSCertificateValidity(t *testing.T) {
	for _, tt := range []struct{ name, expiry, want string }{{"expired", "2025-01-01T00:00:00Z", "FAIL"}, {"valid", "2027-01-01T00:00:00Z", "PASS"}} {
		t.Run(tt.name, func(t *testing.T) {
			s := serviceSnapshot()
			putDump(s, `{"configs":[{"@type":"type.googleapis.com/envoy.admin.v3.ClustersConfigDump","dynamic_active_clusters":[{"cluster":{"name":"outbound|80||backend.shop.svc.cluster.local","transport_socket":{"name":"envoy.transport_sockets.tls","typed_config":{"common_tls_context":{"tls_certificate_sds_secret_configs":[{"name":"default"}]}}}}}]},{"@type":"type.googleapis.com/envoy.admin.v3.SecretsConfigDump","dynamic_active_secrets":[{"name":"default","secret":{"name":"default","tls_certificate":{"certificate_chain":{"inline_string":"[redacted]"}}}}]}]}`)
			s.Pods[0].Envoy["certs"] = json.RawMessage(`{"certificates":[{"name":"default","cert_chain":[{"serial_number":"one","expiration_time":"` + tt.expiry + `","valid_from":"2025-01-01T00:00:00Z"}]}]}`)
			a := Analyze(s, nil)
			requireStatus(t, a, "TLS_VALIDITY", tt.want)
			for _, f := range findings(a, "TLS_VALIDITY") {
				if f.Confidence == "confirmed" {
					t.Fatal("current certificate not historical handshake proof")
				}
			}
		})
	}
}
