package diagnostics

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
)

func TestRouteShadowingSupportedSubset(t *testing.T) {
	for _, tt := range []struct{ name, first, second, want string }{{"shadow", `{"prefix":"/"}`, `{"path":"/items"}`, "FAIL"}, {"disjoint", `{"prefix":"/a"}`, `{"prefix":"/b"}`, "PASS"}, {"extension", `{"safe_regex":{"regex":".*"}}`, `{"path":"/items"}`, "UNSUPPORTED"}} {
		t.Run(tt.name, func(t *testing.T) {
			s := serviceSnapshot()
			dump := routeDump(tt.first)
			dump = strings.Replace(dump, `"routes":[{"name":"route1"`, `"routes":[{"name":"earlier","match":`+tt.first+`,"route":{"cluster":"outbound|80||backend.shop.svc.cluster.local"}},{"name":"route1"`, 1)
			dump = strings.Replace(dump, `"name":"route1","match":`+tt.first, `"name":"route1","match":`+tt.second, 1)
			putDump(s, dump)
			requireStatus(t, Analyze(s, nil), "ROUTE_SHADOWING", tt.want)
		})
	}
}
func TestRecognizedDiagnosticMechanisms(t *testing.T) {
	cases := []struct{ rule, msg string }{{"SDS_DELIVERY", "SDS secret default failed to fetch: connection refused"}, {"JWT_VALIDATION", "Jwks remote fetch is failed for jwt provider"}, {"DNS_CONTEXT", "DNS resolution failed for backend.shop.svc.cluster.local"}}
	for _, tt := range cases {
		t.Run(tt.rule, func(t *testing.T) {
			s := serviceSnapshot()
			s.Pods[0].LogsCurrent = []byte("2026-10-22T10:02:00Z 2026-10-22T10:02:00Z\twarn\t" + tt.msg)
			a := Analyze(s, nil)
			requireStatus(t, a, tt.rule, "FAIL")
			for _, f := range findings(a, tt.rule) {
				if f.Confidence == "confirmed" {
					t.Fatal("diagnostic cannot prove deep cause")
				}
			}
		})
	}
}
func TestSDSActiveReferenceMissingAndPresent(t *testing.T) {
	for _, tt := range []struct{ name, secrets, want string }{{"missing", "[]", "FAIL"}, {"active", `[{"name":"default","secret":{"name":"default"}}]`, "PASS"}} {
		t.Run(tt.name, func(t *testing.T) {
			s := serviceSnapshot()
			putDump(s, `{"configs":[{"@type":"type.googleapis.com/envoy.admin.v3.ClustersConfigDump","static_clusters":[{"cluster":{"name":"outbound|80||backend.shop.svc.cluster.local","transport_socket":{"name":"envoy.transport_sockets.tls","typed_config":{"common_tls_context":{"tls_certificate_sds_secret_configs":[{"name":"default"}]}}}}}]},{"@type":"type.googleapis.com/envoy.admin.v3.SecretsConfigDump","dynamic_active_secrets":`+tt.secrets+`}]}`)
			requireStatus(t, Analyze(s, nil), "SDS_DELIVERY", tt.want)
		})
	}
}
func TestNetworkPolicyStaticIsolationRequiresCompleteScope(t *testing.T) {
	for _, tt := range []struct {
		name, ingress, want string
		complete            bool
	}{{"deny", "[]", "FAIL", true}, {"allow all", "[{}]", "PASS", true}, {"partial deny", "[]", "UNKNOWN", false}, {"unsupported", `[{"from":[{"podSelector":{"matchExpressions":[{"key":"app","operator":"Exists"}]}}]}]`, "UNSUPPORTED", true}} {
		t.Run(tt.name, func(t *testing.T) {
			s := baseSnapshot()
			s.Request.Direction = "inbound"
			s.Pods[0].Role = "destination"
			addResource(s, "NetworkPolicy", "policy", `{"spec":{"podSelector":{},"policyTypes":["Ingress"],"ingress":`+tt.ingress+`}}`)
			if tt.complete {
				addResource(s, "NetworkPolicyList", "", `{"items":[]}`)
			}
			a := Analyze(s, nil)
			requireStatus(t, a, "NETWORK_POLICY_SCOPE", tt.want)
			for _, f := range findings(a, "NETWORK_POLICY_SCOPE") {
				if f.Confidence == "confirmed" {
					t.Fatal("static policy is not runtime cause")
				}
			}
		})
	}
}
func TestDenyHTTPAttributesAppliesToTCP(t *testing.T) {
	s := baseSnapshot()
	s.Request.Direction = "inbound"
	s.Pods[0].Role = "destination"
	s.Pods[0].LogsCurrent = []byte(`2026-10-22T10:03:00Z [2026-10-22T10:03:00.000Z] "- - -" 0 UAEX - - "-" 0 0 5 - "-" "-" "-" "-" "127.0.0.1:8080" inbound|8080|| 127.0.0.1:3333 10.0.0.1:8080 10.0.0.2:4444 - -`)
	addResource(s, "AuthorizationPolicy", "deny-http", `{"apiVersion":"security.istio.io/v1","spec":{"action":"DENY","rules":[{"to":[{"operation":{"methods":["GET"]}}]}]}}`)
	requireStatus(t, Analyze(s, nil), "ISTIO_AUTHORIZATION", "FAIL")
}
func TestCustomAuthorizationExplicitBoundary(t *testing.T) {
	s := baseSnapshot()
	addResource(s, "AuthorizationPolicy", "custom", `{"apiVersion":"security.istio.io/v1","spec":{"action":"CUSTOM","provider":{"name":"external"},"rules":[{}]}}`)
	requireStatus(t, Analyze(s, nil), "ISTIO_AUTHORIZATION", "UNSUPPORTED")
}
func TestReplicaConfigDifferenceAndMissingReplica(t *testing.T) {
	for _, tt := range []struct{ name, dump, want string }{{"different", strings.Replace(clusterDump(""), `"name":"outbound|80||backend.shop.svc.cluster.local"`, `"name":"outbound|80||backend.shop.svc.cluster.local","connect_timeout":"2s"`, 1), "FAIL"}, {"same", clusterDump(""), "PASS"}, {"missing", "", "UNKNOWN"}} {
		t.Run(tt.name, func(t *testing.T) {
			s := serviceSnapshot()
			putDump(s, clusterDump(""))
			p := s.Pods[0]
			p.Ref.UID = "pod-2"
			p.Ref.Name = "frontend-2"
			p.Envoy = map[string]json.RawMessage{}
			if tt.dump != "" {
				p.Envoy["config_dump"] = json.RawMessage(tt.dump)
			}
			s.Pods = append(s.Pods, p)
			requireStatus(t, Analyze(s, nil), "REPLICA_DIVERGENCE", tt.want)
		})
	}
}
func TestTLSModesRequireBothSelectedContexts(t *testing.T) {
	for _, tt := range []struct{ name, socket, want string }{{"mismatch", "", "FAIL"}, {"same", `,"transport_socket":{"name":"envoy.transport_sockets.tls","typed_config":{}}`, "PASS"}} {
		t.Run(tt.name, func(t *testing.T) {
			s := serviceSnapshot()
			putDump(s, strings.Replace(clusterDump(""), `"name":"outbound|80||backend.shop.svc.cluster.local"`, `"name":"outbound|80||backend.shop.svc.cluster.local","transport_socket":{"name":"envoy.transport_sockets.tls","typed_config":{}}`, 1))
			s.Pods = append(s.Pods, core.PodSnapshot{Ref: core.WorkloadRef{Namespace: "shop", Name: "backend", UID: "pod-2"}, Role: "destination", Object: obj(`{"metadata":{"labels":{"app":"backend"}},"status":{"podIP":"10.0.0.2"}}`), Envoy: map[string]json.RawMessage{"config_dump": json.RawMessage(`{"configs":[{"@type":"type.googleapis.com/envoy.admin.v3.ListenersConfigDump","static_listeners":[{"listener":{"name":"inbound","address":{"socket_address":{"address":"0.0.0.0","port_value":8080}},"filter_chains":[{"filters":[{"name":"envoy.filters.network.http_connection_manager","typed_config":{}}]` + tt.socket + `}]}}]}]}`)}})
			endpointList(s, `{"metadata":{"labels":{"kubernetes.io/service-name":"backend"}},"ports":[{"name":"http","port":8080}],"endpoints":[{"addresses":["10.0.0.2"],"targetRef":{"uid":"pod-2"},"conditions":{"ready":true}}]}`)
			requireStatus(t, Analyze(s, nil), "TLS_MODE_COMPATIBILITY", tt.want)
		})
	}
}
func TestMalformedAndFutureIdentity(t *testing.T) {
	s := baseSnapshot()
	s.Request.Direction = "inbound"
	s.Pods[0].Role = "destination"
	s.Pods[0].Object["status"].(map[string]any)["podIP"] = "10.0.0.9"
	s.Pods[0].LogsCurrent = []byte(jsonLog("2026-10-22T10:02:00Z", "inbound|8080||", "503", "UF"))
	s.Pods = append(s.Pods, core.PodSnapshot{Role: "source", Ref: core.WorkloadRef{Namespace: "shop", Kind: "Pod", Name: "new-pod", UID: "new-uid"}, Object: obj(`{"metadata":{"creationTimestamp":"2026-10-22T10:04:00Z"},"status":{"podIP":"10.0.0.1"}}`)})
	a := Analyze(s, nil)
	if len(a.Connections) != 1 || strings.Contains(a.Connections[0].Source, "new-pod") {
		t.Fatalf("historical IP mapped to new pod: %+v", a.Connections)
	}
	putDump(s, `{"configs":"wrong"}`)
	requireStatus(t, Analyze(s, nil), "ROUTE_SELECTION", "UNSUPPORTED")
}
