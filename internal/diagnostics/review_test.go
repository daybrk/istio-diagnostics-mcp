package diagnostics

import (
	"encoding/json"
	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
	"testing"
)

func TestReviewMalformedClusterList(t *testing.T) {
	s := baseSnapshot()
	s.Pods[0].Envoy["config_dump"] = json.RawMessage(`{"configs":[{"@type":"type.googleapis.com/envoy.admin.v3.ClustersConfigDump","dynamic_active_clusters":{}},{"@type":"type.googleapis.com/envoy.admin.v3.ListenersConfigDump","static_listeners":[{"listener":{"name":"outbound","address":{"socket_address":{"address":"0.0.0.0","port_value":80}},"filter_chains":[{"filters":[{"name":"envoy.filters.network.tcp_proxy","typed_config":{"cluster":"outbound|80||backend.shop.svc.cluster.local"}}]}]}}]}]}`)
	a := Analyze(s, &core.Connection{Destination: "backend.shop.svc.cluster.local", Port: 80})
	t.Logf("cluster findings=%+v", findings(a, "CLUSTER_REFERENCE"))
	if hasStatus(a, "CLUSTER_REFERENCE", "FAIL") {
		t.Error("malformed cluster list falsely establishes cluster absence")
	}
}
func TestReviewTLSBackendPortSelection(t *testing.T) {
	s := baseSnapshot()
	s.Request.Peer = &core.PeerQuery{Kind: "service", Namespace: "shop", Value: "backend", Port: 80}
	s.Pods[0].Envoy["config_dump"] = json.RawMessage(`{"configs":[{"@type":"type.googleapis.com/envoy.admin.v3.ClustersConfigDump","dynamic_active_clusters":[{"cluster":{"name":"outbound|80||backend.shop.svc.cluster.local","transport_socket":{"name":"envoy.transport_sockets.tls"}}}]}]}`)
	s.Pods = append(s.Pods, core.PodSnapshot{Ref: core.WorkloadRef{Namespace: "shop", Name: "backend-1", UID: "backend-uid"}, Role: "destination", Envoy: map[string]json.RawMessage{"config_dump": json.RawMessage(`{"configs":[{"@type":"type.googleapis.com/envoy.admin.v3.ListenersConfigDump","static_listeners":[{"listener":{"name":"unrelated-80","address":{"socket_address":{"address":"0.0.0.0","port_value":80}},"filter_chains":[{}]}},{"listener":{"name":"actual-backend-8080","address":{"socket_address":{"address":"0.0.0.0","port_value":8080}},"filter_chains":[{"transport_socket":{"name":"envoy.transport_sockets.tls"}}]}}]}]}`)}})
	s.Resources = []core.Resource{{Kind: "Service", Namespace: "shop", Name: "backend", Object: obj(`{"spec":{"ports":[{"port":80,"targetPort":8080}]}}`)}}
	a := Analyze(s, &core.Connection{Destination: "backend.shop.svc.cluster.local", Port: 80})
	t.Logf("tls findings=%+v", findings(a, "TLS_MODE_COMPATIBILITY"))
	if hasStatus(a, "TLS_MODE_COMPATIBILITY", "FAIL") {
		t.Error("unrelated service-port listener is asserted to be selected backend TLS context")
	}
}
