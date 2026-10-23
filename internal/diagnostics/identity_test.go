package diagnostics

import (
	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
	"testing"
)

func TestSelectedServiceIncludesBothProxySides(t *testing.T) {
	s := serviceSnapshot()
	s.Request.Peer = &core.PeerQuery{Kind: "host", Value: "backend.shop.svc.cluster.local", Port: 80, Protocol: "http"}
	s.Pods[0].Object["status"] = obj(`{"podIP":"10.0.0.1"}`)
	s.Pods[0].Object["metadata"] = obj(`{"creationTimestamp":"2026-10-21T00:00:00Z"}`)
	s.Pods[0].LogsCurrent = []byte(jsonLog("2026-10-22T10:02:00Z", "outbound|80||backend.shop.svc.cluster.local", "503", "UF"))
	s.Pods = append(s.Pods, core.PodSnapshot{Role: "destination", Ref: core.WorkloadRef{Namespace: "shop", Kind: "Pod", Name: "backend-1", UID: "backend-uid"}, Object: obj(`{"metadata":{"labels":{"app":"backend"},"creationTimestamp":"2026-10-21T00:00:00Z"},"status":{"podIP":"10.0.0.2"}}`), LogsCurrent: []byte(jsonLog("2026-10-22T10:02:00Z", "inbound|8080||", "503", "UF"))})
	endpointList(s, `{"metadata":{"labels":{"kubernetes.io/service-name":"backend"}},"ports":[{"name":"http","port":8080}],"endpoints":[{"addresses":["10.0.0.2"],"targetRef":{"uid":"backend-uid"}}]}`)
	selected := core.Connection{ID: "selected", Source: core.WorkloadIdentity(s.Request.Workload), Destination: "backend.shop.svc.cluster.local", Port: 80, Protocol: "http"}
	a := Analyze(s, &selected)
	if len(a.Connections) != 1 || a.Connections[0].ObservationCount != 2 {
		t.Fatalf("lost a proxy side: %+v", a.Connections)
	}
}
