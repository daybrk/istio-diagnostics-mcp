package diagnostics

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
)

func TestInvalidJSONStatusDoesNotParseAsHealthy(t *testing.T) {
	s := baseSnapshot()
	s.Pods[0].LogsCurrent = []byte(`2026-10-22T10:03:00Z {"response_code":"banana","response_flags":"-","protocol":"HTTP/2"}`)
	a := Analyze(s, nil)
	if !strings.Contains(strings.Join(a.Limitations, " "), "Unsupported") {
		t.Fatal("invalid status silently accepted")
	}
}
func TestInboundServicePeerIdentity(t *testing.T) {
	s := baseSnapshot()
	s.Request.Direction = "inbound"
	s.Request.Peer = &core.PeerQuery{Kind: "service", Namespace: "shop", Value: "caller"}
	s.Pods[0].Role = "destination"
	s.Pods[0].Object["status"].(map[string]any)["podIP"] = "10.0.0.9"
	s.Pods[0].LogsCurrent = []byte(jsonLog("2026-10-22T10:02:00Z", "inbound|8080||", "503", "UF"))
	addResource(s, "Service", "caller", `{"spec":{"selector":{"app":"caller"}}}`)
	s.Pods = append(s.Pods, core.PodSnapshot{Role: "source", Ref: core.WorkloadRef{Namespace: "shop", Name: "caller-1", UID: "pod-2", Kind: "Pod"}, Object: obj(`{"metadata":{"creationTimestamp":"2026-10-22T09:00:00Z","labels":{"app":"caller"}},"status":{"podIP":"10.0.0.1"}}`)})
	a := Analyze(s, nil)
	if len(a.Connections) != 1 || a.Connections[0].Source != "caller.shop.svc.cluster.local" {
		t.Fatalf("source service mapping lost: %+v", a.Connections)
	}
}
func TestBoundListenerAddressCannotBeIgnored(t *testing.T) {
	s := serviceSnapshot()
	s.Pods[0].LogsCurrent = []byte(jsonLog("2026-10-22T10:02:00Z", "outbound|80||backend.shop.svc.cluster.local", "503", "UF"))
	putDump(s, strings.Replace(routeDump(`{"prefix":"/"}`), `"address":"0.0.0.0"`, `"address":"10.9.9.9"`, 1))
	a := Analyze(s, nil)
	if hasStatus(a, "ROUTE_SELECTION", "PASS") {
		t.Fatal("selected concrete listener address without observed destination address")
	}
	requireStatus(t, a, "ROUTE_SELECTION", "UNKNOWN")
}
func TestNetworkPolicyUsesObservedBackendPort(t *testing.T) {
	s := serviceSnapshot()
	s.Pods[0].LogsCurrent = []byte(jsonLog("2026-10-22T10:02:00Z", "outbound|80||backend.shop.svc.cluster.local", "503", "UF"))
	addResource(s, "NetworkPolicy", "egress", `{"spec":{"podSelector":{},"policyTypes":["Egress"],"egress":[{"ports":[{"port":80}]}]}}`)
	addResource(s, "NetworkPolicyList", "", `{"items":[]}`)
	a := Analyze(s, nil)
	requireStatus(t, a, "NETWORK_POLICY_SCOPE", "FAIL")
	if hasStatus(a, "NETWORK_POLICY_SCOPE", "PASS") {
		t.Fatal("service port used instead of upstream target port")
	}
}
func TestCertificateSerialAssociatesRealAdminCerts(t *testing.T) {
	s := serviceSnapshot()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	start, _ := time.Parse(time.RFC3339, "2024-01-01T00:00:00Z")
	expiry, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	template := &x509.Certificate{SerialNumber: big.NewInt(42), NotBefore: start, NotAfter: expiry}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	quoted, _ := json.Marshal(cert)
	putDump(s, `{"configs":[{"@type":"type.googleapis.com/envoy.admin.v3.ClustersConfigDump","static_clusters":[{"cluster":{"name":"outbound|80||backend.shop.svc.cluster.local","transport_socket":{"name":"envoy.transport_sockets.tls","typed_config":{"common_tls_context":{"tls_certificate_sds_secret_configs":[{"name":"default"}]}}}}}]},{"@type":"type.googleapis.com/envoy.admin.v3.SecretsConfigDump","dynamic_active_secrets":[{"name":"default","secret":{"name":"default","tls_certificate":{"certificate_chain":{"inline_string":`+string(quoted)+`}}}}]}]}`)
	s.Pods[0].Envoy["certs"] = json.RawMessage(`{"certificates":[{"cert_chain":[{"serial_number":"2a","expiration_time":"2025-01-01T00:00:00Z","valid_from":"2024-01-01T00:00:00Z"}]}]}`)
	requireStatus(t, Analyze(s, nil), "TLS_VALIDITY", "FAIL")
}
func TestNoFalsePositiveForHealthyMechanisms(t *testing.T) {
	s := serviceSnapshot()
	s.Pods[0].LogsCurrent = []byte(`2026-10-22T10:02:00Z {"level":"info","msg":"SDS secret delivered; JWT validation succeeded; DNS resolution succeeded"}`)
	a := Analyze(s, nil)
	for _, r := range []string{"SDS_DELIVERY", "JWT_VALIDATION", "DNS_CONTEXT", "UPSTREAM_FAILURE"} {
		if hasStatus(a, r, "FAIL") {
			t.Fatalf("false failure %s", r)
		}
	}
}
func TestConnectionContractAndFractionalLastSeen(t *testing.T) {
	s := baseSnapshot()
	s.Pods[0].LogsCurrent = []byte(jsonLog("2026-10-22T10:02:00.1Z", "outbound|80||backend.shop.svc.cluster.local", "503", "UF") + "\n" + jsonLog("2026-10-22T10:02:00Z", "outbound|80||backend.shop.svc.cluster.local", "503", "UF"))
	a := Analyze(s, nil)
	if len(a.Connections) != 1 || a.Connections[0].Status != "queued" || a.Connections[0].LastSeen != "2026-10-22T10:02:00.1Z" {
		t.Fatalf("connection contract/window ordering: %+v", a.Connections)
	}
}
func TestNetworkPolicyDoesNotUseUnobservedAllowedReplica(t *testing.T) {
	s := serviceSnapshot()
	s.Pods[0].LogsCurrent = []byte(jsonLog("2026-10-22T10:02:00Z", "outbound|80||backend.shop.svc.cluster.local", "503", "UF"))
	addResource(s, "NetworkPolicy", "egress", `{"spec":{"podSelector":{},"policyTypes":["Egress"],"egress":[{"to":[{"podSelector":{"matchLabels":{"allow":"yes"}}}]}]}}`)
	addResource(s, "NetworkPolicyList", "", `{"items":[]}`)
	s.Pods = append(s.Pods, core.PodSnapshot{Ref: core.WorkloadRef{Namespace: "shop", Name: "unobserved", UID: "other"}, Role: "destination", Object: obj(`{"metadata":{"labels":{"allow":"yes"}},"status":{"podIP":"10.0.0.3"}}`)}, core.PodSnapshot{Ref: core.WorkloadRef{Namespace: "shop", Name: "observed", UID: "target"}, Role: "destination", Object: obj(`{"metadata":{"labels":{"allow":"no"}},"status":{"podIP":"10.0.0.2"}}`)})
	a := Analyze(s, nil)
	for _, f := range findings(a, "NETWORK_POLICY_SCOPE") {
		if includes(f.AffectedPodUIDs, "pod-1") && f.CheckStatus != "FAIL" {
			t.Fatalf("unobserved replica used: %+v", f)
		}
	}
}
