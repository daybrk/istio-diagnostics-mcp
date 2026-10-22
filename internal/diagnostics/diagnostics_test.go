package diagnostics

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func fixture() Object {
	var d Object
	_ = json.Unmarshal([]byte(`{"configs":[
	{"@type":"type.googleapis.com/envoy.admin.v3.ListenersConfigDump","dynamic_listeners":[{"name":"http","active_state":{"listener":{"name":"http","traffic_direction":"OUTBOUND","address":{"socket_address":{"address":"0.0.0.0","port_value":8080}},"filter_chains":[{"filters":[{"name":"envoy.filters.network.http_connection_manager","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager","rds":{"route_config_name":"8080"},"http_filters":[{"name":"envoy.filters.http.router"}]}}]}]}}}]},
	{"@type":"type.googleapis.com/envoy.admin.v3.RoutesConfigDump","dynamic_route_configs":[{"route_config":{"name":"8080","virtual_hosts":[{"name":"api","domains":["api.example.com"],"routes":[{"name":"default","match":{"prefix":"/"},"route":{"cluster":"api"}}]}]}}]},
	{"@type":"type.googleapis.com/envoy.admin.v3.ClustersConfigDump","dynamic_active_clusters":[{"cluster":{"name":"api","type":"EDS","eds_cluster_config":{"service_name":"api"}}}]},
	{"@type":"type.googleapis.com/envoy.admin.v3.EndpointsConfigDump","dynamic_endpoint_configs":[{"endpoint_config":{"cluster_name":"api","endpoints":[{"lb_endpoints":[{"endpoint":{"address":{"socket_address":{"address":"10.0.0.2","port_value":8080}}},"health_status":"HEALTHY"}]}]}}]}
	]}`), &d)
	return d
}
func request() Request {
	return Request{Direction: "outbound", Port: 8080, Protocol: "HTTP", Host: "api.example.com", Path: "/health", Method: "GET"}
}
func section(d Object, i int) Object { return obj(arr(d["configs"])[i]) }
func listener(d Object) Object {
	return obj(get(obj(get(obj(arr(get(section(d, 0), "dynamic_listeners"))[0]), "active_state")), "listener"))
}
func virtualHost(d Object) Object {
	return obj(arr(get(obj(get(obj(arr(get(section(d, 1), "dynamic_route_configs"))[0]), "route_config")), "virtual_hosts"))[0])
}
func route(d Object) Object { return obj(arr(get(virtualHost(d), "routes"))[0]) }
func has(r Report, code string) bool {
	for _, c := range r.Checks {
		if c.Code == code {
			return true
		}
	}
	return false
}
func mustTrace(t *testing.T, d Object, q Request) Report {
	t.Helper()
	r, e := Trace(d, q, now)
	if e != nil {
		t.Fatal(e)
	}
	return r
}

func TestTraceHappyPath(t *testing.T) {
	r := mustTrace(t, fixture(), request())
	if r.Verdict != "configuration_path_found" || !has(r, "ENDPOINTS_PRESENT") {
		t.Fatalf("%+v", r)
	}
}
func TestTraceMissingHostAndRoute(t *testing.T) {
	for _, tc := range []struct{ host, path, code string }{{"wrong.example.com", "/", "HTTP_VIRTUAL_HOST_NOT_FOUND"}, {"api.example.com", "/other", "HTTP_ROUTE_NOT_FOUND"}} {
		t.Run(tc.code, func(t *testing.T) {
			d := fixture()
			route(d)["match"] = Object{"path": "/health"}
			q := request()
			q.Host = tc.host
			q.Path = tc.path
			r := mustTrace(t, d, q)
			if !has(r, tc.code) || r.Verdict != "configuration_blocked" {
				t.Fatalf("%+v", r)
			}
		})
	}
}
func TestIncompleteDumpIsNotMissingCluster(t *testing.T) {
	d := fixture()
	d["configs"] = arr(d["configs"])[:2]
	r := mustTrace(t, d, request())
	if !has(r, "CLUSTERS_NOT_COLLECTED") || has(r, "CLUSTER_NOT_FOUND") || r.Verdict != "undetermined" {
		t.Fatalf("%+v", r)
	}
}
func TestMissingCluster(t *testing.T) {
	d := fixture()
	section(d, 2)["dynamic_active_clusters"] = []any{}
	r := mustTrace(t, d, request())
	if !has(r, "CLUSTER_NOT_FOUND") || r.Verdict != "configuration_issues" {
		t.Fatalf("%+v", r)
	}
}

func TestZeroWeightMissingClusterDoesNotBreakRequest(t *testing.T) {
	d := fixture()
	route(d)["route"] = Object{"weighted_clusters": Object{"clusters": []any{Object{"name": "api", "weight": 100}, Object{"name": "missing", "weight": 0}}}}
	r := mustTrace(t, d, request())
	if has(r, "CLUSTER_NOT_FOUND") || r.Verdict != "configuration_path_found" {
		t.Fatalf("%+v", r)
	}
}

func TestInboundVirtualListener(t *testing.T) {
	d := fixture()
	l := listener(d)
	l["traffic_direction"] = "INBOUND"
	obj(get(obj(get(l, "address")), "socket_address"))["port_value"] = 15006
	fc := obj(arr(get(l, "filter_chains"))[0])
	fc["filter_chain_match"] = Object{"destination_port": 8080}
	q := request()
	q.Direction = "inbound"
	r := mustTrace(t, d, q)
	if !has(r, "CLUSTER_PRESENT") {
		t.Fatalf("%+v", r)
	}
}

func TestNoncanonicalPathIsUnsupported(t *testing.T) {
	d := fixture()
	q := request()
	q.Path = "/a/../health"
	r := mustTrace(t, d, q)
	if !has(r, "UNSUPPORTED_CONFIGURATION") {
		t.Fatal(r)
	}
}

func TestExactVirtualHostBeatsWildcard(t *testing.T) {
	d := fixture()
	rc := obj(get(obj(arr(get(section(d, 1), "dynamic_route_configs"))[0]), "route_config"))
	rc["virtual_hosts"] = append(arr(rc["virtual_hosts"]), Object{"name": "wildcard", "domains": []any{"*"}, "routes": []any{Object{"match": Object{"prefix": "/"}, "route": Object{"cluster": "missing"}}}})
	r := mustTrace(t, d, request())
	if has(r, "CLUSTER_NOT_FOUND") || !has(r, "CLUSTER_PRESENT") {
		t.Fatal(r)
	}
}
func TestMissingEDSIsUnknownButExplicitEmptyIsFailure(t *testing.T) {
	d := fixture()
	d["configs"] = arr(d["configs"])[:3]
	r := mustTrace(t, d, request())
	if !has(r, "ENDPOINTS_UNKNOWN") || has(r, "NO_ENDPOINTS") {
		t.Fatalf("%+v", r)
	}
	d = fixture()
	ec := obj(get(obj(arr(get(section(d, 3), "dynamic_endpoint_configs"))[0]), "endpoint_config"))
	ec["endpoints"] = []any{}
	r = mustTrace(t, d, request())
	if !has(r, "NO_ENDPOINTS") {
		t.Fatalf("%+v", r)
	}
}
func TestUnknownEarlierRouteStopsTrace(t *testing.T) {
	d := fixture()
	v := virtualHost(d)
	v["routes"] = []any{Object{"match": Object{"prefix": "/", "query_parameters": []any{Object{"name": "x"}}}, "route": Object{"cluster": "missing"}}, route(d)}
	r := mustTrace(t, d, request())
	if !has(r, "UNSUPPORTED_CONFIGURATION") || has(r, "CLUSTER_PRESENT") {
		t.Fatalf("%+v", r)
	}
}
func TestAuditRouteShadowingAndXDSRejection(t *testing.T) {
	d := fixture()
	v := virtualHost(d)
	v["routes"] = append(arr(v["routes"]), Object{"match": Object{"path": "/health"}, "route": Object{"cluster": "api"}})
	dl := obj(arr(section(d, 0)["dynamic_listeners"])[0])
	dl["error_state"] = Object{"details": "duplicate match"}
	r, e := Analyze(d, now)
	if e != nil || !has(r, "ROUTE_SHADOWED") || !has(r, "XDS_UPDATE_REJECTED") {
		t.Fatalf("%+v %v", r, e)
	}
	if r.Verdict != "undetermined" {
		t.Fatal("an audit must not claim a request cause")
	}
}
func TestSamePortDifferentAddressesIsNotConflict(t *testing.T) {
	d := fixture()
	l := listener(d)
	other := Object{"listener": Object{"name": "other", "address": Object{"socket_address": Object{"address": "10.0.0.3", "port_value": 8080}}, "filter_chains": get(l, "filter_chains")}}
	section(d, 0)["static_listeners"] = []any{other}
	r, e := Analyze(d, now)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range r.Checks {
		if strings.Contains(c.Code, "PORT_CONFLICT") {
			t.Fatal(c)
		}
	}
}
func TestFilterChainsDoNotFallBackAfterSNIPriority(t *testing.T) {
	d := fixture()
	l := listener(d)
	filters := get(obj(arr(get(l, "filter_chains"))[0]), "filters")
	l["filter_chains"] = []any{Object{"filter_chain_match": Object{"server_names": []any{"api.example.com"}, "application_protocols": []any{"h2"}}, "filters": filters}, Object{"filter_chain_match": Object{"server_names": []any{"*.example.com"}}, "filters": filters}}
	q := request()
	q.Protocol = "HTTPS"
	q.SNI = "api.example.com"
	q.ALPN = "http/1.1"
	r := mustTrace(t, d, q)
	if !has(r, "FILTER_CHAIN_NOT_FOUND") {
		t.Fatalf("less-specific chain must not win: %+v", r)
	}
}
func TestMissingALPNIsUnknown(t *testing.T) {
	d := fixture()
	fc := obj(arr(get(listener(d), "filter_chains"))[0])
	fc["filter_chain_match"] = Object{"application_protocols": []any{"h2"}}
	r := mustTrace(t, d, request())
	if !has(r, "UNSUPPORTED_CONFIGURATION") {
		t.Fatalf("%+v", r)
	}
}
func TestTCPWithoutRDS(t *testing.T) {
	d := fixture()
	fc := obj(arr(get(listener(d), "filter_chains"))[0])
	fc["filters"] = []any{Object{"name": "envoy.filters.network.tcp_proxy", "typed_config": Object{"@type": "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy", "cluster": "api"}}}
	q := request()
	q.Protocol = "TCP"
	q.Host = ""
	r := mustTrace(t, d, q)
	if !has(r, "CLUSTER_PRESENT") {
		t.Fatalf("%+v", r)
	}
}
func TestDirectResponseDoesNotRequireCluster(t *testing.T) {
	d := fixture()
	rt := route(d)
	delete(rt, "route")
	rt["direct_response"] = Object{"status": 503}
	r := mustTrace(t, d, request())
	if r.Verdict != "local_response" || has(r, "CLUSTER_PRESENT") {
		t.Fatalf("%+v", r)
	}
}
func TestMatcherAndFiltersUnsupported(t *testing.T) {
	d := fixture()
	virtualHost(d)["matcher"] = Object{}
	r := mustTrace(t, d, request())
	if !has(r, "UNSUPPORTED_CONFIGURATION") {
		t.Fatalf("%+v", r)
	}
}
func TestHeaderMatching(t *testing.T) {
	d := fixture()
	route(d)["match"] = Object{"prefix": "/", "headers": []any{Object{"name": "x-tenant", "string_match": Object{"exact": "billing"}}}}
	q := request()
	q.Headers = map[string]string{"X-Tenant": "billing"}
	r := mustTrace(t, d, q)
	if !has(r, "CLUSTER_PRESENT") {
		t.Fatalf("%+v", r)
	}
	q.Headers = nil
	r = mustTrace(t, d, q)
	if !has(r, "HTTP_ROUTE_NOT_FOUND") {
		t.Fatalf("%+v", r)
	}
}
func camel(v any) any {
	switch x := v.(type) {
	case map[string]any:
		o := Object{}
		for k, v := range x {
			parts := strings.Split(k, "_")
			for i := 1; i < len(parts); i++ {
				parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
			}
			o[strings.Join(parts, "")] = camel(v)
		}
		return o
	case []any:
		a := []any{}
		for _, v := range x {
			a = append(a, camel(v))
		}
		return a
	}
	return v
}
func TestCamelCaseDump(t *testing.T) {
	r := mustTrace(t, camel(fixture()).(map[string]any), request())
	if !has(r, "ENDPOINTS_PRESENT") {
		t.Fatalf("%+v", r)
	}
}
func TestInvalidDumpAndRequest(t *testing.T) {
	if _, e := Analyze(Object{}, now); e == nil {
		t.Fatal("expected invalid dump")
	}
	q := request()
	q.Port = 0
	if _, e := Trace(fixture(), q, now); e == nil {
		t.Fatal("expected invalid port")
	}
}

func certificate(t *testing.T, start, end time.Time) string {
	t.Helper()
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "test.example"}, DNSNames: []string{"test.example"}, NotBefore: start, NotAfter: end}
	der, e := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if e != nil {
		t.Fatal(e)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
func secrets(source Object) Object {
	return Object{"configs": []any{Object{"@type": "type.googleapis.com/envoy.admin.v3.SecretsConfigDump", "dynamic_active_secrets": []any{Object{"name": "default", "secret": Object{"name": "default", "tls_certificate": Object{"certificate_chain": source}}}}}}}
}
func TestCertificateValidity(t *testing.T) {
	for _, tc := range []struct {
		name       string
		start, end time.Time
		code       string
	}{{"expired", now.Add(-time.Hour), now, "CERTIFICATE_EXPIRED"}, {"future", now.Add(time.Hour), now.Add(24 * time.Hour), "CERTIFICATE_NOT_YET_VALID"}, {"valid", now.Add(-time.Hour), now.Add(30 * 24 * time.Hour), "CERTIFICATE_TIME_VALID"}} {
		t.Run(tc.name, func(t *testing.T) {
			data := base64.StdEncoding.EncodeToString([]byte(certificate(t, tc.start, tc.end)))
			r, e := InspectTLS(secrets(Object{"inline_bytes": data}), now)
			if e != nil || !has(r, tc.code) {
				t.Fatalf("%+v %v", r, e)
			}
			if r.Verdict != "undetermined" {
				t.Fatal("unused cert is not a confirmed request cause")
			}
		})
	}
}
func TestCertificateFileAndRedaction(t *testing.T) {
	r, e := InspectTLS(secrets(Object{"filename": "/etc/passwd"}), now)
	if e != nil || !has(r, "CERTIFICATE_BYTES_UNAVAILABLE") {
		t.Fatalf("%+v %v", r, e)
	}
	d := Object{"privateKey": Object{"inlineBytes": "SECRET"}, "certificateChain": "PUBLIC", "token": "TOKEN"}
	b, _ := json.Marshal(Redact(d))
	if strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "TOKEN") || !strings.Contains(string(b), "PUBLIC") {
		t.Fatal(string(b))
	}
}
func TestInvalidCertificateBytes(t *testing.T) {
	r, e := InspectTLS(secrets(Object{"inline_bytes": "%%"}), now)
	if e != nil || !has(r, "CERTIFICATE_PARSE_ERROR") {
		t.Fatalf("%+v %v", r, e)
	}
}

func FuzzAnalyze(f *testing.F) {
	b, _ := json.Marshal(fixture())
	f.Add(b)
	f.Add([]byte(`{"configs":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		var o Object
		if json.Unmarshal(b, &o) != nil {
			return
		}
		_, _ = Analyze(o, now)
		_, _ = Trace(o, request(), now)
	})
}
