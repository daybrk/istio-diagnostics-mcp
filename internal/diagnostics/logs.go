package diagnostics

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
)

type accessEvent struct {
	pod                                                                                                                             int
	when                                                                                                                            time.Time
	protocol, method, path, authority, sni, cluster, upstream, downstream, local, flags, details, transport, grpc, requestID, route string
	code                                                                                                                            int
	hasCode                                                                                                                         bool
	evidence                                                                                                                        string
	connection                                                                                                                      core.Connection
}
type diagnosticEvent struct {
	pod               int
	when              time.Time
	message, evidence string
	errorLevel        bool
}

var textTokens = regexp.MustCompile(`"(?:\\.|[^"\\])*"|\[[^\]]*\]|\S+`)
var diagnosticLevel = regexp.MustCompile(`(?i)(?:^|[\s\[])((?:error)|(?:critical)|(?:fatal)|(?:warn(?:ing)?)|(?:info)|(?:debug)|(?:trace))(?:[\s\]:]|$)`)

func (a *analyzer) readLogs() {
	if !a.validWindow {
		return
	}
	for i := range a.s.Pods {
		p := &a.s.Pods[i]
		for _, stream := range []struct {
			name string
			data []byte
		}{{"current", p.LogsCurrent}, {"previous", p.LogsPrevious}} {
			unsupported := 0
			example := ""
			exampleLine := 0
			lineIndex := -1
			for line := range strings.SplitSeq(string(stream.data), "\n") {
				lineIndex++
				if a.usedBytes > a.byteLimit/2 && !a.limited {
					a.limited = true
					a.limit("RESOURCE_LIMIT: log materialization budget reached; further log records were omitted. Counts and discovery are incomplete.")
				}
				if a.limited {
					continue
				}
				if strings.TrimSpace(line) == "" {
					continue
				}
				timestamp, payload, ok := strings.Cut(line, " ")
				when, err := time.Parse(time.RFC3339Nano, timestamp)
				if !ok || err != nil {
					unsupported++
					if example == "" {
						example = line
						exampleLine = lineIndex + 1
					}
					continue
				}
				if when.Before(a.start) || !when.Before(a.end) {
					continue
				}
				e, parsed := parseAccess(payload)
				locator := fmt.Sprintf("pod/%s/%s?uid=%s/container/istio-proxy/logs/%s#line=%d&timestamp=%s", p.Ref.Namespace, p.Ref.Name, p.Ref.UID, stream.name, lineIndex+1, timestamp)
				if parsed {
					e.pod = i
					e.when = when
					e.evidence = a.evidence(p, "proxy_access", locator, timestamp, line)
					if a.reserve(line) {
						a.events = append(a.events, e)
					}
					continue
				}
				message, errorLevel, diagnostic := parseDiagnostic(payload)
				if diagnostic {
					d := diagnosticEvent{pod: i, when: when, message: message, errorLevel: errorLevel}
					if errorLevel {
						d.evidence = a.evidence(p, "proxy_diagnostic", locator, timestamp, line)
					}
					if a.reserve(message) {
						a.diagnostics = append(a.diagnostics, d)
					}
					continue
				}
				unsupported++
				if example == "" {
					example = line
					exampleLine = lineIndex + 1
				}
			}
			if unsupported > 0 {
				a.limit(fmt.Sprintf("Unsupported proxy log format: %d %s records on pod %s could not be evaluated (including records without Kubernetes timestamps).", unsupported, stream.name, p.Ref.Name))
				id := a.evidence(p, "proxy_diagnostic", fmt.Sprintf("pod/%s/%s?uid=%s/container/istio-proxy/logs/%s#line=%d", p.Ref.Namespace, p.Ref.Name, p.Ref.UID, stream.name, exampleLine), "", example)
				a.add("PROXY_STARTUP_ERROR", "UNSUPPORTED", "unknown", "Some proxy records use an unsupported format; no conclusions were inferred from their contents.", []string{id}, []string{p.Ref.UID}, []string{"Recognized access or diagnostic log format with Kubernetes timestamps"})
			}
		}
	}
}
func parseAccess(line string) (accessEvent, bool) {
	var e accessEvent
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "{") {
		var v map[string]any
		if json.Unmarshal([]byte(line), &v) != nil {
			return e, false
		}
		get := func(keys ...string) string {
			for _, k := range keys {
				if x, ok := v[k]; ok {
					return str(x)
				}
			}
			return ""
		}
		code := get("response_code", "responseCode", "status", "status_code")
		_, flags := v["response_flags"]
		_, flagsCamel := v["responseFlags"]
		if code == "" && !flags && !flagsCamel {
			return e, false
		}
		e.hasCode = code != "" && code != "-"
		if e.hasCode {
			var err error
			e.code, err = strconv.Atoi(code)
			if err != nil || e.code < 0 || e.code > 599 {
				return e, false
			}
		}
		e.flags = get("response_flags", "responseFlags")
		e.details = get("response_code_details", "responseCodeDetails")
		e.transport = get("upstream_transport_failure_reason", "upstreamTransportFailureReason")
		e.protocol = get("protocol")
		e.method = get("method", "request_method")
		e.path = get("path", "request_path")
		e.authority = get("authority", "host", "requested_authority")
		e.sni = get("requested_server_name", "requestedServerName")
		e.cluster = get("upstream_cluster", "upstream_cluster_raw", "upstreamCluster")
		e.upstream = get("upstream_host", "upstreamHost", "upstream_address")
		e.downstream = get("downstream_remote_address", "downstreamRemoteAddress")
		e.local = get("downstream_local_address", "downstreamLocalAddress")
		e.grpc = get("grpc_status", "grpcStatus")
		e.requestID = get("request_id", "requestId")
		e.route = get("route_name", "routeName")
	} else {
		tokens := textTokens.FindAllString(line, -1)
		if len(tokens) != 22 || !strings.HasPrefix(tokens[0], "[") {
			return e, false
		}
		req := strings.Fields(unquote(tokens[1]))
		if len(req) != 3 {
			return e, false
		}
		n, err := strconv.Atoi(tokens[2])
		if err != nil {
			return e, false
		}
		e.method = req[0]
		e.path = req[1]
		e.protocol = req[2]
		e.code = n
		e.hasCode = true
		e.flags = tokens[3]
		e.details = tokens[4]
		e.transport = unquote(tokens[6])
		e.requestID = unquote(tokens[13])
		e.authority = unquote(tokens[14])
		e.upstream = unquote(tokens[15])
		e.cluster = tokens[16]
		e.local = tokens[18]
		e.downstream = tokens[19]
		e.sni = tokens[20]
		e.route = tokens[21]
	}
	e.protocol = normalizeProtocol(e)
	return e, true
}
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' {
		if v, err := strconv.Unquote(s); err == nil {
			return v
		}
	}
	return s
}
func normalizeProtocol(e accessEvent) string {
	if e.grpc != "" && e.grpc != "-" {
		return "grpc"
	}
	if strings.HasPrefix(strings.ToUpper(e.protocol), "HTTP") {
		return "http"
	}
	switch strings.ToLower(e.protocol) {
	case "http", "https", "grpc", "tcp":
		return strings.ToLower(e.protocol)
	}
	if e.method == "-" && e.path == "-" && e.protocol == "-" {
		return "tcp"
	}
	return "unknown"
}
func parseDiagnostic(line string) (string, bool, bool) {
	var v map[string]any
	if json.Unmarshal([]byte(line), &v) == nil {
		level := strings.ToLower(str(v["level"]))
		if level == "" {
			level = strings.ToLower(str(v["severity"]))
		}
		message := str(v["msg"])
		if message == "" {
			message = str(v["message"])
		}
		if level != "" && message != "" {
			return message, containsAny(level, "error", "critical", "fatal", "warn"), true
		}
	}
	match := diagnosticLevel.FindStringSubmatch(line)
	if len(match) > 1 {
		return line, containsAny(strings.ToLower(match[1]), "error", "critical", "fatal", "warn"), true
	}
	return "", false, false
}
func failed(e accessEvent) bool {
	return e.code >= 400 || (e.grpc != "" && e.grpc != "-" && e.grpc != "0" && strings.ToUpper(e.grpc) != "OK") || (e.flags != "" && e.flags != "-") || (e.transport != "" && e.transport != "-")
}
func hostPort(addr string) (string, int) {
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		n, _ := strconv.Atoi(port)
		if n < 1 || n > 65535 {
			n = 0
		}
		return host, n
	}
	return strings.Trim(addr, "[]"), 0
}
func clusterDestination(cluster string) (string, int, bool) {
	p := strings.Split(cluster, "|")
	if len(p) != 4 || (p[0] != "inbound" && p[0] != "outbound") {
		return "", 0, false
	}
	port, err := strconv.Atoi(p[1])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	return p[3], port, true
}
func (a *analyzer) addressIdentity(address string, when time.Time) string {
	ip, _ := hostPort(address)
	if ip == "" || ip == "-" {
		return "unknown"
	}
	for i := range a.s.Pods {
		p := &a.s.Pods[i]
		if str(at(p.Object, "status", "podIP")) == ip {
			created, err := time.Parse(time.RFC3339Nano, str(at(p.Object, "metadata", "creationTimestamp")))
			if err != nil || created.After(when) {
				continue
			}
			a.limit("IP-to-pod attribution uses current pod metadata and creation time; historical IP continuity and address rewriting remain limitations.")
			return a.podIdentity(p)
		}
	}
	return "ip:" + ip
}
func (a *analyzer) connectionFor(e accessEvent) (core.Connection, bool) {
	p := &a.s.Pods[e.pod]
	dest, port, recognized := clusterDestination(e.cluster)
	inbound := strings.HasPrefix(e.cluster, "inbound|")
	if p.Role == "source" && inbound || p.Role == "destination" && recognized && !inbound {
		return core.Connection{}, false
	}
	c := core.Connection{Source: a.podIdentity(p), Destination: "unknown", Port: port, Protocol: e.protocol, Status: "queued", CountSemantics: "log_records", PodUIDs: []string{p.Ref.UID}}
	if inbound || p.Role == "destination" {
		c.Source = a.addressIdentity(e.downstream, e.when)
		c.Destination = a.podIdentity(p)
		if c.Source == c.Destination {
			ip, _ := hostPort(e.downstream)
			c.Source = "ip:" + ip
		}
	} else if dest != "" {
		c.Destination = dest
	} else {
		c.Destination = a.addressIdentity(e.upstream, e.when)
		_, c.Port = hostPort(e.upstream)
	}
	// Keep the query identity stable when the second collection resolves an IP
	// to a pod or a workload's backend is logged under its Service cluster name.
	if q := a.s.Request.Peer; q != nil {
		address := e.upstream
		if a.s.Request.Direction == "inbound" {
			address = e.downstream
		}
		ip, _ := hostPort(address)
		if q.Kind == "ip" && ip == q.Value || q.Kind == "workload" && a.addressIdentity(address, e.when) == core.PeerIdentity(*q) {
			if a.s.Request.Direction == "inbound" {
				c.Source = core.PeerIdentity(*q)
			} else {
				c.Destination = core.PeerIdentity(*q)
			}
		}
	}

	if p.Role == "destination" && a.s.Request.Direction == "outbound" {
		c.Port = a.frontendPort(c.Destination, p.Ref.UID, c.Port)
	}
	if p.Role == "source" && a.s.Request.Direction == "inbound" && a.addressIdentity(e.upstream, e.when) == core.WorkloadIdentity(a.s.Request.Workload) {
		c.Destination = core.WorkloadIdentity(a.s.Request.Workload)
		_, c.Port = hostPort(e.upstream)
	}
	if !a.peerMatches(c, e) {
		return c, false
	}
	return c, true
}

// Relate the two proxies' ports only through a UID-bound EndpointSlice port;
// Service port and application port are otherwise distinct observations.
func (a *analyzer) frontendPort(host, podUID string, backend int) int {
	ports := map[int]bool{}
	for _, svc := range a.s.Resources {
		if svc.Kind != "Service" || !includes(serviceHosts(&svc), host) {
			continue
		}
		for _, slice := range a.s.Resources {
			if slice.Kind != "EndpointSlice" || slice.Namespace != svc.Namespace || str(at(slice.Object, "metadata", "labels", "kubernetes.io/service-name")) != svc.Name {
				continue
			}
			member := false
			for _, ep := range list(slice.Object["endpoints"]) {
				member = member || str(at(ep, "targetRef", "uid")) == podUID
			}
			if !member {
				continue
			}
			for _, sp := range list(at(svc.Object, "spec", "ports")) {
				for _, ep := range list(slice.Object["ports"]) {
					if str(m(sp)["name"]) == str(m(ep)["name"]) && number(m(ep)["port"]) == backend {
						ports[number(m(sp)["port"])] = true
					}
				}
			}
		}
	}
	if len(ports) == 1 {
		for port := range ports {
			if port > 0 {
				return port
			}
		}
	}
	return backend
}
func (a *analyzer) peerMatches(c core.Connection, e accessEvent) bool {
	q := a.s.Request.Peer
	if q == nil {
		return true
	}
	if q.Port > 0 && q.Port != c.Port {
		return false
	}
	if q.Protocol != "" && q.Protocol != "unknown" && q.Protocol != c.Protocol {
		return false
	}
	identity := c.Destination
	if a.s.Request.Direction == "inbound" {
		identity = c.Source
	}
	switch q.Kind {
	case "service":
		return identity == q.Value+"."+q.Namespace+".svc.cluster.local" || identity == q.Value+"."+q.Namespace+".svc" || identity == q.Value+"."+q.Namespace
	case "host":
		return identity == q.Value
	case "ip":
		address := e.upstream
		if a.s.Request.Direction == "inbound" {
			address = e.downstream
		}
		ip, _ := hostPort(address)
		return identity == "ip:"+q.Value || ip == q.Value
	case "workload":
		return identity == core.PeerIdentity(*q) || strings.HasPrefix(identity, q.Namespace+"/") && strings.HasSuffix(identity, "/"+q.Value)
	}
	return false
}
func (a *analyzer) discover() {
	groups := map[string]int{}
	for i := range a.events {
		e := &a.events[i]
		c, ok := a.connectionFor(*e)
		if !ok {
			continue
		}
		e.connection = c
		if !failed(*e) {
			continue
		}
		key := connectionKey(c)
		if a.selected != nil && !core.ConnectionMatches(c, *a.selected) {
			continue
		}
		if a.selected != nil {
			key = connectionKey(*a.selected)
		}
		j, exists := groups[key]
		if !exists {
			c.ID = core.NewID("connection")
			if a.selected != nil {
				c.ID = a.selected.ID
			}
			j = len(a.out.Connections)
			groups[key] = j
			a.out.Connections = append(a.out.Connections, c)
		}
		group := &a.out.Connections[j]
		if exists && group.Port != c.Port {
			group.Port = 0
		}
		if exists && group.Protocol != c.Protocol {
			group.Protocol = "unknown"
		}
		group.ObservationCount++
		group.PodUIDs = unique(append(group.PodUIDs, c.PodUIDs...))
		previous, _ := time.Parse(time.RFC3339Nano, group.LastSeen)
		if e.when.After(previous) {
			group.LastSeen = core.Timestamp(e.when)
		}
	}
	if a.selected != nil && len(a.out.Connections) == 0 {
		c := *a.selected
		c.ObservationCount = 0
		c.CountSemantics = "log_records"
		c.LastSeen = ""
		c.PodUIDs = []string{}
		a.out.Connections = append(a.out.Connections, c)
	}
	a.limit("Observation counts are proxy log records, not deduplicated requests; retries and both sides of a connection can produce multiple records.")
	if len(a.out.Connections) == 0 {
		a.limit("No failed connection was established from the available supported logs; this is not evidence of network health.")
	}
}
func (a *analyzer) relevantEvents() []accessEvent {
	out := []accessEvent{}
	for _, e := range a.events {
		if e.connection.Source == "" {
			continue
		}
		if a.selected != nil && !core.ConnectionMatches(e.connection, *a.selected) {
			continue
		}
		out = append(out, e)
	}
	return out
}
func (a *analyzer) symptoms() {
	for _, e := range a.relevantEvents() {
		p := a.s.Pods[e.pod]
		ids := []string{e.evidence}
		pods := []string{p.Ref.UID}
		if !failed(e) {
			continue
		}
		if e.protocol == "grpc" && e.grpc != "0" && e.grpc != "OK" && e.grpc != "" && e.grpc != "-" {
			a.add("PROTOCOL_STATUS", "FAIL", "unknown", fmt.Sprintf("Observed gRPC status %s with HTTP status %d; HTTP 200 alone does not establish RPC success.", e.grpc, e.code), ids, pods, nil)
		} else if e.hasCode && e.code >= 400 {
			summary := fmt.Sprintf("Observed HTTP status %d.", e.code)
			if e.flags == "-" && e.details == "via_upstream" {
				summary += " The reply was reported as upstream; no network cause is established."
			} else {
				summary += " Proxy details must be correlated before attributing a cause."
			}
			a.add("PROTOCOL_STATUS", "FAIL", "unknown", summary, ids, pods, nil)
		}
		detail := strings.ToLower(e.transport + " " + e.details)
		reason := ""
		switch {
		case containsAny(detail, "connection refused", "delayed_connect_error:_111", "connect_error:111"):
			reason = "Connection refusal is recorded on the observed upstream segment; the process/socket cause is unknown."
		case containsAny(detail, "timeout", "timed_out") || strings.Contains(e.flags, "UT"):
			reason = "An upstream timeout symptom is recorded; policy, network, and application causes remain unproven."
		case containsAny(detail, "reset", "connection_failure") || containsAny(e.flags, "UF", "UR", "UC"):
			reason = "An upstream connection/reset failure symptom is recorded; flags alone do not establish a root cause."
		}
		if reason != "" {
			a.add("UPSTREAM_FAILURE", "FAIL", "unknown", reason, ids, pods, []string{"Correlated remote-side mechanism and connection identity"})
		}
	}
}
