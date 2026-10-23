package live

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
)

type resourceType struct{ resource, kind string }

var allowedResources = []resourceType{{"pods", "Pod"}, {"deployments", "Deployment"}, {"replicasets", "ReplicaSet"}, {"statefulsets", "StatefulSet"}, {"daemonsets", "DaemonSet"}, {"services", "Service"}, {"endpointslices.discovery.k8s.io", "EndpointSlice"}, {"networkpolicies.networking.k8s.io", "NetworkPolicy"}, {"virtualservices.networking.istio.io", "VirtualService"}, {"destinationrules.networking.istio.io", "DestinationRule"}, {"serviceentries.networking.istio.io", "ServiceEntry"}, {"sidecars.networking.istio.io", "Sidecar"}, {"envoyfilters.networking.istio.io", "EnvoyFilter"}, {"authorizationpolicies.security.istio.io", "AuthorizationPolicy"}, {"peerauthentications.security.istio.io", "PeerAuthentication"}, {"requestauthentications.security.istio.io", "RequestAuthentication"}, {"events", "Event"}}

type readFailure struct {
	namespace, resource string
	err                 error
}
type resources struct {
	objects  map[string]map[string][]map[string]any
	failures []readFailure
	entries  []core.Resource
	used     int
}

func (c *Collector) Collect(ctx context.Context, p core.Principal, req core.CollectRequest, progress func(core.Progress)) (*core.Snapshot, error) {
	s := &core.Snapshot{Request: req, Pods: []core.PodSnapshot{}, Resources: []core.Resource{}, Coverage: []core.CoverageEntry{}, Limitations: []string{}, CollectedAt: core.Timestamp(time.Now())}
	start, e := time.Parse(time.RFC3339Nano, req.Window.Start)
	if e != nil {
		return s, &core.Fault{Code: "INVALID_TIME_WINDOW", Message: "invalid window start"}
	}
	end, e := time.Parse(time.RFC3339Nano, req.Window.End)
	if e != nil || !start.Before(end) {
		return s, &core.Fault{Code: "INVALID_TIME_WINDOW", Message: "invalid frozen window"}
	}
	if req.Direction != "inbound" && req.Direction != "outbound" {
		return s, &core.Fault{Code: "INVALID_ARGUMENT", Message: "direction must be inbound or outbound"}
	}
	q := core.WorkloadQuery{Context: req.Workload.Context, Namespace: req.Workload.Namespace, Kind: req.Workload.Kind, Name: req.Workload.Name}
	if controllerResources[q.Kind] == "" || !core.ValidName(q.Name) || req.Workload.UID == "" {
		return s, &core.Fault{Code: "INVALID_ARGUMENT", Message: "invalid workload reference"}
	}
	q, question, e := c.scope(p, q)
	if e != nil {
		return s, e
	}
	if question != nil {
		return s, &core.Fault{Code: "INVALID_ARGUMENT", Message: "collection requires explicit context and namespace"}
	}
	if e = c.validatePeer(p, q.Context, req.Peer); e != nil {
		return s, e
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.Limits.OperationBudgetSeconds)*time.Second)
	defer cancel()
	current, e := c.get(ctx, q.Context, q.Namespace, controllerResources[q.Kind], q.Name, "")
	if e != nil {
		return s, e
	}
	if str(meta(current[0]), "uid") != req.Workload.UID {
		return s, &core.Fault{Code: "WORKLOAD_REPLACED", Message: "selected workload no longer has the resolved UID"}
	}
	s.Request.Workload = reference(q.Context, current[0])
	mainPods := current
	if q.Kind != "Pod" {
		in, err := c.loadInventory(ctx, q.Context, q.Namespace, "", q.Kind)
		if err != nil {
			return s, err
		}
		mainPods = in.podsFor(s.Request.Workload)
	}
	// Establish every discovered replica before any budget-limited per-pod work.
	sourceRole, peerRole := "source", "destination"
	if req.Direction == "inbound" {
		sourceRole, peerRole = peerRole, sourceRole
	}
	addPod := func(o map[string]any, role string) {
		for _, x := range s.Pods {
			if x.Ref.UID == str(meta(o), "uid") {
				return
			}
		}
		s.Pods = append(s.Pods, core.PodSnapshot{Ref: reference(q.Context, o), Role: role, Object: core.RedactObject(o).(map[string]any), CollectedAt: core.Timestamp(time.Now()), Envoy: map[string]json.RawMessage{}})
	}
	for _, o := range mainPods {
		addPod(o, sourceRole)
	}
	selectedNamespaces := []string{q.Namespace}
	if req.Peer != nil && req.Peer.Namespace != "" {
		selectedNamespaces = append(selectedNamespaces, req.Peer.Namespace)
	}
	r := c.readResources(ctx, p, q.Context, selectedNamespaces...)
	s.Resources = r.entries
	for _, f := range r.failures {
		s.Limitations = append(s.Limitations, fmt.Sprintf("%s/%s: %s", f.namespace, f.resource, safeError(f.err)))
	}
	if req.Peer != nil {
		peers, lim := c.peerPods(q.Context, req.Peer, r)
		for _, pod := range peers {
			addPod(pod, peerRole)
		}
		s.Limitations = append(s.Limitations, lim...)
	}
	sort.Slice(s.Pods, func(i, j int) bool {
		return s.Pods[i].Ref.Namespace+"/"+s.Pods[i].Ref.Name < s.Pods[j].Ref.Namespace+"/"+s.Pods[j].Ref.Name
	})
	s.Resources = filterEvents(s.Resources, s.Pods, start, end)
	for _, pod := range s.Pods {
		resourceOK := true
		for _, f := range r.failures {
			if f.resource == "events" {
				continue
			}
			resourceOK = false
			s.Coverage = append(s.Coverage, coverage(pod.Ref, "resources", status(f.err), fmt.Sprintf("%s/%s: %s", f.namespace, f.resource, safeError(f.err))))
		}
		if resourceOK {
			s.Coverage = append(s.Coverage, coverage(pod.Ref, "resources", "collected", "All planned resource reads completed in the permitted scope"))
		} else {
			s.Coverage = append(s.Coverage, coverage(pod.Ref, "resources", "partial", "Resource coverage is incomplete; unavailable reads are listed separately"))
		}
		eventOK := false
		for ns, objects := range r.objects {
			if ns == pod.Ref.Namespace {
				_, eventOK = objects["Event"]
			}
		}
		if eventOK {
			s.Coverage = append(s.Coverage, coverage(pod.Ref, "events", "collected", "Events filtered by involved pod UID and the frozen time window"))
		} else {
			detail := "Event collection unavailable"
			st := "unavailable"
			for _, f := range r.failures {
				if (f.namespace == pod.Ref.Namespace || f.namespace == "*") && f.resource == "events" {
					detail = safeError(f.err)
					st = status(f.err)
				}
			}
			s.Coverage = append(s.Coverage, coverage(pod.Ref, "events", st, detail))
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	completed := 0
	used := r.used
	for i := range s.Pods {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			pending := func() {
				mu.Lock()
				defer mu.Unlock()
				for _, source := range podSources(req.IncludeEnvoy) {
					s.Coverage = append(s.Coverage, coverage(s.Pods[i].Ref, source, "pending", "Not started before the operation stopped"))
				}
			}
			select {
			case c.podSlots <- struct{}{}:
				defer func() { <-c.podSlots }()
			case <-ctx.Done():
				pending()
				return
			}
			if ctx.Err() != nil {
				pending()
				return
			}
			pod, entries := c.collectPod(ctx, s.Pods[i], req, start, end)
			mu.Lock()
			size := len(pod.LogsCurrent) + len(pod.LogsPrevious)
			for _, v := range pod.Envoy {
				size += len(v)
			}
			if used+size > c.cfg.Limits.MemoryBytes {
				pod.LogsCurrent = nil
				pod.LogsPrevious = nil
				pod.Envoy = map[string]json.RawMessage{}
				for j := range entries {
					if entries[j].Source != "pod_status" && entries[j].Status == "collected" {
						entries[j].Status = "truncated"
						entries[j].Detail = "Snapshot memory limit reached; source bytes were discarded"
					}
				}
			} else {
				used += size
			}
			s.Pods[i] = pod
			s.Coverage = append(s.Coverage, entries...)
			completed++
			update := core.Progress{Completed: completed, Total: len(s.Pods), Coverage: append([]core.CoverageEntry{}, entries...)}
			mu.Unlock()
			if progress != nil {
				progress(update)
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		s.Limitations = append(s.Limitations, "Operation stopped: "+ctx.Err().Error()+"; queued replicas remain explicitly pending")
	}
	s.Limitations = append(s.Limitations, "Current configuration is not historical state for the log window. Log rotation, buffering, deleted pods and since-time filtering limit historical completeness.")
	return s, nil
}
func (c *Collector) validatePeer(p core.Principal, cluster string, peer *core.PeerQuery) error {
	if peer == nil {
		return nil
	}
	if peer.Kind != "workload" && peer.Kind != "service" && peer.Kind != "host" && peer.Kind != "ip" {
		return &core.Fault{Code: "INVALID_ARGUMENT", Message: "invalid peer kind"}
	}
	if len(peer.Value) == 0 || len(peer.Value) > 253 || strings.HasPrefix(peer.Value, "-") || strings.ContainsAny(peer.Value, "\x00\n\r ") {
		return &core.Fault{Code: "INVALID_ARGUMENT", Message: "invalid peer value"}
	}
	if peer.Kind == "workload" || peer.Kind == "service" {
		if peer.Namespace == "" {
			return &core.Fault{Code: "INVALID_ARGUMENT", Message: "peer workload or service requires an explicit namespace"}
		}
	}
	if !p.AllowsContext(cluster) || !c.cfg.LocalPrincipal().AllowsContext(cluster) {
		return &core.Fault{Code: "SCOPE_DENIED", Message: "context is outside the allowed scope"}
	}
	if peer.Namespace != "" && !core.ValidName(peer.Namespace) {
		return &core.Fault{Code: "INVALID_ARGUMENT", Message: "invalid peer namespace"}
	}
	if peer.Kind == "ip" && net.ParseIP(peer.Value) == nil {
		return &core.Fault{Code: "INVALID_ARGUMENT", Message: "invalid peer IP"}
	}
	if peer.Kind == "service" && !core.ValidName(peer.Value) {
		return &core.Fault{Code: "INVALID_ARGUMENT", Message: "invalid service name"}
	}
	return nil
}
func (c *Collector) peerPods(cluster string, peer *core.PeerQuery, r resources) ([]map[string]any, []string) {
	selected := map[string]map[string]any{}
	limitations := []string{}
	add := func(p map[string]any) { selected[str(meta(p), "uid")] = p }
	serviceMatches := func(ns string, s map[string]any) bool {
		name := str(meta(s), "name")
		switch peer.Kind {
		case "service":
			return ns == peer.Namespace && name == peer.Value
		case "host":
			host := strings.TrimSuffix(strings.ToLower(peer.Value), ".")
			return host == name+"."+ns || host == name+"."+ns+".svc" || host == name+"."+ns+".svc.cluster.local" || (peer.Namespace == ns && host == name)
		case "ip":
			spec := obj(s["spec"])
			if str(spec, "clusterIP") == peer.Value {
				return true
			}
			for _, k := range []string{"clusterIPs", "externalIPs"} {
				for _, v := range array(spec, k) {
					if v == peer.Value {
						return true
					}
				}
			}
			for _, x := range array(obj(obj(s["status"])["loadBalancer"]), "ingress") {
				if str(obj(x), "ip") == peer.Value {
					return true
				}
			}
		}
		return false
	}
	workloadMatches := []core.WorkloadRef{}
	for ns, data := range r.objects {
		if peer.Namespace != "" && ns != peer.Namespace {
			continue
		}
		pods := data["Pod"]
		if peer.Kind == "workload" {
			kind, name := "", peer.Value
			if parts := strings.Split(peer.Value, "/"); len(parts) == 2 {
				for k := range controllerResources {
					if strings.EqualFold(k, parts[0]) {
						kind = k
					}
				}
				name = parts[1]
			}
			if !core.ValidName(name) {
				limitations = append(limitations, "Peer workload identity is invalid or unsupported")
				continue
			}
			in := inventory{pods: pods, owners: map[string]map[string]any{}}
			for _, k := range []string{"ReplicaSet", "Deployment", "StatefulSet", "DaemonSet"} {
				for _, o := range data[k] {
					in.owners[str(meta(o), "uid")] = o
				}
			}
			for _, k := range []string{"Deployment", "StatefulSet", "DaemonSet", "Pod"} {
				if kind != "" && kind != k {
					continue
				}
				for _, o := range data[k] {
					if str(meta(o), "name") == name {
						ref := reference(cluster, o)
						workloadMatches = append(workloadMatches, ref)
						for _, pod := range in.podsFor(ref) {
							add(pod)
						}
					}
				}
			}
			continue
		}
		for _, pod := range pods {
			if peer.Kind == "ip" {
				status := obj(pod["status"])
				if str(status, "podIP") == peer.Value {
					add(pod)
				}
				for _, x := range array(status, "podIPs") {
					if str(obj(x), "ip") == peer.Value {
						add(pod)
					}
				}
			}
		}
		for _, service := range data["Service"] {
			if !serviceMatches(ns, service) {
				continue
			}
			selector := obj(obj(service["spec"])["selector"])
			for _, pod := range pods {
				if matches(selector, obj(meta(pod)["labels"])) {
					add(pod)
				}
			}
			for _, slice := range data["EndpointSlice"] {
				if str(obj(meta(slice)["labels"]), "kubernetes.io/service-name") != str(meta(service), "name") {
					continue
				}
				for _, ep := range array(slice, "endpoints") {
					target := obj(obj(ep)["targetRef"])
					if str(target, "kind") != "Pod" || str(target, "namespace") != "" && str(target, "namespace") != ns {
						continue
					}
					for _, pod := range pods {
						if str(target, "uid") != "" && str(meta(pod), "uid") == str(target, "uid") {
							add(pod)
						}
					}
				}
			}
		}
		if peer.Kind == "host" || peer.Kind == "ip" {
			for _, entry := range data["ServiceEntry"] {
				spec := obj(entry["spec"])
				match := false
				for _, v := range array(spec, "hosts") {
					if v == peer.Value {
						match = true
					}
				}
				for _, v := range array(spec, "addresses") {
					if v == peer.Value {
						match = true
					}
				}
				if !match {
					continue
				}
				selector := obj(obj(spec["workloadSelector"])["labels"])
				for _, pod := range pods {
					if matches(selector, obj(meta(pod)["labels"])) {
						add(pod)
					}
				}
				for _, ep := range array(spec, "endpoints") {
					address := str(obj(ep), "address")
					for _, pod := range pods {
						if address != "" && str(obj(pod["status"]), "podIP") == address {
							add(pod)
						}
					}
				}
			}
		}
	}
	if peer.Kind == "workload" && len(workloadMatches) > 1 {
		return nil, []string{"Peer workload name is ambiguous across controller kinds; specify Kind/name"}
	}
	out := []map[string]any{}
	for _, p := range selected {
		out = append(out, p)
	}
	if len(out) == 0 {
		limitations = append(limitations, "Peer membership could not be established from allowed cluster resources; no local DNS or network probe was used")
	}
	return out, limitations
}
func matches(selector, labels map[string]any) bool {
	if len(selector) == 0 {
		return false
	}
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}
func filterEvents(entries []core.Resource, pods []core.PodSnapshot, start, end time.Time) []core.Resource {
	uids := map[string]bool{}
	for _, p := range pods {
		uids[p.Ref.UID] = true
	}
	out := entries[:0]
	for _, r := range entries {
		if r.Kind == "EventList" {
			continue
		}
		if r.Kind == "Event" {
			o := r.Object
			if !uids[str(obj(o["involvedObject"]), "uid")] {
				continue
			}
			raw := str(o, "eventTime")
			if raw == "" {
				raw = str(obj(o["series"]), "lastObservedTime")
			}
			if raw == "" {
				raw = str(o, "lastTimestamp")
			}
			if raw == "" {
				raw = str(o, "firstTimestamp")
			}
			t, e := time.Parse(time.RFC3339Nano, raw)
			if e != nil || t.Before(start) || !t.Before(end) {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}
func podSources(envoy bool) []string {
	s := []string{"pod_status", "logs_current", "logs_previous"}
	if envoy {
		s = append(s, "config_dump", "certs", "clusters", "server_info")
	}
	return s
}
func coverage(ref core.WorkloadRef, source, st, detail string) core.CoverageEntry {
	return core.CoverageEntry{PodUID: ref.UID, Namespace: ref.Namespace, Pod: ref.Name, Source: source, Status: st, Detail: short(core.RedactString(detail))}
}
func status(e error) string {
	if e == nil {
		return "collected"
	}
	if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
		return "cancelled"
	}
	var fault *core.Fault
	if errors.As(e, &fault) {
		if fault.Code == "RESOURCE_LIMIT" {
			return "truncated"
		}
		if fault.Code == "KUBERNETES_FORBIDDEN" || fault.Code == "SCOPE_DENIED" {
			return "forbidden"
		}
	}
	return "unavailable"
}
func safeError(e error) string {
	if e == nil {
		return ""
	}
	return short(core.RedactString(e.Error()))
}
func (c *Collector) verifyUID(ctx context.Context, ref core.WorkloadRef) error {
	pods, e := c.get(ctx, ref.Context, ref.Namespace, "pods", ref.Name, "")
	if e != nil {
		return e
	}
	if str(meta(pods[0]), "uid") != ref.UID {
		return errUIDChanged
	}
	return nil
}
func (c *Collector) collectPod(ctx context.Context, pod core.PodSnapshot, req core.CollectRequest, start, end time.Time) (core.PodSnapshot, []core.CoverageEntry) {
	entries := []core.CoverageEntry{}
	if e := c.verifyUID(ctx, pod.Ref); e != nil {
		for _, source := range podSources(req.IncludeEnvoy) {
			entries = append(entries, coverage(pod.Ref, source, status(e), safeError(e)))
		}
		return pod, entries
	}
	entries = append(entries, coverage(pod.Ref, "pod_status", "collected", "Pod identity and UID verified"))
	restart := false
	for _, field := range []string{"containerStatuses", "initContainerStatuses"} {
		for _, cs := range array(obj(pod.Object["status"]), field) {
			m := obj(cs)
			if str(m, "name") == "istio-proxy" {
				n, _ := m["restartCount"].(float64)
				restart = restart || n > 0
			}
		}
	}
	for _, previous := range []bool{false, true} {
		source := "logs_current"
		if previous {
			source = "logs_previous"
			if !restart {
				entries = append(entries, coverage(pod.Ref, source, "unsupported", "Pod status does not report a previous istio-proxy container instance"))
				continue
			}
		}
		a := append(c.base(pod.Ref.Context, pod.Ref.Namespace), "logs", pod.Ref.Name, "--container=istio-proxy", "--timestamps=true", "--since-time="+req.Window.Start)
		if previous {
			a = append(a, "--previous=true")
		}
		r, e := c.run(ctx, a, c.cfg.Limits.MaxLogBytes)
		if e != nil && !r.Truncated {
			entries = append(entries, coverage(pod.Ref, source, status(e), safeError(e)))
			continue
		}
		logs, malformed := filterLogs(r.Stdout, start, end, r.Truncated)
		st, detail := "collected", "Timestamped proxy logs filtered to the requested [start,end) window"
		if malformed > 0 {
			st = "partial"
			detail = fmt.Sprintf("%d log lines lacked a parseable timestamp and were excluded", malformed)
		}
		if r.Truncated {
			st = "truncated"
			detail = "Log byte limit reached; incomplete final line excluded and remaining coverage unknown"
		}
		entries = append(entries, coverage(pod.Ref, source, st, detail))
		if previous {
			pod.LogsPrevious = logs
		} else {
			pod.LogsCurrent = logs
		}
	}
	if req.IncludeEnvoy {
		data, envoyEntries := c.collectEnvoy(ctx, pod.Ref)
		pod.Envoy = data
		entries = append(entries, envoyEntries...)
	}
	if e := c.verifyUID(ctx, pod.Ref); e != nil {
		pod.LogsCurrent = nil
		pod.LogsPrevious = nil
		pod.Envoy = map[string]json.RawMessage{}
		for i := range entries {
			entries[i].Status = status(e)
			entries[i].Detail = "Post-collection UID verification failed; bytes discarded: " + safeError(e)
		}
	}
	return pod, entries
}
func filterLogs(data []byte, start, end time.Time, truncated bool) ([]byte, int) {
	var out bytes.Buffer
	bad := 0
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		var line []byte
		if i < 0 {
			if truncated {
				break
			}
			line = data
			data = nil
		} else {
			line = data[:i]
			data = data[i+1:]
		}
		if len(line) == 0 {
			continue
		}
		prefix, _, ok := bytes.Cut(line, []byte{' '})
		if !ok {
			bad++
			continue
		}
		t, e := time.Parse(time.RFC3339Nano, string(prefix))
		if e != nil {
			bad++
			continue
		}
		if t.Before(start) || !t.Before(end) {
			continue
		}
		out.WriteString(core.RedactString(string(line)))
		out.WriteByte('\n')
	}
	return out.Bytes(), bad
}
