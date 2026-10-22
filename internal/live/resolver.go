package live

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
)

type Collector struct {
	cfg                   core.Config
	runner                runner
	podSlots, tunnelSlots chan struct{}
}

var _ core.Collector = (*Collector)(nil)

func New(cfg core.Config) *Collector {
	if cfg.Limits.PodConcurrency < 1 {
		cfg.Limits.PodConcurrency = 4
	}
	if cfg.Limits.PortForwardConcurrency < 1 {
		cfg.Limits.PortForwardConcurrency = 2
	}
	if cfg.Limits.RequestTimeoutSeconds < 1 {
		cfg.Limits.RequestTimeoutSeconds = 15
	}
	if cfg.Limits.OperationBudgetSeconds < 1 {
		cfg.Limits.OperationBudgetSeconds = 120
	}
	if cfg.Limits.MaxLogBytes < 1 {
		cfg.Limits.MaxLogBytes = 8 << 20
	}
	if cfg.Limits.MaxEnvoyResponseBytes < 1 {
		cfg.Limits.MaxEnvoyResponseBytes = 32 << 20
	}
	if cfg.Limits.MemoryBytes < 1 {
		cfg.Limits.MemoryBytes = 256 << 20
	}
	return &Collector{cfg: cfg, runner: execRunner{}, podSlots: make(chan struct{}, cfg.Limits.PodConcurrency), tunnelSlots: make(chan struct{}, cfg.Limits.PortForwardConcurrency)}
}
func (c *Collector) base(cluster, namespace string) []string {
	return []string{"--kubeconfig=" + c.cfg.Kube.KubeconfigPath, "--context=" + cluster, "--namespace=" + namespace, fmt.Sprintf("--request-timeout=%ds", c.cfg.Limits.RequestTimeoutSeconds)}
}
func (c *Collector) run(ctx context.Context, args []string, limit int) (commandResult, error) {
	var out commandResult
	var err error
	for i := 0; i < 2; i++ {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		call, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.Limits.RequestTimeoutSeconds)*time.Second)
		out, err = c.runner.Run(call, args, limit)
		if call.Err() != nil {
			err = call.Err()
		}
		cancel()
		if out.Truncated {
			return out, &core.Fault{Code: "RESOURCE_LIMIT", Message: "kubectl output exceeded the configured byte limit"}
		}
		if err == nil {
			return out, nil
		}
		if i == 1 || !transient(out.Stderr, err) {
			break
		}
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	return out, &core.Fault{Code: errorCode(out.Stderr, err), Message: core.RedactString(short(out.Stderr + " " + err.Error())), Retryable: transient(out.Stderr, err)}
}
func transient(s string, e error) bool {
	if e == nil {
		return false
	}
	s = strings.ToLower(s + " " + e.Error())
	for _, v := range []string{"timeout", "timed out", "deadline exceeded", "temporarily unavailable", "connection reset", "connection refused", "too many requests", "service unavailable", "unexpected eof"} {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}
func errorCode(s string, e error) string {
	s = strings.ToLower(s + " " + fmt.Sprint(e))
	if strings.Contains(s, "forbidden") || strings.Contains(s, "unauthorized") {
		return "KUBERNETES_FORBIDDEN"
	}
	if strings.Contains(s, "notfound") || strings.Contains(s, "not found") {
		return "KUBERNETES_NOT_FOUND"
	}
	return "KUBERNETES_UNAVAILABLE"
}
func short(s string) string {
	if len(s) > 2048 {
		return s[:2048]
	}
	return s
}
func (c *Collector) get(ctx context.Context, cluster, ns, resource, name, selector string) ([]map[string]any, error) {
	a := append(c.base(cluster, ns), "get", resource)
	if name != "" {
		a = append(a, name)
	}
	a = append(a, "-o=json")
	if selector != "" {
		a = append(a, "--selector="+selector)
	}
	limit := min(c.cfg.Limits.MemoryBytes, 32<<20)
	r, e := c.run(ctx, a, limit)
	if e != nil {
		return nil, e
	}
	var o map[string]any
	if e = json.Unmarshal(r.Stdout, &o); e != nil {
		return nil, &core.Fault{Code: "KUBERNETES_INVALID_RESPONSE", Message: "invalid JSON for " + resource}
	}
	if name != "" {
		if str(meta(o), "name") != name || str(meta(o), "uid") == "" {
			return nil, &core.Fault{Code: "KUBERNETES_INVALID_RESPONSE", Message: "invalid object identity for " + resource}
		}
		if resource != "namespaces" && str(meta(o), "namespace") != ns {
			return nil, &core.Fault{Code: "SCOPE_DENIED", Message: "resource response is outside requested namespace"}
		}
		return []map[string]any{o}, nil
	}
	items, ok := o["items"]
	if !ok {
		return nil, &core.Fault{Code: "KUBERNETES_INVALID_RESPONSE", Message: "missing list items for " + resource}
	}
	if items == nil {
		return []map[string]any{}, nil
	}
	array, ok := items.([]any)
	if !ok {
		return nil, &core.Fault{Code: "KUBERNETES_INVALID_RESPONSE", Message: "invalid list items for " + resource}
	}
	out := make([]map[string]any, 0, len(array))
	for _, x := range array {
		v, ok := x.(map[string]any)
		if !ok || str(meta(v), "uid") == "" || !core.ValidName(str(meta(v), "name")) {
			return nil, &core.Fault{Code: "KUBERNETES_INVALID_RESPONSE", Message: "invalid item identity for " + resource}
		}
		if resource != "namespaces" && str(meta(v), "namespace") != ns {
			return nil, &core.Fault{Code: "SCOPE_DENIED", Message: "resource response is outside requested namespace"}
		}
		out = append(out, v)
	}
	return out, nil
}
func (c *Collector) scope(p core.Principal, q core.WorkloadQuery) (core.WorkloadQuery, *core.Question, error) {
	scopes := core.IntersectScopes(c.cfg.Kube.Contexts, p.Scopes)
	contexts := []string{}
	for _, s := range scopes {
		contexts = append(contexts, s.Context)
	}
	if q.Context == "" {
		if len(contexts) != 1 {
			return q, &core.Question{Field: "context", Message: "Select an allowed Kubernetes context", Options: contexts}, nil
		}
		q.Context = contexts[0]
	}
	ns := []string{}
	for _, s := range scopes {
		if s.Context == q.Context {
			ns = append(ns, s.Namespaces...)
		}
	}
	if len(ns) == 0 {
		return q, nil, &core.Fault{Code: "SCOPE_DENIED", Message: "context is outside the allowed scope"}
	}
	if q.Namespace == "" {
		if len(ns) != 1 {
			return q, &core.Question{Field: "namespace", Message: "Select an allowed namespace", Options: ns}, nil
		}
		q.Namespace = ns[0]
	}
	if !p.Allows(q.Context, q.Namespace) || !c.cfg.LocalPrincipal().Allows(q.Context, q.Namespace) {
		return q, nil, &core.Fault{Code: "SCOPE_DENIED", Message: "namespace is outside the allowed scope"}
	}
	if !core.ValidName(q.Namespace) {
		return q, nil, &core.Fault{Code: "INVALID_ARGUMENT", Message: "invalid namespace"}
	}
	return q, nil, nil
}

var labelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[-A-Za-z0-9_.]*[A-Za-z0-9])?$`)
var setSelectorPattern = regexp.MustCompile(`^([^\s()]+)\s+(?:in|notin)\s*\(([^()]+)\)$`)
var equalitySelectorPattern = regexp.MustCompile(`^([^\s!=]+)\s*(?:==|!=|=)\s*([^\s!=]*)$`)

func validLabel(s string, empty bool) bool {
	return empty && s == "" || len(s) <= 63 && labelPattern.MatchString(s)
}
func validLabelKey(s string) bool {
	parts := strings.Split(s, "/")
	if len(parts) == 1 {
		return validLabel(parts[0], false)
	}
	return len(parts) == 2 && core.ValidName(parts[0]) && validLabel(parts[1], false)
}
func validRequirement(s string) bool {
	s = strings.TrimSpace(s)
	if m := setSelectorPattern.FindStringSubmatch(s); len(m) == 3 {
		if !validLabelKey(m[1]) {
			return false
		}
		for _, v := range strings.Split(m[2], ",") {
			if !validLabel(strings.TrimSpace(v), false) {
				return false
			}
		}
		return true
	}
	if m := equalitySelectorPattern.FindStringSubmatch(s); len(m) == 3 {
		return validLabelKey(m[1]) && validLabel(m[2], true)
	}
	return validLabelKey(strings.TrimPrefix(s, "!"))
}

func validSelector(s string) bool {
	if s == "" || len(s) > 2048 || strings.ContainsAny(s, "\x00\r\n\t") {
		return false
	}
	depth := 0
	start := 0
	for i, r := range s {
		if r == '(' {
			depth++
		}
		if r == ')' {
			depth--
		}
		if depth < 0 || depth > 1 {
			return false
		}
		if r == ',' && depth == 0 {
			if !validRequirement(s[start:i]) {
				return false
			}
			start = i + 1
		}
	}
	return depth == 0 && validRequirement(s[start:])
}

var controllerResources = map[string]string{"Deployment": "deployments", "StatefulSet": "statefulsets", "DaemonSet": "daemonsets", "Pod": "pods"}

type inventory struct {
	pods   []map[string]any
	owners map[string]map[string]any
}

func (c *Collector) loadInventory(ctx context.Context, cluster, ns, selector, kind string) (inventory, error) {
	in := inventory{owners: map[string]map[string]any{}}
	var err error
	in.pods, err = c.get(ctx, cluster, ns, "pods", "", selector)
	if err != nil {
		return in, err
	}
	resources := []string{"replicasets", "deployments", "statefulsets", "daemonsets"}
	switch kind {
	case "Pod":
		resources = nil
	case "Deployment":
		resources = []string{"replicasets", "deployments"}
	case "StatefulSet":
		resources = []string{"statefulsets"}
	case "DaemonSet":
		resources = []string{"daemonsets"}
	}
	for _, r := range resources {
		objects, e := c.get(ctx, cluster, ns, r, "", "")
		if e != nil {
			return in, e
		}
		for _, o := range objects {
			in.owners[str(meta(o), "uid")] = o
		}
	}
	return in, nil
}
func (in inventory) owner(p map[string]any) map[string]any {
	cur := p
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		uid := str(meta(cur), "uid")
		if seen[uid] {
			break
		}
		seen[uid] = true
		owner := controller(cur)
		if owner == nil {
			break
		}
		next := in.owners[str(owner, "uid")]
		if next == nil || str(next, "kind") != str(owner, "kind") || str(meta(next), "name") != str(owner, "name") {
			break
		}
		kind := str(next, "kind")
		if kind != "ReplicaSet" && kind != "Deployment" && kind != "StatefulSet" && kind != "DaemonSet" {
			break
		}
		cur = next
	}
	if _, ok := controllerResources[str(cur, "kind")]; !ok {
		return p
	}
	return cur
}
func (in inventory) podsFor(ref core.WorkloadRef) []map[string]any {
	out := []map[string]any{}
	for _, p := range in.pods {
		if (ref.Kind == "Pod" && str(meta(p), "uid") == ref.UID) || (ref.Kind != "Pod" && str(meta(in.owner(p)), "uid") == ref.UID) {
			out = append(out, p)
		}
	}
	return out
}
func (c *Collector) Resolve(ctx context.Context, p core.Principal, q core.WorkloadQuery) (core.Resolution, error) {
	r := core.Resolution{Candidates: []core.Candidate{}}
	if q.Kind == "Selector" {
		if q.Name != "" || !validSelector(q.Selector) {
			return r, &core.Fault{Code: "INVALID_ARGUMENT", Message: "invalid label selector"}
		}
	} else {
		if controllerResources[q.Kind] == "" || !core.ValidName(q.Name) || q.Selector != "" {
			return r, &core.Fault{Code: "INVALID_ARGUMENT", Message: "invalid workload kind or name"}
		}
	}
	q, question, e := c.scope(p, q)
	if e != nil {
		return r, e
	}
	if question != nil {
		r.Question = question
		return r, nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.Limits.OperationBudgetSeconds)*time.Second)
	defer cancel()
	if q.Kind == "Pod" {
		objects, err := c.get(ctx, q.Context, q.Namespace, "pods", q.Name, "")
		if err != nil {
			return r, err
		}
		r.Candidates = append(r.Candidates, core.Candidate{Workload: reference(q.Context, objects[0]), PodCount: 1})
		return r, nil
	}
	in, e := c.loadInventory(ctx, q.Context, q.Namespace, q.Selector, q.Kind)
	if e != nil {
		return r, e
	}
	if q.Kind != "Selector" {
		objects, e := c.get(ctx, q.Context, q.Namespace, controllerResources[q.Kind], q.Name, "")
		if e != nil {
			return r, e
		}
		ref := reference(q.Context, objects[0])
		r.Candidates = append(r.Candidates, core.Candidate{Workload: ref, PodCount: len(in.podsFor(ref))})
		return r, nil
	}
	groups := map[string]*core.Candidate{}
	for _, pod := range in.pods {
		o := in.owner(pod)
		uid := str(meta(o), "uid")
		if groups[uid] == nil {
			groups[uid] = &core.Candidate{Workload: reference(q.Context, o)}
		}
		groups[uid].PodCount++
	}
	for _, v := range groups {
		r.Candidates = append(r.Candidates, *v)
	}
	sort.Slice(r.Candidates, func(i, j int) bool { return r.Candidates[i].Workload.Name < r.Candidates[j].Workload.Name })
	return r, nil
}
func obj(v any) map[string]any               { m, _ := v.(map[string]any); return m }
func meta(o map[string]any) map[string]any   { return obj(o["metadata"]) }
func str(o map[string]any, k string) string  { s, _ := o[k].(string); return s }
func array(o map[string]any, k string) []any { v, _ := o[k].([]any); return v }
func controller(o map[string]any) map[string]any {
	for _, x := range array(meta(o), "ownerReferences") {
		m := obj(x)
		if yes, _ := m["controller"].(bool); yes {
			return m
		}
	}
	return nil
}
func reference(cluster string, o map[string]any) core.WorkloadRef {
	return core.WorkloadRef{Context: cluster, Namespace: str(meta(o), "namespace"), Kind: str(o, "kind"), Name: str(meta(o), "name"), UID: str(meta(o), "uid")}
}
