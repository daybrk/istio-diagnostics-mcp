package live

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
)

// selectedNamespaces supplies bounded RBAC fallbacks, never an allowlist.
// Namespace enumeration is independent of the namespaced resource lists.
func (c *Collector) readResources(ctx context.Context, p core.Principal, cluster string, selectedNamespaces ...string) resources {
	out := resources{objects: map[string]map[string][]map[string]any{}}
	if !p.AllowsContext(cluster) || !c.cfg.LocalPrincipal().AllowsContext(cluster) {
		out.failures = append(out.failures, readFailure{"*", "scope", &core.Fault{Code: "SCOPE_DENIED", Message: "context is outside the allowed scope"}})
		return out
	}
	selected := []string{}
	ensure := func(ns string) {
		if out.objects[ns] == nil {
			out.objects[ns] = map[string][]map[string]any{}
		}
	}
	for _, ns := range selectedNamespaces {
		if core.ValidName(ns) && out.objects[ns] == nil {
			ensure(ns)
			selected = append(selected, ns)
		}
	}
	allComplete := map[string]bool{}
	var mu sync.Mutex
	// Record an atomic list: a truncated or failed list never proves absence.
	record := func(rt resourceType, namespace string, objects []map[string]any, err error) {
		mu.Lock()
		defer mu.Unlock()
		b, _ := json.Marshal(objects)
		if err == nil && out.used+len(b) > c.cfg.Limits.MemoryBytes {
			err = &core.Fault{Code: "RESOURCE_LIMIT", Message: "snapshot memory limit reached"}
		}
		if err != nil {
			out.failures = append(out.failures, readFailure{namespace, rt.resource, err})
			return
		}
		out.used += len(b)
		if namespace == "*" {
			allComplete[rt.kind] = true
		} else {
			ensure(namespace)
			out.objects[namespace][rt.kind] = []map[string]any{}
		}
		for _, o := range objects {
			ns := str(meta(o), "namespace")
			if rt.kind == "Namespace" {
				ns = str(meta(o), "name")
			}
			ensure(ns)
			out.objects[ns][rt.kind] = append(out.objects[ns][rt.kind], o)
		}
	}
	var wg sync.WaitGroup
	for _, rt := range append(append([]resourceType{}, allowedResources...), resourceType{"namespaces", "Namespace"}) {
		wg.Add(1)
		go func(rt resourceType) {
			defer wg.Done()
			select {
			case c.podSlots <- struct{}{}:
				defer func() { <-c.podSlots }()
			case <-ctx.Done():
				record(rt, "*", nil, ctx.Err())
				return
			}
			objects, err := c.get(ctx, cluster, "", rt.resource, "", "")
			record(rt, "*", objects, err)
			var fault *core.Fault
			if !errors.As(err, &fault) || fault.Code != "KUBERNETES_FORBIDDEN" {
				return
			}
			// Keep the global failure even when a selected-namespace fallback succeeds.
			for _, ns := range selected {
				name := ""
				if rt.kind == "Namespace" {
					name = ns
				}
				objects, err = c.get(ctx, cluster, ns, rt.resource, name, "")
				record(rt, ns, objects, err)
			}
		}(rt)
	}
	wg.Wait()
	c.materializeResources(ctx, cluster, &out, allComplete, selected)
	return out
}

// Commit each namespace-kind atomically, including its completeness marker.
// Account both the collected objects and serialized evidence. Temporary Go/JSON
// buffers still require headroom; this budget is not a process RSS limit.
func (c *Collector) materializeResources(ctx context.Context, cluster string, out *resources, allComplete map[string]bool, selected []string) {
	collected := out.objects
	out.objects = map[string]map[string][]map[string]any{}
	namespaces := []string{}
	priority := map[string]bool{}
	for _, ns := range selected {
		priority[ns] = true
	}
	for ns := range collected {
		if !priority[ns] {
			namespaces = append(namespaces, ns)
		}
	}
	sort.Strings(namespaces)
	namespaces = append(append([]string{}, selected...), namespaces...)
	now := core.Timestamp(time.Now())
	stop := func(ns string, err error) {
		out.failures = append(out.failures, readFailure{ns, "snapshot", err})
	}
	for _, ns := range namespaces {
		for _, rt := range append(append([]resourceType{}, allowedResources...), resourceType{"namespaces", "Namespace"}) {
			if err := ctx.Err(); err != nil {
				stop(ns, err)
				return
			}
			objects, exists := collected[ns][rt.kind]
			if !exists && (!allComplete[rt.kind] || rt.kind == "Namespace") {
				continue
			}
			entries := []core.Resource{}
			items := []any{}
			cost := 2 // array delimiters, conservatively charged per group
			add := func(entry core.Resource) bool {
				b, _ := json.Marshal(entry)
				cost += len(b) + 1
				if out.used+cost > c.cfg.Limits.MemoryBytes {
					return false
				}
				entries = append(entries, entry)
				return true
			}
			limited := false
			for _, o := range objects {
				if err := ctx.Err(); err != nil {
					stop(ns, err)
					return
				}
				clean := core.RedactObject(o).(map[string]any)
				items = append(items, clean)
				if !add(core.Resource{Context: cluster, Namespace: ns, Kind: rt.kind, Name: str(meta(o), "name"), UID: str(meta(o), "uid"), CollectedAt: now, Object: clean}) {
					limited = true
					break
				}
			}
			if !limited && rt.kind != "Namespace" {
				limited = !add(core.Resource{Context: cluster, Namespace: ns, Kind: rt.kind + "List", CollectedAt: now, Object: map[string]any{"apiVersion": "v1", "kind": rt.kind + "List", "items": items}})
			}
			if limited {
				stop(ns, &core.Fault{Code: "RESOURCE_LIMIT", Message: "snapshot evidence and list markers exceeded the memory budget; remaining resource coverage is incomplete"})
				return
			}
			if err := ctx.Err(); err != nil {
				stop(ns, err)
				return
			}
			out.used += cost
			out.entries = append(out.entries, entries...)
			if out.objects[ns] == nil {
				out.objects[ns] = map[string][]map[string]any{}
			}
			if objects == nil {
				objects = []map[string]any{}
			}
			out.objects[ns][rt.kind] = objects
		}
	}
}
