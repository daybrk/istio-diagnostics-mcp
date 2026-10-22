// Package live collects namespaced evidence using fixed, read-only CLI operations.
package live

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daybrk/istio-diagnostics-mcp/internal/diagnostics"
)

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type ExecRunner struct {
	Timeout  time.Duration
	MaxBytes int
}
type limitedBuffer struct {
	b        bytes.Buffer
	max      int
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.b.Len()+len(p) > b.max {
		remaining := b.max - b.b.Len()
		if remaining > 0 {
			_, _ = b.b.Write(p[:remaining])
		}
		b.exceeded = true
		return len(p), nil
	}
	return b.b.Write(p)
}
func (r ExecRunner) Run(ctx context.Context, program string, args ...string) ([]byte, error) {
	if program != "kubectl" && program != "istioctl" {
		return nil, fmt.Errorf("executable is not allowed")
	}
	if r.Timeout <= 0 {
		r.Timeout = 20 * time.Second
	}
	if r.MaxBytes <= 0 {
		r.MaxBytes = 20 << 20
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.WaitDelay = 2 * time.Second
	out := &limitedBuffer{max: r.MaxBytes}
	stderr := &limitedBuffer{max: 4096}
	cmd.Stdout = out
	cmd.Stderr = stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if out.exceeded {
		return nil, errors.New("command output exceeds configured limit")
	}
	if err != nil {
		// Do not return raw stderr: authentication plugins may print credentials.
		s := strings.ToLower(stderr.b.String())
		switch {
		case strings.Contains(s, "forbidden"):
			return nil, errors.New("access denied by Kubernetes RBAC")
		case strings.Contains(s, "notfound") || strings.Contains(s, "not found"):
			return nil, errors.New("resource or executable not found")
		default:
			return nil, fmt.Errorf("%s failed; inspect local CLI diagnostics without sharing credentials", program)
		}
	}
	return out.b.Bytes(), nil
}

type Config struct {
	Enabled    bool
	Context    string
	Namespaces []string
}

func FromEnv() Config {
	return Config{Enabled: os.Getenv("ISTIO_DIAG_ENABLE_LIVE") == "true", Context: os.Getenv("ISTIO_DIAG_CONTEXT"), Namespaces: strings.FieldsFunc(os.Getenv("ISTIO_DIAG_NAMESPACES"), func(r rune) bool { return r == ',' })}
}

type Collector struct {
	Config Config
	Runner Runner
}
type Collection struct {
	Resource string `json:"resource"`
	Status   string `json:"status"`
	Detail   string `json:"detail,omitempty"`
}
type Snapshot struct {
	ID          string                        `json:"snapshot_id"`
	Namespace   string                        `json:"namespace"`
	Pod         string                        `json:"pod"`
	CollectedAt string                        `json:"collected_at"`
	Dump        diagnostics.Object            `json:"config_dump"`
	Resources   map[string]diagnostics.Object `json:"resources"`
	Collection  []Collection                  `json:"collection"`
}

var dnsName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

func (c Collector) authorize(ns string) error {
	if !c.Config.Enabled {
		return errors.New("live collection is disabled; set ISTIO_DIAG_ENABLE_LIVE=true")
	}
	if c.Config.Context == "" {
		return errors.New("ISTIO_DIAG_CONTEXT must explicitly select a Kubernetes context")
	}
	if !dnsName.MatchString(ns) || len(ns) > 63 || strings.Contains(ns, ".") {
		return errors.New("invalid namespace")
	}
	for _, n := range c.Config.Namespaces {
		if strings.TrimSpace(n) == ns {
			return nil
		}
	}
	return fmt.Errorf("namespace %q is not in ISTIO_DIAG_NAMESPACES", ns)
}
func (c Collector) get(ctx context.Context, ns, resource, n string) (diagnostics.Object, error) {
	args := []string{"--context=" + c.Config.Context, "--namespace=" + ns, "get", resource}
	if n != "" {
		args = append(args, n)
	}
	args = append(args, "-o", "json", "--request-timeout=15s")
	b, err := c.Runner.Run(ctx, "kubectl", args...)
	if err != nil {
		return nil, err
	}
	var o diagnostics.Object
	if err = json.Unmarshal(b, &o); err != nil {
		return nil, fmt.Errorf("invalid JSON for %s", resource)
	}
	return o, nil
}

var resources = []string{"services", "endpointslices.discovery.k8s.io", "networkpolicies.networking.k8s.io", "virtualservices.networking.istio.io", "destinationrules.networking.istio.io", "serviceentries.networking.istio.io", "gateways.networking.istio.io", "sidecars.networking.istio.io", "authorizationpolicies.security.istio.io", "peerauthentications.security.istio.io", "requestauthentications.security.istio.io"}

func (c Collector) Collect(ctx context.Context, ns, pod string) (Snapshot, error) {
	s := Snapshot{Namespace: ns, Pod: pod, CollectedAt: time.Now().UTC().Format(time.RFC3339Nano), Resources: map[string]diagnostics.Object{}, Collection: []Collection{}}
	if err := c.authorize(ns); err != nil {
		return s, err
	}
	if !dnsName.MatchString(pod) || len(pod) > 253 {
		return s, errors.New("invalid pod name")
	}
	p, err := c.get(ctx, ns, "pods", pod)
	if err != nil {
		return s, err
	}
	// Keep only fields needed for diagnosis; Pod specs can contain plaintext credentials.
	s.Resources["pod"] = podSummary(p)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 3)
	for _, resource := range resources {
		wg.Add(1)
		go func(resource string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			o, e := c.get(ctx, ns, resource, "")
			entry := Collection{Resource: resource, Status: "PASS"}
			if e != nil {
				entry.Status = "UNKNOWN"
				entry.Detail = e.Error()
			}
			mu.Lock()
			defer mu.Unlock()
			s.Collection = append(s.Collection, entry)
			if e == nil {
				s.Resources[resource] = diagnostics.Redact(o).(map[string]any)
			}
		}(resource)
	}
	wg.Wait()
	b, e := c.Runner.Run(ctx, "istioctl", "--context="+c.Config.Context, "proxy-config", "all", pod, "--namespace="+ns, "-o", "json")
	entry := Collection{Resource: "config_dump", Status: "PASS"}
	if e != nil {
		entry.Status = "UNKNOWN"
		entry.Detail = e.Error()
	} else {
		var raw diagnostics.Object
		if json.Unmarshal(b, &raw) != nil {
			entry.Status = "UNKNOWN"
			entry.Detail = "istioctl returned invalid JSON"
		} else {
			s.Dump = diagnostics.Redact(raw).(map[string]any)
		}
	}
	s.Collection = append(s.Collection, entry)
	sort.Slice(s.Collection, func(i, j int) bool { return s.Collection[i].Resource < s.Collection[j].Resource })
	identity, _ := json.Marshal(s)
	sum := sha256.Sum256(identity)
	s.ID = hex.EncodeToString(sum[:12])
	return s, nil
}

func podSummary(o diagnostics.Object) diagnostics.Object {
	meta, _ := o["metadata"].(map[string]any)
	spec, _ := o["spec"].(map[string]any)
	return diagnostics.Object{"apiVersion": "v1", "kind": "Pod", "metadata": diagnostics.Object{"name": meta["name"], "namespace": meta["namespace"], "uid": meta["uid"], "labels": meta["labels"], "ownerReferences": meta["ownerReferences"]}, "spec": diagnostics.Object{"nodeName": spec["nodeName"], "serviceAccountName": spec["serviceAccountName"], "hostNetwork": spec["hostNetwork"]}, "status": o["status"]}
}

// Resolve returns exact pod matches or pods belonging to a Deployment/StatefulSet/DaemonSet.
// ReplicaSet-to-Deployment ownership is followed explicitly, never inferred from a name prefix.
func (c Collector) Resolve(ctx context.Context, ns, workload string) ([]diagnostics.Object, error) {
	if err := c.authorize(ns); err != nil {
		return nil, err
	}
	if !dnsName.MatchString(workload) || len(workload) > 253 {
		return nil, errors.New("invalid workload name")
	}
	pods, err := c.get(ctx, ns, "pods", "")
	if err != nil {
		return nil, err
	}
	rs, rsErr := c.get(ctx, ns, "replicasets.apps", "")
	rsOwners := map[string]string{}
	if rsErr == nil {
		for _, v := range list(rs) {
			o := asObject(v)
			m := asObject(o["metadata"])
			for _, v := range asList(m["ownerReferences"]) {
				owner := asObject(v)
				if owner["kind"] == "Deployment" {
					rsOwners[fmt.Sprint(m["name"])] = fmt.Sprint(owner["name"])
				}
			}
		}
	}
	out := []diagnostics.Object{}
	for _, v := range list(pods) {
		p := asObject(v)
		m := asObject(p["metadata"])
		match := m["name"] == workload
		for _, v := range asList(m["ownerReferences"]) {
			o := asObject(v)
			if o["name"] == workload {
				match = true
			}
			if o["kind"] == "ReplicaSet" && rsOwners[fmt.Sprint(o["name"])] == workload {
				match = true
			}
		}
		if match {
			out = append(out, podSummary(p))
		}
	}
	if len(out) == 0 && rsErr != nil {
		return nil, fmt.Errorf("no exact workload match; ReplicaSet ownership lookup unavailable: %w", rsErr)
	}
	return out, nil
}
func asObject(v any) diagnostics.Object {
	o, _ := v.(map[string]any)
	if o == nil {
		return diagnostics.Object{}
	}
	return o
}
func asList(v any) []any              { a, _ := v.([]any); return a }
func list(o diagnostics.Object) []any { return asList(o["items"]) }
