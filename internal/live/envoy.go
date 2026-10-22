package live

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
)

var forwardingLine = regexp.MustCompile(`^Forwarding from 127\.0\.0\.1:([0-9]+) -> 15000$`)

type tunnel struct {
	process   process
	address   string
	closeOnce sync.Once
	cancel    context.CancelFunc
	drainDone chan struct{}
}

func (t *tunnel) Close() { t.closeOnce.Do(func() { t.cancel(); _ = t.process.Close(); <-t.drainDone }) }
func (c *Collector) openTunnel(ctx context.Context, ref core.WorkloadRef) (*tunnel, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	child, cancel := context.WithCancel(ctx)
	args := append(c.base(ref.Context, ref.Namespace), "port-forward", "--address=127.0.0.1", "pod/"+ref.Name, ":15000")
	p, e := c.runner.Start(child, args)
	if e != nil {
		cancel()
		return nil, e
	}
	t := &tunnel{process: p, cancel: cancel, drainDone: make(chan struct{})}
	ready := make(chan string, 1)
	failed := make(chan error, 1)
	go func() {
		defer close(t.drainDone)
		scanner := bufio.NewScanner(p.Output())
		scanner.Buffer(make([]byte, 4096), 64<<10)
		for scanner.Scan() {
			match := forwardingLine.FindStringSubmatch(scanner.Text())
			if len(match) == 2 {
				port, e := strconv.Atoi(match[1])
				if e == nil && port > 0 && port <= 65535 {
					select {
					case ready <- net.JoinHostPort("127.0.0.1", match[1]):
					default:
					}
				}
			}
		}
		e := scanner.Err()
		if e == nil {
			e = errors.New("port-forward closed before becoming ready")
		}
		select {
		case failed <- e:
		default:
		}
	}()
	timer := time.NewTimer(time.Duration(c.cfg.Limits.RequestTimeoutSeconds) * time.Second)
	defer timer.Stop()
	select {
	case address := <-ready:
		t.address = address
		return t, nil
	case e := <-failed: // The process may emit readiness and immediately finish its output; consume readiness first.
		select {
		case address := <-ready:
			t.address = address
			return t, nil
		default:
		}
		t.Close()
		return nil, e
	case e := <-p.Done():
		t.Close()
		if e == nil {
			e = errors.New("port-forward exited")
		}
		return nil, e
	case <-ctx.Done():
		t.Close()
		return nil, ctx.Err()
	case <-timer.C:
		t.Close()
		return nil, context.DeadlineExceeded
	}
}

var adminEndpoints = []struct{ source, path string }{{"config_dump", "/config_dump?include_eds"}, {"certs", "/certs"}, {"clusters", "/clusters?format=json"}, {"server_info", "/server_info"}}

func (c *Collector) collectEnvoy(ctx context.Context, ref core.WorkloadRef) (map[string]json.RawMessage, []core.CoverageEntry) {
	data := map[string]json.RawMessage{}
	entries := []core.CoverageEntry{}
	failAll := func(e error) (map[string]json.RawMessage, []core.CoverageEntry) {
		v := []core.CoverageEntry{}
		for _, ep := range adminEndpoints {
			v = append(v, coverage(ref, ep.source, status(e), safeError(e)))
		}
		return map[string]json.RawMessage{}, v
	}
	select {
	case c.tunnelSlots <- struct{}{}:
		defer func() { <-c.tunnelSlots }()
	case <-ctx.Done():
		return failAll(ctx.Err())
	}
	if e := c.verifyUID(ctx, ref); e != nil {
		return failAll(e)
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	t, e := c.openTunnel(child, ref)
	if e != nil {
		return failAll(e)
	}
	defer t.Close()
	// A bounded background identity check also cancels a response blocked in Read.
	identityFailure := make(chan error, 1)
	identityError := func(fallback error) error {
		select {
		case e := <-identityFailure:
			return e
		default:
			return fallback
		}
	}
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-child.Done():
				return
			case <-ticker.C:
				if e := c.verifyUID(child, ref); e != nil {
					select {
					case identityFailure <- e:
					default:
					}
					cancel()
					return
				}
			case <-t.process.Done():
				select {
				case identityFailure <- errors.New("port-forward process exited"):
				default:
				}
				cancel()
				return
			}
		}
	}()
	defer func() { cancel(); <-monitorDone }()
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Duration(c.cfg.Limits.RequestTimeoutSeconds) * time.Second}).DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Duration(c.cfg.Limits.RequestTimeoutSeconds) * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, ep := range adminEndpoints {
		if e := c.verifyUID(child, ref); e != nil {
			return failAll(identityError(e))
		}
		body, st, detail := c.readAdmin(child, client, t.address, ep.path)
		entries = append(entries, coverage(ref, ep.source, st, detail))
		if body != nil {
			data[ep.source] = body
		}
		if e := c.verifyUID(child, ref); e != nil {
			return failAll(identityError(e))
		}
	}
	select {
	case e := <-identityFailure:
		return failAll(e)
	default:
	}
	return data, entries
}
func (c *Collector) readAdmin(ctx context.Context, client *http.Client, address, path string) (json.RawMessage, string, string) {
	for attempt := 0; attempt < 2; attempt++ {
		if e := ctx.Err(); e != nil {
			return nil, status(e), safeError(e)
		}
		request, e := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+path, nil)
		if e != nil {
			return nil, "unavailable", "Cannot create the fixed Envoy request"
		}
		response, e := client.Do(request)
		if e != nil {
			if attempt == 0 && transient("", e) {
				continue
			}
			return nil, status(e), safeError(e)
		}
		if response.StatusCode != http.StatusOK {
			code := response.StatusCode
			_ = response.Body.Close()
			if attempt == 0 && (code == 429 || code == 502 || code == 503 || code == 504) {
				continue
			}
			if code == 404 || code == 405 {
				return nil, "unsupported", fmt.Sprintf("Envoy endpoint returned HTTP %d", code)
			}
			return nil, "unavailable", fmt.Sprintf("Envoy endpoint returned HTTP %d; redirects are disabled", code)
		}
		body, e := io.ReadAll(io.LimitReader(response.Body, int64(c.cfg.Limits.MaxEnvoyResponseBytes)+1))
		_ = response.Body.Close()
		if len(body) > c.cfg.Limits.MaxEnvoyResponseBytes {
			return nil, "truncated", "Envoy response exceeded its byte limit; incomplete JSON was discarded"
		}
		if e != nil {
			if attempt == 0 && transient("", e) {
				continue
			}
			return nil, status(e), safeError(e)
		}
		var value any
		if e = json.Unmarshal(body, &value); e != nil {
			return nil, "unavailable", "Envoy returned malformed or unsupported non-JSON content"
		}
		clean, e := json.Marshal(core.RedactObject(value))
		if e != nil {
			return nil, "unavailable", "Envoy response could not be sanitized"
		}
		return clean, "collected", "Fixed Envoy admin endpoint collected with verified pod UID"
	}
	return nil, "unavailable", "Envoy endpoint remains unavailable after one bounded retry"
}
