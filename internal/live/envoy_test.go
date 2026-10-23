package live

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
)

func tunnelFixture(t *testing.T, handler http.HandlerFunc) (*Collector, *fakeRunner, *fakeProcess, core.WorkloadRef) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	f := fixture()
	process := &fakeProcess{reader: io.NopCloser(strings.NewReader(fmt.Sprintf("Forwarding from %s -> 15000\n", strings.TrimPrefix(server.URL, "http://")))), done: make(chan error, 1)}
	f.process = process
	c := testCollector(f)
	return c, f, process, core.WorkloadRef{Context: "cluster", Namespace: "app", Kind: "Pod", Name: "shop-old-a", UID: "p1"}
}
func TestEnvoyUsesOnlyFixedEndpointsAndClosesTunnel(t *testing.T) {
	var mu sync.Mutex
	paths := []string{}
	c, _, p, ref := tunnelFixture(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.RequestURI())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"LIVE","token":"secret"}`)
	})
	data, entries := c.collectEnvoy(context.Background(), ref)
	if len(data) != 4 || len(entries) != 4 {
		t.Fatalf("data=%v coverage=%+v", data, entries)
	}
	want := []string{"/config_dump?include_eds", "/certs", "/clusters?format=json", "/server_info"}
	for i, path := range want {
		if paths[i] != path {
			t.Errorf("request=%q want=%q", paths[i], path)
		}
	}
	for _, v := range data {
		if strings.Contains(string(v), "secret") {
			t.Fatal("raw token in Envoy")
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		t.Fatal("tunnel not closed")
	}
}
func TestEnvoyRejectsRedirectsAndOversizedJSON(t *testing.T) {
	c, _, _, ref := tunnelFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config_dump" {
			http.Redirect(w, r, "http://192.0.2.1:15000/secrets", http.StatusFound)
			return
		}
		fmt.Fprint(w, `{"huge":"`+strings.Repeat("x", 5000)+`"}`)
	})
	data, entries := c.collectEnvoy(context.Background(), ref)
	if len(data) > 0 {
		t.Fatal("invalid endpoint data retained")
	}
	truncated := 0
	for _, e := range entries {
		if e.Status == "truncated" {
			truncated++
		}
	}
	if truncated != 3 {
		t.Fatalf("entries=%+v", entries)
	}
}
func TestEnvoyUIDReplacementDiscardsSnapshotAndCloses(t *testing.T) {
	var f *fakeRunner
	c, runner, p, ref := tunnelFixture(t, func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		meta(f.objects["pods"][0])["uid"] = "replacement"
		f.mu.Unlock()
		fmt.Fprint(w, `{}`)
	})
	f = runner
	data, entries := c.collectEnvoy(context.Background(), ref)
	if len(data) != 0 {
		t.Fatal("replacement UID data retained")
	}
	for _, e := range entries {
		if e.Status != "unavailable" {
			t.Fatalf("entry=%+v", e)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		t.Fatal("replacement tunnel not closed")
	}
}
func TestTunnelCancellationClosesUnreadyProcess(t *testing.T) {
	f := fixture()
	read, write := io.Pipe()
	defer write.Close()
	p := &fakeProcess{reader: read, done: make(chan error, 1)}
	f.process = p
	c := testCollector(f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.onStart = func(args []string) {
		for _, want := range []string{"--kubeconfig=/selected/kubeconfig", "--context=cluster", "--namespace=app", "--address=127.0.0.1", "pod/shop-old-a", ":15000"} {
			if !has(args, want) {
				t.Errorf("missing %s in tunnel argv %v", want, args)
			}
		}
		go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	}
	_, e := c.openTunnel(ctx, core.WorkloadRef{Context: "cluster", Namespace: "app", Kind: "Pod", Name: "shop-old-a", UID: "p1"})
	if e == nil {
		t.Fatal("cancelled tunnel started")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		t.Fatal("unready tunnel was not closed on cancellation")
	}
}

func TestUIDMonitorCancelsBlockedHTTPAndRejectsAttribution(t *testing.T) {
	var f *fakeRunner
	c, runner, p, ref := tunnelFixture(t, func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		meta(f.objects["pods"][0])["uid"] = "replacement"
		f.mu.Unlock()
		<-r.Context().Done()
	})
	f = runner
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	data, entries := c.collectEnvoy(ctx, ref)
	if len(data) != 0 {
		t.Fatal("data kept after UID changed")
	}
	for _, entry := range entries {
		if entry.Status != "unavailable" || !strings.Contains(entry.Detail, "UID") {
			t.Fatalf("identity error obscured: %+v", entry)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		t.Fatal("blocked tunnel was not closed")
	}
}
