// Command istio-diagnostics-mcp runs the live, read-only MCP server.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/daybrk/istio-diagnostics-mcp/internal/astra"
	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
	"github.com/daybrk/istio-diagnostics-mcp/internal/diagnostics"
	"github.com/daybrk/istio-diagnostics-mcp/internal/engine"
	"github.com/daybrk/istio-diagnostics-mcp/internal/live"
	"github.com/daybrk/istio-diagnostics-mcp/internal/transport"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var version = "0.1.0-live"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, core.RedactString(err.Error()))
		os.Exit(1)
	}
}
func run() error {
	var path, cert, key string
	var showVersion, check bool
	flag.StringVar(&path, "config", "", "Path to the server JSON configuration")
	flag.StringVar(&cert, "tls-cert", "", "TLS certificate for a remote HTTP listener")
	flag.StringVar(&key, "tls-key", "", "TLS private key for a remote HTTP listener")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")
	flag.BoolVar(&check, "check-config", false, "Validate configuration and exit without network access")
	flag.Parse()
	if showVersion {
		fmt.Println(version)
		return nil
	}
	if path == "" {
		return fmt.Errorf("-config is required; see docs/design/examples/server-config.json")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read configuration: %w", err)
	}
	cfg, err := core.ParseConfig(b)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	if err = validateListener(cfg, cert, key); err != nil {
		return err
	}
	if check {
		fmt.Fprintln(os.Stderr, "Configuration is valid; no live connections were attempted.")
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	eng := engine.New(cfg, live.New(cfg), astra.New(cfg), diagnostics.Analyze, diagnostics.SupportedChecks())
	defer eng.Close()
	handler := loggingHandler{next: eng, logger: slog.New(slog.NewJSONHandler(os.Stderr, nil))}
	if cfg.Transport == "stdio" {
		err = transport.NewServer(handler, cfg).Run(ctx, &mcp.StdioTransport{MaxLineLength: 1 << 20})
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	h, err := transport.HTTPHandler(handler, cfg)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", h)
	srv := &http.Server{Addr: cfg.HTTP.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	done := make(chan error, 1)
	go func() {
		if cert != "" {
			done <- srv.ListenAndServeTLS(cert, key)
		} else {
			done <- srv.ListenAndServe()
		}
	}()
	select {
	case err = <-done:
	case <-ctx.Done():
		shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if e := srv.Shutdown(shutdown); e != nil {
			_ = srv.Close()
		}
		err = <-done
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func validateListener(c core.Config, cert, key string) error {
	if (cert == "") != (key == "") {
		return fmt.Errorf("-tls-cert and -tls-key must be provided together")
	}
	if c.Transport != "streamable_http" {
		return nil
	}
	if c.HTTP == nil {
		return fmt.Errorf("HTTP configuration is required")
	}
	host, _, err := net.SplitHostPort(c.HTTP.Listen)
	if err != nil {
		return fmt.Errorf("http.listen must be host:port")
	}
	ip := net.ParseIP(host)
	if cert == "" && host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("non-loopback HTTP listener requires -tls-cert and -tls-key; use loopback only behind a local TLS reverse proxy")
	}
	return nil
}

type loggingHandler struct {
	next   core.Handler
	logger *slog.Logger
}

func (h loggingHandler) Call(ctx context.Context, p core.Principal, name string, args json.RawMessage) (core.Envelope, error) {
	start := time.Now()
	r, err := h.next.Call(ctx, p, name, args)
	sum := sha256.Sum256([]byte(p.ID))
	status := r.Outcome
	if err != nil {
		status = "protocol_error"
	}
	h.logger.Info("mcp_tool", "request_id", core.NewID("request"), "tool", name, "principal", hex.EncodeToString(sum[:8]), "duration_ms", time.Since(start).Milliseconds(), "outcome", status)
	return r, err
}
