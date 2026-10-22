package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/daybrk/istio-diagnostics-mcp/internal/diagnostics"
	"github.com/daybrk/istio-diagnostics-mcp/internal/live"
	"github.com/daybrk/istio-diagnostics-mcp/internal/server"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run() error {
	mode := flag.String("mode", "serve", "serve (MCP stdio), analyze, trace, or tls")
	dumpPath := flag.String("dump", "", "Config dump JSON file for offline CLI modes")
	requestPath := flag.String("request", "", "Connection request JSON file for trace")
	at := flag.String("at", "", "RFC3339 certificate evaluation time (defaults to now)")
	version := flag.Bool("version", false, "Print version")
	flag.Parse()
	if *version {
		fmt.Println(server.Version)
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if *mode == "serve" {
		c := live.Collector{Config: live.FromEnv(), Runner: live.ExecRunner{}}
		return server.New(c).Run(ctx, &mcp.StdioTransport{})
	}
	var raw diagnostics.Object
	if err := readJSON(*dumpPath, &raw); err != nil {
		return err
	}
	now := time.Now().UTC()
	if *at != "" {
		var err error
		now, err = time.Parse(time.RFC3339, *at)
		if err != nil {
			return err
		}
	}
	var r diagnostics.Report
	var err error
	switch *mode {
	case "analyze":
		r, err = diagnostics.Analyze(raw, now)
	case "tls":
		r, err = diagnostics.InspectTLS(raw, now)
	case "trace":
		var q diagnostics.Request
		if err = readJSON(*requestPath, &q); err == nil {
			r, err = diagnostics.Trace(raw, q, now)
		}
	default:
		return fmt.Errorf("unsupported mode %q", *mode)
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}
func readJSON(path string, out any) error {
	if path == "" {
		return fmt.Errorf("JSON file path is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (20<<20)+1))
	if err != nil {
		return err
	}
	if len(b) > 20<<20 {
		return fmt.Errorf("input exceeds 20 MiB")
	}
	return json.Unmarshal(b, out)
}
