package main

import (
	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
	"testing"
)

func TestRemoteListenerNeedsTLS(t *testing.T) {
	cfg := core.Config{Transport: "streamable_http", HTTP: &core.HTTPConfig{Listen: "0.0.0.0:8080"}}
	if err := validateListener(cfg, "", ""); err == nil {
		t.Fatal("public plaintext listener accepted")
	}
	cfg.HTTP.Listen = "127.0.0.1:8080"
	if err := validateListener(cfg, "", ""); err != nil {
		t.Fatal(err)
	}
	cfg.HTTP.Listen = "[::1]:8080"
	if err := validateListener(cfg, "", ""); err != nil {
		t.Fatal(err)
	}
	cfg.HTTP.Listen = "0.0.0.0:8443"
	if err := validateListener(cfg, "cert.pem", "key.pem"); err != nil {
		t.Fatal(err)
	}
}
