package core

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWindowFrozenAndFutureRejected(t *testing.T) {
	now := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)
	w, e := ResolveWindow(nil, now)
	if e != nil || w.Start != "2026-10-22T09:45:00Z" || w.End != "2026-10-22T10:00:00Z" {
		t.Fatalf("%+v %v", w, e)
	}
	_, e = ResolveWindow(&TimeWindow{Start: "2026-10-22T09:00:00Z", End: "2026-10-22T11:00:00Z"}, now)
	if e == nil {
		t.Fatal("accepted future end")
	}
}
func TestContextScopeCannotExpand(t *testing.T) {
	p := Principal{ID: "a", Scopes: []Scope{{Context: "c", Namespaces: []string{"a"}}}}
	if p.AllowsContext("other") || !p.AllowsContext("c") {
		t.Fatal("scope mismatch")
	}
}
func TestConfigStrict(t *testing.T) {
	b, e := os.ReadFile("../../docs/design/examples/server-config.json")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ParseConfig(b); e != nil {
		t.Fatal(e)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	m["exec"] = true
	b, _ = json.Marshal(m)
	if _, e = ParseConfig(b); e == nil {
		t.Fatal("accepted unknown option")
	}
}
func TestRedactQuotedSecretsAndCookies(t *testing.T) {
	for _, raw := range []string{`{"password":"first second"}`, `cookie: sid=abc; preference=secret`, `{"client_secret": "with spaces and escaped \"quotes\""}`} {
		got := RedactString(raw)
		for _, secret := range []string{"second", "preference=secret", "with spaces", "quotes"} {
			if strings.Contains(got, secret) {
				t.Fatalf("secret fragment remained: %s", got)
			}
		}
	}
}

func TestAstraConfigAcceptsUserChosenProject(t *testing.T) {
	b, _ := os.ReadFile("../../docs/design/examples/server-config.json")
	var v map[string]any
	json.Unmarshal(b, &v)
	v["astra"] = map[string]any{"agent_url": "https://astra.example/mcp/agent", "credential_env": "ASTRA_KEY"}
	b, _ = json.Marshal(v)
	if _, err := ParseConfig(b); err != nil {
		t.Fatalf("endpoint and credential should suffice: %v", err)
	}
	delete(v, "astra")
	b, _ = json.Marshal(v)
	if _, err := ParseConfig(b); err != nil {
		t.Fatalf("core diagnostics should not require ASTRA config: %v", err)
	}
}
