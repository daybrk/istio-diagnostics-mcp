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
func TestScopeCannotExpand(t *testing.T) {
	p := Principal{ID: "a", Scopes: []Scope{{Context: "c", Namespaces: []string{"a"}}}}
	if p.Allows("c", "b") || !p.Allows("c", "a") {
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
