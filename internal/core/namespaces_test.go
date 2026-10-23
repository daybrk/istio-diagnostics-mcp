package core

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestConfigWithoutNamespaceAllowlist(t *testing.T) {
	b, err := os.ReadFile("../../docs/design/examples/server-config.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, legacy := range []bool{false, true} {
		var raw map[string]any
		if err := json.Unmarshal(b, &raw); err != nil {
			t.Fatal(err)
		}
		scope := map[string]any{"context": "test-cluster"}
		if legacy {
			scope["namespaces"] = []string{"old-only"}
		}
		raw["kube"].(map[string]any)["contexts"] = []any{scope}
		encoded, _ := json.Marshal(raw)
		cfg, err := ParseConfig(encoded)
		if err != nil {
			t.Fatalf("legacy=%v: %v", legacy, err)
		}
		if legacy != (len(cfg.Warnings) > 0) {
			t.Fatalf("legacy=%v warnings=%v", legacy, cfg.Warnings)
		}
		want := []Scope{{Context: "test-cluster", Namespaces: []string{"*"}}}
		if !reflect.DeepEqual(cfg.LocalPrincipal().Scopes, want) {
			t.Fatalf("legacy=%v: scopes=%+v", legacy, cfg.LocalPrincipal().Scopes)
		}
	}
}

func TestContextIntersectionIgnoresLegacyNamespaceLists(t *testing.T) {
	a := []Scope{{Context: "cluster", Namespaces: []string{"app"}}, {Context: "other"}}
	b := []Scope{{Context: "cluster", Namespaces: []string{"default", "istio-system"}}}
	want := []Scope{{Context: "cluster", Namespaces: []string{"*"}}}
	if got := IntersectScopes(a, b); !reflect.DeepEqual(got, want) {
		t.Fatalf("intersection=%+v", got)
	}
}
