package design

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
)

func TestEmbeddedContractCases(t *testing.T) {
	b, e := os.ReadFile("examples/tool-cases.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Cases []struct {
			Name          string `json:"case"`
			Tool          string `json:"tool"`
			Input, Output any
			InputValid    bool `json:"input_valid"`
			OutputValid   bool `json:"output_valid"`
		} `json:"cases"`
	}
	if e = json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if e := Validate(c.Tool+"Input", c.Input); (e == nil) != c.InputValid {
				t.Fatalf("input: %v", e)
			}
			// Native-object examples must retain their constraints after discovery
			// references are inlined and compatibility alternatives are added.
			b, e := json.Marshal(ToolSchema(c.Tool + "Input"))
			if e != nil {
				t.Fatal(e)
			}
			var s jsonschema.Schema
			if e = json.Unmarshal(b, &s); e != nil {
				t.Fatal(e)
			}
			r, e := s.Resolve(nil)
			if e != nil {
				t.Fatal(e)
			}
			if e = r.Validate(c.Input); (e == nil) != c.InputValid {
				t.Fatalf("client input: %v", e)
			}
			if c.Output != nil {
				if e := Validate(c.Tool+"Output", c.Output); (e == nil) != c.OutputValid {
					t.Fatalf("output: %v", e)
				}
			}
		})
	}
}
func TestEmbeddedPromptHashes(t *testing.T) {
	b, _ := Files.ReadFile("prompts/manifest.json")
	var m struct {
		Bundle   string `json:"bundle_version"`
		Contract string `json:"contract_version"`
		Modules  []struct{ Path, SHA256, Version string }
	}
	if e := json.Unmarshal(b, &m); e != nil {
		t.Fatal(e)
	}
	if m.Bundle != PromptVersion || m.Contract != Version {
		t.Fatalf("stale manifest: %+v", m)
	}
	if len(m.Modules) != 7 {
		t.Fatal("missing modules")
	}
	for _, module := range m.Modules {
		if module.Version != PromptVersion {
			t.Fatalf("stale module version: %+v", module)
		}
		b, e := Files.ReadFile("prompts/" + module.Path)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != module.SHA256 {
			t.Fatalf("hash mismatch %s", module.Path)
		}
	}
}
func TestDiscoveryFitsDefaultResponseBudget(t *testing.T) {
	b, _ := Files.ReadFile("contracts/mcp-tools.json")
	var catalog struct{ Tools []struct{ Name string } }
	json.Unmarshal(b, &catalog)
	schemas := []any{}
	for _, tool := range catalog.Tools {
		schemas = append(schemas, ToolSchema(tool.Name+"Input"), ToolSchema(tool.Name+"Output"))
	}
	encoded, _ := json.Marshal(schemas)
	if len(encoded) > 524288 {
		t.Fatalf("tool discovery exceeds default response budget: %d bytes", len(encoded))
	}
}
