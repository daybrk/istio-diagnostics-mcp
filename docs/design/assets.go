// Package design embeds the versioned public contracts and agent playbooks.
package design

import (
	"embed"
	"encoding/json"
	"fmt"
	"github.com/google/jsonschema-go/jsonschema"
	"strings"
	"sync"
)

//go:embed contracts/*.json prompts/*.md prompts/*.json prompts/integrations/*.md
var Files embed.FS

const Version = "2026-10-22"
const PromptVersion = "2026-10-23.1"

var once sync.Once
var compiled map[string]*jsonschema.Resolved
var initializationError error
var schema map[string]any

func initialize() {
	compiled = map[string]*jsonschema.Resolved{}
	b, e := Files.ReadFile("contracts/mcp.schema.json")
	if e != nil {
		initializationError = e
		return
	}
	if e = json.Unmarshal(b, &schema); e != nil {
		initializationError = e
		return
	}
	for n := range schema["$defs"].(map[string]any) {
		if len(n) < 5 {
			continue
		}
		if n[len(n)-5:] != "Input" && (len(n) < 6 || n[len(n)-6:] != "Output") {
			continue
		}
		v := map[string]any{"$defs": schema["$defs"], "$ref": "#/$defs/" + n}
		if e = compile(n, v); e != nil {
			initializationError = e
			return
		}
	}
	b, e = Files.ReadFile("contracts/config.schema.json")
	if e != nil {
		initializationError = e
		return
	}
	var v any
	if e = json.Unmarshal(b, &v); e != nil {
		initializationError = e
		return
	}
	initializationError = compile("config", v)
}
func compile(n string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	var s jsonschema.Schema
	if e = json.Unmarshal(b, &s); e != nil {
		return e
	}
	r, e := s.Resolve(&jsonschema.ResolveOptions{ValidateDefaults: true})
	if e == nil {
		compiled[n] = r
	}
	return e
}
func Validate(name string, v any) error {
	once.Do(initialize)
	if initializationError != nil {
		return initializationError
	}
	r := compiled[name]
	if r == nil {
		return fmt.Errorf("unknown schema %s", name)
	}
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	var j any
	if e = json.Unmarshal(b, &j); e != nil {
		return e
	}
	return r.Validate(j)
}
func ToolSchema(name string) map[string]any {
	once.Do(initialize)
	if strings.HasSuffix(name, "Input") {
		return clientInputSchema(name)
	}
	// Ship only the transitive definitions this tool uses. Clients receive a
	// self-contained schema without repeating the entire catalog 22 times.
	all := schema["$defs"].(map[string]any)
	defs := map[string]any{}
	var visit func(any)
	visit = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if ref, ok := x["$ref"].(string); ok && strings.HasPrefix(ref, "#/$defs/") {
				key := strings.TrimPrefix(ref, "#/$defs/")
				if _, seen := defs[key]; !seen {
					defs[key] = all[key]
					visit(all[key])
				}
			}
			for _, child := range x {
				visit(child)
			}
		case []any:
			for _, child := range x {
				visit(child)
			}
		}
	}
	root := map[string]any{"type": "object", "$ref": "#/$defs/" + name}
	visit(root)
	root["$defs"] = defs
	return root
}
