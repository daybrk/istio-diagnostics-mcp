//go:build ignore

// Run from the repository root: go run docs/design/validate_contracts.go
// This validates design artifacts, not a live implementation.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
)

const root = "docs/design"

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(path string) []byte {
	b, err := os.ReadFile(path)
	must(err)
	return b
}
func decode(path string, value any) { must(json.Unmarshal(read(path), value)) }
func check(ok bool, message string) {
	if !ok {
		panic(message)
	}
}
func resolve(value any) *jsonschema.Resolved {
	b, err := json.Marshal(value)
	must(err)
	var schema jsonschema.Schema
	must(json.Unmarshal(b, &schema))
	rs, err := schema.Resolve(&jsonschema.ResolveOptions{ValidateDefaults: true})
	must(err)
	return rs
}

func main() {
	var schema map[string]any
	decode(root+"/contracts/mcp.schema.json", &schema)
	var catalog struct {
		Version string `json:"contract_version"`
		Tools   []struct {
			Name   string            `json:"name"`
			Input  map[string]string `json:"inputSchema"`
			Output map[string]string `json:"outputSchema"`
		} `json:"tools"`
	}
	decode(root+"/contracts/mcp-tools.json", &catalog)
	check(catalog.Version == schema["x-contract-version"], "Contract version mismatch")
	inputs, outputs := map[string]*jsonschema.Resolved{}, map[string]*jsonschema.Resolved{}
	apiText := string(read(root + "/api.md"))
	for _, tool := range catalog.Tools {
		check(inputs[tool.Name] == nil, "Duplicate tool "+tool.Name)
		check(strings.Contains(apiText, "`"+tool.Name+"`"), "Tool absent from API prose: "+tool.Name)
		for _, pair := range []struct {
			target  map[string]*jsonschema.Resolved
			pointer string
		}{
			{inputs, tool.Input["$ref"]}, {outputs, tool.Output["$ref"]},
		} {
			check(strings.HasPrefix(pair.pointer, "mcp.schema.json#/$defs/"), "Unexpected schema pointer")
			pair.target[tool.Name] = resolve(map[string]any{"$schema": schema["$schema"], "$defs": schema["$defs"], "$ref": strings.TrimPrefix(pair.pointer, "mcp.schema.json")})
		}
	}
	var cases struct {
		Version string `json:"contract_version"`
		Cases   []struct {
			Name        string `json:"case"`
			Tool        string `json:"tool"`
			Input       any    `json:"input"`
			Output      any    `json:"output"`
			InputValid  bool   `json:"input_valid"`
			OutputValid bool   `json:"output_valid"`
		} `json:"cases"`
	}
	decode(root+"/examples/tool-cases.json", &cases)
	check(cases.Version == catalog.Version, "Example version mismatch")
	seen := map[string]bool{}
	for _, c := range cases.Cases {
		check(inputs[c.Tool] != nil, "Unknown tool in "+c.Name)
		seen[c.Tool] = true
		err := inputs[c.Tool].Validate(c.Input)
		check((err == nil) == c.InputValid, fmt.Sprintf("%s input: expected valid=%v, got %v", c.Name, c.InputValid, err))
		if c.Output != nil {
			err = outputs[c.Tool].Validate(c.Output)
			check((err == nil) == c.OutputValid, fmt.Sprintf("%s output: expected valid=%v, got %v", c.Name, c.OutputValid, err))
			if c.OutputValid {
				checkTimeWindows(c.Output)
			}
		}
	}
	check(len(seen) == len(catalog.Tools), "Every tool must have an example")
	var exchange struct {
		Response struct {
			Result struct {
				Structured any `json:"structuredContent"`
				Content    []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		} `json:"response"`
	}
	decode(root+"/examples/mcp-exchange.json", &exchange)
	check(len(exchange.Response.Result.Content) == 1, "Expected one compatibility text block")
	var textResult any
	must(json.Unmarshal([]byte(exchange.Response.Result.Content[0].Text), &textResult))
	a, err := json.Marshal(exchange.Response.Result.Structured)
	must(err)
	b, err := json.Marshal(textResult)
	must(err)
	check(string(a) == string(b), "structuredContent/text mismatch")
	must(outputs["get_capabilities"].Validate(textResult))
	var configSchema, configExample any
	decode(root+"/contracts/config.schema.json", &configSchema)
	decode(root+"/examples/server-config.json", &configExample)
	configValidator := resolve(configSchema)
	must(configValidator.Validate(configExample))
	var astraExample any
	decode(root+"/examples/server-config-astra.json", &astraExample)
	must(configValidator.Validate(astraExample))
	// Missing remote authentication and enabled ASTRA without its configuration
	// must fail rather than silently selecting a permissive setup.
	for _, mode := range []string{"http-no-auth", "astra-no-config"} {
		b, err := json.Marshal(configExample)
		must(err)
		var bad map[string]any
		must(json.Unmarshal(b, &bad))
		if mode == "http-no-auth" {
			bad["transport"] = "streamable_http"
		} else {
			bad["astra"] = map[string]any{"enabled": true}
		}
		check(configValidator.Validate(bad) != nil, "Expected invalid config: "+mode)
	}
	var manifest struct {
		Version  string `json:"bundle_version"`
		Contract string `json:"contract_version"`
		Modules  []struct {
			ID      string   `json:"id"`
			Path    string   `json:"path"`
			Version string   `json:"version"`
			Hash    string   `json:"sha256"`
			Related []string `json:"related_modules"`
		} `json:"modules"`
	}
	decode(root+"/prompts/manifest.json", &manifest)
	check(manifest.Contract == catalog.Version, "Prompt contract version mismatch")
	ids := map[string]bool{}
	for _, m := range manifest.Modules {
		check(!ids[m.ID], "Duplicate module "+m.ID)
		ids[m.ID] = true
		check(m.Version == manifest.Version, "Module version mismatch")
		check(!filepath.IsAbs(m.Path) && !strings.HasPrefix(filepath.Clean(m.Path), ".."), "Invalid module path")
		digest := sha256.Sum256(read(filepath.Join(root, "prompts", m.Path)))
		check(fmt.Sprintf("%x", digest) == m.Hash, "Prompt hash mismatch: "+m.ID)
		must(inputs["get_playbook"].Validate(map[string]any{"module_id": m.ID}))
	}
	for _, m := range manifest.Modules {
		for _, related := range m.Related {
			check(ids[related], "Unknown related module "+related)
		}
	}
	links, jsonFiles := 0, 0
	linkPattern := regexp.MustCompile(`\[[^\]]*\]\(([^\s)]+)\)`)
	must(filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".json") {
			var v any
			decode(path, &v)
			jsonFiles++
		}
		if !strings.HasSuffix(path, ".md") {
			return nil
		}
		for _, m := range linkPattern.FindAllStringSubmatch(string(read(path)), -1) {
			target := strings.Split(m[1], "#")[0]
			if target == "" || strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			_, e := os.Stat(filepath.Join(filepath.Dir(path), target))
			if e != nil {
				return fmt.Errorf("broken link %s -> %s: %w", path, target, e)
			}
			links++
		}
		return nil
	}))
	fmt.Printf("Validated %d tools, %d cases, 2 configs + 2 negative configs, %d prompt hashes, %d local links, %d JSON files.\n", len(catalog.Tools), len(cases.Cases), len(manifest.Modules), links, jsonFiles)
	fmt.Println("This command validates design artifacts only; use go test for runtime fixtures and a real cluster for live verification.")
}

func checkTimeWindows(value any) {
	switch v := value.(type) {
	case map[string]any:
		if start, ok := v["start"].(string); ok {
			if end, ok := v["end"].(string); ok {
				a, err := time.Parse(time.RFC3339Nano, start)
				must(err)
				b, err := time.Parse(time.RFC3339Nano, end)
				must(err)
				check(a.Before(b), "Window start must be before end")
			}
		}
		for _, child := range v {
			checkTimeWindows(child)
		}
	case []any:
		for _, child := range v {
			checkTimeWindows(child)
		}
	}
}
