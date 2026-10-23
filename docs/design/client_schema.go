package design

import "strings"

// MaxEncodedObjectLength bounds the compatibility form in Unicode code points,
// matching JSON Schema maxLength. The decoded object still uses strict validation.
const MaxEncodedObjectLength = 32768

// JSONEncodedObjectFields is an explicit wire-compatibility allowlist. Arbitrary
// user text (questions, selectors, hostnames, etc.) is never decoded recursively.
func JSONEncodedObjectFields(tool string) []string {
	switch tool {
	case "start_diagnosis":
		return []string{"workload", "peer", "time_window"}
	case "refresh_diagnosis":
		return []string{"time_window"}
	default:
		return nil
	}
}

func clientInputSchema(name string) map[string]any {
	all := schema["$defs"].(map[string]any)
	// Input definitions are acyclic. Inline their references so clients/models
	// see parameter shapes directly. Output schemas retain shared definitions.
	var inline func(any) any
	inline = func(value any) any {
		switch v := value.(type) {
		case map[string]any:
			out := map[string]any{}
			if ref, ok := v["$ref"].(string); ok {
				out = inline(all[strings.TrimPrefix(ref, "#/$defs/")]).(map[string]any)
			}
			for key, child := range v {
				if key != "$ref" {
					out[key] = inline(child)
				}
			}
			return out
		case []any:
			out := make([]any, len(v))
			for i, child := range v {
				out[i] = inline(child)
			}
			return out
		default:
			return value
		}
	}
	root := inline(all[name]).(map[string]any)
	root["type"] = "object"
	for _, field := range JSONEncodedObjectFields(strings.TrimSuffix(name, "Input")) {
		properties := root["properties"].(map[string]any)
		object := properties[field].(map[string]any)
		object["type"] = "object"
		properties[field] = map[string]any{
			"description": "Pass a JSON object. Compatibility only: one JSON-encoded object string is also accepted; its contents must satisfy the object schema. Do not double-encode.",
			"anyOf":       []any{object, map[string]any{"type": "string", "maxLength": MaxEncodedObjectLength}},
		}
	}
	return root
}
