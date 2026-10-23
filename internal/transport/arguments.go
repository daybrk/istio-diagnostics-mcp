package transport

import (
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/daybrk/istio-diagnostics-mcp/docs/design"
)

// normalizeArguments is the only compatibility boundary. The engine always
// receives canonical objects, with the same representation for operation replay.
func normalizeArguments(tool string, raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	var args map[string]any
	if err := json.Unmarshal(raw, &args); err != nil || args == nil {
		return nil, fmt.Errorf("arguments must be a JSON object")
	}
	for _, field := range design.JSONEncodedObjectFields(tool) {
		value, present := args[field]
		if !present {
			continue
		}
		if text, ok := value.(string); ok {
			if utf8.RuneCountInString(text) > design.MaxEncodedObjectLength {
				return nil, fmt.Errorf("%s: JSON-encoded object exceeds %d characters", field, design.MaxEncodedObjectLength)
			}
			var object map[string]any
			if err := json.Unmarshal([]byte(text), &object); err != nil || object == nil {
				return nil, fmt.Errorf("%s: expected an object or one JSON-encoded object string; arrays, null and double encoding are not accepted", field)
			}
			args[field] = object
		} else if _, ok := value.(map[string]any); !ok {
			return nil, fmt.Errorf("%s: expected a JSON object", field)
		}
	}
	if err := design.Validate(tool+"Input", args); err != nil {
		// Validator errors can quote user payloads. Keep the protocol error useful
		// without reflecting credentials or other arbitrary argument contents.
		return nil, fmt.Errorf("arguments do not match %s input schema after object decoding; check required fields, types and allowed properties in tools/list; preserve the requested workload, peer and time window", tool)
	}
	return json.Marshal(args)
}
