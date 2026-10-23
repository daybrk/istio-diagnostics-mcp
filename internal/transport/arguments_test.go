package transport

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/daybrk/istio-diagnostics-mcp/docs/design"
	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Validate the advertised schema before sending, as MCP clients including Qwen
// do. A server-only decoder cannot fix a call rejected at this boundary.
func TestClientEncodedObjectsReachHandlerAsCanonicalArguments(t *testing.T) {
	for _, tc := range []struct{ name, tool, canonical string }{
		{"start", "start_diagnosis", `{"operation_id":"start-1","direction":"outbound","workload":{"kind":"Pod","name":"worker-1","namespace":"allowed"},"peer":{"kind":"service","value":"api","namespace":"allowed","port":443,"protocol":"https"},"time_window":{"lookback_seconds":900}}`},
		{"refresh", "refresh_diagnosis", `{"operation_id":"refresh-1","diagnosis_id":"diag_1","time_window":{"start":"2026-10-23T10:00:00Z","end":"2026-10-23T10:15:00Z"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var want map[string]any
			if err := json.Unmarshal([]byte(tc.canonical), &want); err != nil {
				t.Fatal(err)
			}
			calls := 0
			cs := connect(t, handlerFunc(func(_ context.Context, _ core.Principal, name string, raw json.RawMessage) (core.Envelope, error) {
				calls++
				var got any
				if err := json.Unmarshal(raw, &got); err != nil {
					t.Fatal(err)
				}
				if name != tc.tool || !reflect.DeepEqual(got, want) {
					t.Errorf("dispatch: %s %s", name, raw)
				}
				return core.Fail("TEST_STOP", "collection is not part of this transport test"), nil
			}))
			list, err := cs.ListTools(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			var validator *jsonschema.Resolved
			for _, tool := range list.Tools {
				if tool.Name != tc.tool {
					continue
				}
				b, err := json.Marshal(tool.InputSchema)
				if err != nil {
					t.Fatal(err)
				}
				var schema jsonschema.Schema
				if err = json.Unmarshal(b, &schema); err != nil {
					t.Fatal(err)
				}
				validator, err = schema.Resolve(nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			if validator == nil {
				t.Fatal("tool missing")
			}
			for _, encode := range []bool{false, true} {
				args := map[string]any{}
				for key, value := range want {
					args[key] = value
					if _, ok := value.(map[string]any); encode && ok {
						b, _ := json.Marshal(value)
						args[key] = string(b)
					}
				}
				if encode && design.Validate(tc.tool+"Input", args) == nil {
					t.Fatal("canonical contract must remain strict")
				}
				if err := validator.Validate(args); err != nil {
					t.Fatalf("client rejects encoded=%v before RPC: %v", encode, err)
				}
				if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tc.tool, Arguments: args}); err != nil {
					t.Fatalf("encoded=%v: %v", encode, err)
				}
			}
			if calls != 2 {
				t.Fatalf("dispatch count=%d", calls)
			}
		})
	}
}

func TestEncodedArgumentsCannotBypassCanonicalValidation(t *testing.T) {
	for i, tc := range []struct {
		field string
		value any
	}{
		{"workload", `{broken`}, {"workload", `[]`}, {"workload", `null`},
		{"workload", `42`}, {"workload", `"{\"kind\":\"Pod\",\"name\":\"worker\"}"`},
		{"workload", `{"kind":"Pod","selector":"app=worker"}`},
		{"workload", `{"kind":"Pod","name":"worker","selector":"app=worker"}`},
		{"workload", `{"kind":"Selector","name":"worker"}`},
		{"workload", `{"kind":"Pod","name":"worker","unexpected":true}`},
		{"workload", strings.Repeat(" ", 32769) + `{}`},
		{"time_window", `{"lookback_seconds":"900"}`},
		{"time_window", `{"lookback_seconds":0}`},
		{"time_window", `{"lookback_seconds":900,"start":"2026-10-23T10:00:00Z","end":"2026-10-23T10:15:00Z"}`},
		{"peer", `{"kind":"service","value":"api","port":70000}`},
		{"peer", `{"kind":"service","value":"api","port":"443"}`},
		{"workload", nil}, {"workload", []any{}},
	} {
		t.Run(strconv.Itoa(i)+"/"+tc.field, func(t *testing.T) {
			called := false
			cs := connect(t, handlerFunc(func(context.Context, core.Principal, string, json.RawMessage) (core.Envelope, error) {
				called = true
				return core.Success(nil), nil
			}))
			_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "start_diagnosis", Arguments: map[string]any{"operation_id": "invalid-1", tc.field: tc.value}})
			var rpc *jsonrpc.Error
			if !errors.As(err, &rpc) || rpc.Code != jsonrpc.CodeInvalidParams || called {
				t.Fatalf("called=%v err=%v", called, err)
			}
		})
	}
}

func TestUserTextIsNotDecodedAsAnObject(t *testing.T) {
	const question = `{"kind":"Pod","name":"this is documentation text"}`
	cs := connect(t, handlerFunc(func(_ context.Context, _ core.Principal, _ string, raw json.RawMessage) (core.Envelope, error) {
		var args map[string]any
		if err := json.Unmarshal(raw, &args); err != nil {
			t.Fatal(err)
		}
		if args["question"] != question {
			t.Errorf("question changed: %s", raw)
		}
		return core.Fail("TEST_STOP", "no external request"), nil
	}))
	_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_product_context", Arguments: map[string]any{"diagnosis_id": "diag_1", "operation_id": "ask-1", "action": "ask", "project_id": "docs", "question": question}})
	if err != nil {
		t.Fatal(err)
	}
}
