package engine

import (
	"context"
	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
	"reflect"
	"sync/atomic"
	"testing"
)

func TestAstraScopeNarrowingHidesHistoricalSession(t *testing.T) {
	e, _, p := setup(t)
	p.AstraCredentialScope = true
	d := diagnosis(t, call(t, e, p, "start_diagnosis", startArgs("wide-astra")))
	settled(t, e, p, d.DiagnosisID)
	narrowed := p
	narrowed.AstraCredentialScope = false
	narrowed.AstraProjects = []string{"p1"}
	r := call(t, e, narrowed, "get_diagnosis", map[string]any{"diagnosis_id": d.DiagnosisID})
	if r.Error == nil || r.Error.Code != "SESSION_NOT_FOUND" {
		t.Fatalf("historical scope leaked: %+v", r)
	}
	if !retainsScope(p, narrowed) {
		t.Fatal("widening unexpectedly hides session")
	}
}

func TestPromptBundleVersionAcrossResponses(t *testing.T) {
	e, _, p := setup(t)
	e.cfg.Astra = core.AstraConfig{AgentURL: "https://astra.example/mcp/agent", CredentialEnv: "ASTRA_KEY"}
	caps := call(t, e, p, "get_capabilities", map[string]any{}).Data.(core.Capabilities)
	if !caps.Astra.Enabled {
		t.Fatal("configured ASTRA not discoverable")
	}
	if caps.PromptBundle != "2026-10-23.1" || caps.ContractVersion != "2026-10-22" {
		t.Fatalf("versions: %+v", caps)
	}
	pb := call(t, e, p, "get_playbook", map[string]any{"module_id": "astra"}).Data.(core.Playbook)
	if pb.BundleVersion != caps.PromptBundle {
		t.Fatalf("playbook version: %s", pb.BundleVersion)
	}
	d := diagnosis(t, call(t, e, p, "start_diagnosis", startArgs("prompt-version")))
	if d.PromptBundle != caps.PromptBundle {
		t.Fatalf("diagnosis version: %s", d.PromptBundle)
	}
}

func TestAstraActionsMatchConfiguredEndpoints(t *testing.T) {
	for _, tt := range []struct {
		name, defaultURL, agentURL string
		actions                    []string
	}{
		{"ask-only", "", "https://astra.example/mcp/agent", []string{"ask"}},
		{"search-only", "https://astra.example/mcp", "", []string{"catalog", "search", "source"}},
		{"both", "https://astra.example/mcp", "https://astra.example/mcp/agent", []string{"catalog", "ask", "search", "source"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e, _, p := setup(t)
			e.cfg.Astra = core.AstraConfig{DefaultURL: tt.defaultURL, AgentURL: tt.agentURL, CredentialEnv: "KEY"}
			caps := call(t, e, p, "get_capabilities", map[string]any{}).Data.(core.Capabilities)
			if !reflect.DeepEqual(caps.Astra.Actions, tt.actions) {
				t.Fatalf("advertised unsupported actions: %v", caps.Astra.Actions)
			}
		})
	}
}

func TestCoreDiagnosisDoesNotInitiateAstra(t *testing.T) {
	e, _, p := setup(t)
	e.cfg.Astra = core.AstraConfig{AgentURL: "https://astra.example/mcp/agent", CredentialEnv: "KEY"}
	var requests atomic.Int32
	e.provider = productFunc(func(context.Context, core.Principal, core.ProductRequest) (core.ProductResult, error) {
		requests.Add(1)
		return core.ProductResult{}, nil
	})
	d := diagnosis(t, call(t, e, p, "start_diagnosis", startArgs("core-with-astra")))
	settled(t, e, p, d.DiagnosisID)
	if requests.Load() != 0 {
		t.Fatal("core diagnostics initiated unsolicited ASTRA call")
	}
}
