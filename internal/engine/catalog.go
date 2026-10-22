package engine

import (
	"encoding/json"
	"github.com/daybrk/istio-diagnostics-mcp/docs/design"
	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
)

func (e *Engine) capabilities(p core.Principal) core.Envelope {
	status := "disabled"
	actions := []string{}
	if e.cfg.Astra.Enabled {
		status = "configured"
		actions = []string{"catalog", "ask", "search", "source"}
	}
	checks := append([]string{}, e.checks...)
	scope := append([]core.Scope{}, p.Scopes...)
	return core.Success(core.Capabilities{ServerVersion: "0.1.0-live", ContractVersion: core.Version, PromptBundle: core.Version, RulesetVersion: core.Version, Transports: []string{"stdio", "streamable_http"}, Scope: scope, Formats: []string{"envoy-v3-json", "istio-default-access-log", "istio-json-access-log"}, SupportedChecks: checks, Limits: core.CapabilitiesLimits{SessionTTLSeconds: e.cfg.Limits.SessionIdleTTLSeconds, MaxSessions: e.cfg.Limits.MaxSessions, OperationBudgetSeconds: e.cfg.Limits.OperationBudgetSeconds, ResponseBytes: e.cfg.Limits.MaxToolResponseBytes}, Astra: core.CapabilitiesAstra{Enabled: e.cfg.Astra.Enabled, Status: status, Actions: actions}})
}
func (e *Engine) playbook(p core.Principal, in input) core.Envelope {
	if in.DiagnosisID != "" {
		s, r := e.lookup(p, in.DiagnosisID)
		if s == nil {
			return r
		}
		e.touch(s)
	}
	if in.ModuleID == "astra" && !e.cfg.Astra.Enabled {
		return core.Fail("INTEGRATION_DISABLED", "ASTRA is disabled. Continue with the core diagnostics playbook.")
	}
	b, err := design.Files.ReadFile("prompts/manifest.json")
	if err != nil {
		return core.Fail("PLAYBOOK_NOT_FOUND", "Playbook manifest unavailable.")
	}
	var manifest struct {
		BundleVersion string `json:"bundle_version"`
		Modules       []struct {
			ID, Path             string
			RequiredCapabilities []string `json:"required_capabilities"`
			RelatedModules       []string `json:"related_modules"`
		} `json:"modules"`
	}
	if json.Unmarshal(b, &manifest) != nil {
		return core.Fail("PLAYBOOK_NOT_FOUND", "Invalid bundled playbook manifest.")
	}
	for _, m := range manifest.Modules {
		if m.ID == in.ModuleID {
			b, err := design.Files.ReadFile("prompts/" + m.Path)
			if err != nil {
				break
			}
			return core.Success(core.Playbook{ModuleID: m.ID, BundleVersion: manifest.BundleVersion, Content: string(b), RequiredCapabilities: m.RequiredCapabilities, RelatedModules: m.RelatedModules})
		}
	}
	return core.Fail("PLAYBOOK_NOT_FOUND", "Playbook does not exist in the pinned bundle.")
}
