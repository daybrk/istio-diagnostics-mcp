package core

import (
	"encoding/json"
	"os"
	"testing"
)

func TestAstraConfigModes(t *testing.T) {
	base, err := os.ReadFile("../../docs/design/examples/server-config.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, astra                           string
		valid, available, credentialScope, p1 bool
	}{
		{"absent", "", true, false, true, true},
		{"empty", `{}`, true, false, true, true},
		{"configured", `{"agent_url":"https://astra.example/mcp/agent","credential_env":"KEY"}`, true, true, true, true},
		{"deny-all", `{"agent_url":"https://astra.example/mcp/agent","credential_env":"KEY","allowed_projects":[]}`, true, true, false, false},
		{"explicit-projects", `{"agent_url":"https://astra.example/mcp/agent","credential_env":"KEY","allowed_projects":["p1"]}`, true, true, false, true},
		{"legacy-disabled", `{"enabled":false}`, true, false, true, true},
		{"legacy-enabled-incomplete", `{"enabled":true}`, false, false, false, false},
		{"missing-credential", `{"agent_url":"https://astra.example/mcp/agent"}`, false, false, false, false},
		{"missing-endpoint", `{"credential_env":"KEY"}`, false, false, false, false},
		{"plain-http", `{"agent_url":"http://astra.example/mcp/agent","credential_env":"KEY"}`, false, false, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(base, &raw); err != nil {
				t.Fatal(err)
			}
			delete(raw, "astra")
			if tt.astra != "" {
				raw["astra"] = json.RawMessage(tt.astra)
			}
			b, _ := json.Marshal(raw)
			cfg, err := ParseConfig(b)
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v err=%v", tt.valid, err)
			}
			if err != nil {
				return
			}
			if cfg.Astra.Available() != tt.available || cfg.LocalPrincipal().AstraCredentialScope != tt.credentialScope || cfg.Astra.ProjectAllowed("p1") != tt.p1 {
				t.Fatalf("unexpected scope: %+v %+v", cfg.Astra, cfg.LocalPrincipal())
			}
			if cfg.Astra.RequestBudgetSeconds != 45 || cfg.Astra.MaxResponseBytes != 1<<20 {
				t.Fatal("missing safe defaults")
			}
		})
	}
}

func TestAstraAllowlistSerializationPreservesDenyAll(t *testing.T) {
	for _, projects := range [][]string{nil, {}, {"p1"}} {
		before := AstraConfig{AllowedProjects: projects}
		b, err := json.Marshal(before)
		if err != nil {
			t.Fatal(err)
		}
		var after AstraConfig
		if err := json.Unmarshal(b, &after); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"p1", "p2"} {
			if before.ProjectAllowed(id) != after.ProjectAllowed(id) {
				t.Fatalf("serialization changed project access: %s", b)
			}
		}
	}
}
