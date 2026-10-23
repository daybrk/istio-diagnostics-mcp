package astra

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
)

func projectID(m map[string]any) string { return firstString(m, "projectId", "project_id", "id") }
func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}
func repoName(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if m, ok := v.(map[string]any); ok {
		return firstString(m, "name", "repo", "id")
	}
	return ""
}
func filterCatalog(value any, allowed map[string]bool, selected string) ([]map[string]any, error) {
	var entries []any
	switch v := value.(type) {
	case []any:
		entries = v
	case map[string]any:
		var ok bool
		entries, ok = v["projects"].([]any)
		if !ok {
			return nil, fault("UPSTREAM_CONTRACT_MISMATCH", "ASTRA project catalog has an unknown shape", false)
		}
	default:
		return nil, fault("UPSTREAM_CONTRACT_MISMATCH", "ASTRA project catalog has an unknown shape", false)
	}
	projects := []map[string]any{}
	for _, entry := range entries {
		m, ok := entry.(map[string]any)
		if !ok || projectID(m) == "" {
			return nil, fault("UPSTREAM_CONTRACT_MISMATCH", "ASTRA project catalog has an invalid entry", false)
		}
		id := projectID(m)
		if allowed != nil && !allowed[id] || selected != "" && selected != id {
			continue
		}
		project := map[string]any{"projectId": id}
		for _, k := range []string{"name", "description"} {
			if s, ok := m[k].(string); ok {
				project[k] = clean(s, 2048)
			}
		}
		if raw, exists := m["repos"]; exists {
			repos, ok := raw.([]any)
			if !ok {
				return nil, fault("UPSTREAM_CONTRACT_MISMATCH", "ASTRA repository catalog has an unknown shape", false)
			}
			filtered := []any{}
			for _, repo := range repos {
				if name := repoName(repo); name != "" {
					filtered = append(filtered, map[string]any{"name": clean(name, 512)})
				} else {
					return nil, fault("UPSTREAM_CONTRACT_MISMATCH", "ASTRA repository catalog has an invalid entry", false)
				}
			}
			project["repos"] = filtered
		}
		projects = append(projects, project)
	}
	return projects, nil
}
func clean(s string, limit int) string {
	s = strings.ToValidUTF8(core.RedactString(s), "�")
	if len(s) > limit {
		marker := "[truncated]"
		s = s[:limit-len(marker)]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
		s += marker
	}
	return s
}

func normalize(r core.ProductRequest, value any, allowed map[string]bool) (core.ProductResult, error) {
	result := core.ProductResult{Knowledge: core.Knowledge{ID: core.NewID("knowledge"), Action: r.Action, Status: "available", ProjectID: r.ProjectID, EvidenceIDs: []string{}}, Evidence: []core.Evidence{}, Warnings: []core.Warning{}}
	fail := func() (core.ProductResult, error) {
		return core.ProductResult{}, fault("UPSTREAM_CONTRACT_MISMATCH", "ASTRA returned an unknown response shape", false)
	}
	m, _ := value.(map[string]any)
	meta, _ := m["meta"].(map[string]any)
	if meta != nil {
		selection, _ := meta["projectSelectionRequired"].(bool)
		entries, _ := m["results"].([]any)
		if selection || (len(entries) == 0 && m["answer"] == nil && m["content"] == nil && (meta["catalog"] != nil || meta["projects"] != nil)) {
			return core.ProductResult{}, fault("PROJECT_SELECTION_REQUIRED", "ASTRA requires an explicit authorized project selection", false)
		}
	}
	switch r.Action {
	case "catalog":
		projects, err := filterCatalog(value, allowed, r.ProjectID)
		if err != nil {
			return core.ProductResult{}, err
		}
		b, _ := json.Marshal(map[string]any{"projects": projects, "totalProjects": len(projects)})
		addEvidence(&result, r, string(b), nil, 1, false)
		result.Knowledge.Summary = fmt.Sprintf("%d authorized project(s) available", len(projects))
	case "ask":
		answer, ok := m["answer"].(string)
		if !ok {
			return fail()
		}
		if strings.TrimSpace(answer) == "" {
			return core.ProductResult{}, fault("UPSTREAM_UNAVAILABLE", "ASTRA returned no answer", false)
		}
		addEvidence(&result, r, answer, meta, 1, false)
		result.Knowledge.Summary = clean(answer, 2048)
	case "search":
		entries, ok := m["results"].([]any)
		if !ok || len(entries) > 5 {
			return fail()
		}
		for _, entry := range entries {
			item, ok := entry.(map[string]any)
			if !ok {
				return fail()
			}
			content := firstString(item, "content", "text")
			if content == "" {
				if lines, ok := item["lines"].([]any); ok {
					var text []string
					for _, line := range lines {
						s, ok := line.(string)
						if !ok {
							return fail()
						}
						text = append(text, s)
					}
					content = strings.Join(text, "\n")
				} else {
					return fail()
				}
			}
			// Never expose a returned chunk explicitly attributed to another project.
			if id := firstString(item, "projectId", "project_id"); id != "" && id != r.ProjectID {
				return fail()
			}
			addEvidence(&result, r, content, item, intNumber(item["lineFrom"], 1), false)
		}
		result.Knowledge.Summary = fmt.Sprintf("Retrieved %d product source(s); these describe expected behavior, not live causality", len(result.Evidence))
	case "source":
		content, ok := m["content"].(string)
		if !ok {
			return fail()
		}
		addEvidence(&result, r, content, meta, intNumber(meta["lineFrom"], r.Offset), false)
		result.Knowledge.Summary = "Retrieved an indexed source excerpt; deployed revision is not established"
	default:
		return fail()
	}
	return result, nil
}
func intNumber(v any, fallback int) int {
	if n, ok := v.(float64); ok && n >= 1 && n <= 1<<31 {
		return int(n)
	}
	return fallback
}
func addEvidence(result *core.ProductResult, r core.ProductRequest, content string, meta map[string]any, offset int, truncated bool) {
	id := core.NewID("evidence")
	repo, path := r.Repo, r.Path
	if v := firstString(meta, "repo"); v != "" {
		repo = v
	}
	if v := firstString(meta, "path"); v != "" {
		path = v
	}
	revision := firstString(meta, "revision", "commit")
	status := "unknown"
	if revision != "" {
		status = "known"
	}
	citation := firstString(meta, "citation")
	if len(content) > 256<<10 {
		truncated = true
	}
	content = clean(content, 256<<10)
	lines := strings.Split(content, "\n")
	if len(lines) > 200 {
		lines = lines[:200]
		truncated = true
	}
	for i, line := range lines {
		if len(line) > 8192 {
			lines[i] = clean(line, 8192)
			truncated = true
		}
	}
	e := core.Evidence{ID: id, SourceType: "product_knowledge", CollectedAt: core.Timestamp(time.Now()), SourceLocator: "astra:" + r.Action + ":" + clean(r.ProjectID, 256), Lines: lines, Offset: offset, Truncated: truncated, ProductSource: &core.EvidenceProductSource{Provider: "astra", ProjectID: r.ProjectID, Repo: clean(repo, 253), Path: clean(path, 1024), Citation: clean(citation, 2048), RevisionStatus: status, Revision: clean(revision, 256)}}
	if truncated {
		result.Knowledge.Status = "partial"
		e.NextOffset = offset + len(lines)
		result.Warnings = append(result.Warnings, core.Warning{Code: "RESOURCE_LIMIT", Message: "Product source excerpt was bounded; additional indexed content may be available"})
	}
	result.Evidence = append(result.Evidence, e)
	result.Knowledge.EvidenceIDs = append(result.Knowledge.EvidenceIDs, id)
}
