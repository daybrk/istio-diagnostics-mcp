package engine

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
	"strings"
)

type cursor struct {
	Session  string `json:"s"`
	Attempt  string `json:"a"`
	Owner    string `json:"p"`
	Revision uint64 `json:"r"`
	Offsets  [5]int `json:"o"`
}

func (e *Engine) encodeCursor(c cursor) string {
	b, _ := json.Marshal(c)
	mac := hmac.New(sha256.New, e.cursorKey)
	mac.Write(b)
	return base64.RawURLEncoding.EncodeToString(b) + "." + hex.EncodeToString(mac.Sum(nil))
}
func (e *Engine) decodeCursor(v string) (cursor, error) {
	var c cursor
	parts := strings.Split(v, ".")
	if len(parts) != 2 {
		return c, fmt.Errorf("invalid cursor")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return c, err
	}
	sig, err := hex.DecodeString(parts[1])
	if err != nil {
		return c, err
	}
	mac := hmac.New(sha256.New, e.cursorKey)
	mac.Write(b)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return c, fmt.Errorf("invalid cursor")
	}
	if err = json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	for _, off := range c.Offsets {
		if off < 0 {
			return c, fmt.Errorf("invalid offset")
		}
	}
	return c, nil
}
func (e *Engine) view(s *session, a *attempt, limit int, token string) core.Envelope {
	d := core.Diagnosis{DiagnosisID: s.id, State: s.state, CreatedAt: core.Timestamp(s.created), UpdatedAt: core.Timestamp(s.updated), ExpiresAt: core.Timestamp(s.expires), PromptBundle: core.Version, RulesetVersion: core.Version, Jobs: []core.Job{}, Connections: []core.Connection{}, Findings: []core.Finding{}, Knowledge: []core.Knowledge{}, Coverage: emptyCoverage(), ResumeSummary: core.ResumeSummary{ScopeSummary: "Application scope is not yet resolved.", CheckedRuleIDs: []string{}, KnownFacts: []string{}, Gaps: []string{}, NextStep: "Clarify the application and direction.", RemainingCount: 0}, Question: s.question}
	c := cursor{Session: s.id, Owner: s.owner, Revision: s.revision}
	if a != nil {
		c.Attempt = a.id
		c.Revision = a.revision
		d.AttemptID = a.id
		d.Window = &a.window
		d.Workload = a.workload
		d.Direction = a.direction
		d.State = a.state
		if a.id == s.current {
			d.State = s.state
		}
		d.Coverage = a.coverage
		d.Comparison = a.comparison
		d.ResumeSummary = e.summary(s, a)
		d.Totals = core.DiagnosisTotals{Connections: len(a.connections), Findings: len(a.findings), Knowledge: len(a.knowledge), Jobs: len(a.jobs), CoverageEntries: len(a.coverage.Entries)}
	}
	if token != "" {
		old, err := e.decodeCursor(token)
		if err != nil || old.Session != c.Session || old.Owner != c.Owner || old.Attempt != c.Attempt || old.Revision != c.Revision {
			return core.Fail("CURSOR_STALE", "The cursor is invalid or the investigation changed; restart from the first page.")
		}
		c.Offsets = old.Offsets
	}
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	for {
		next := c
		more := false
		take := func(index, total int) (int, int) {
			lo := c.Offsets[index]
			if lo > total {
				lo = total
			}
			hi := lo + limit
			if hi > total {
				hi = total
			}
			next.Offsets[index] = hi
			if hi < total {
				more = true
			}
			return lo, hi
		}
		if a != nil {
			lo, hi := take(0, len(a.connections))
			d.Connections = append([]core.Connection{}, a.connections[lo:hi]...)
			lo, hi = take(1, len(a.findings))
			d.Findings = append([]core.Finding{}, a.findings[lo:hi]...)
			lo, hi = take(2, len(a.knowledge))
			d.Knowledge = append([]core.Knowledge{}, a.knowledge[lo:hi]...)
			lo, hi = take(3, len(a.jobs))
			d.Jobs = []core.Job{}
			for _, j := range a.jobs[lo:hi] {
				d.Jobs = append(d.Jobs, j.view)
			}
			lo, hi = take(4, len(a.coverage.Entries))
			d.Coverage.Entries = append([]core.CoverageEntry{}, a.coverage.Entries[lo:hi]...)
		}
		d.NextCursor = ""
		if more {
			d.NextCursor = e.encodeCursor(next)
		}
		r := core.Success(d)
		r.NextActions = actions(d)
		if d.State == "needs_clarification" {
			r.Outcome = "needs_clarification"
		} else if d.Coverage.PartialPods+d.Coverage.UnavailablePods+d.Coverage.PendingPods > 0 || len(d.Coverage.Limitations) > 0 {
			r.Outcome = "partial"
		}
		for _, v := range d.Coverage.Limitations {
			r.Warnings = append(r.Warnings, core.Warning{Code: "COVERAGE_LIMITATION", Message: v})
		}
		b, _ := json.Marshal(r)
		if len(b) <= e.cfg.Limits.MaxToolResponseBytes {
			return r
		}
		if limit == 1 {
			return core.Fail("RESOURCE_LIMIT", "Even the minimum investigation page exceeds the configured response limit.")
		}
		limit = (limit + 1) / 2
	}
}
func (e *Engine) summary(s *session, a *attempt) core.ResumeSummary {
	v := core.ResumeSummary{ScopeSummary: "Resolving application identity.", SelectedConnectionID: a.selected, CheckedRuleIDs: []string{}, KnownFacts: []string{}, Gaps: append([]string{}, a.coverage.Limitations...), NextStep: "Read the job state and available evidence.", RemainingCount: 0}
	if a.workload != nil {
		v.ScopeSummary = fmt.Sprintf("%s / %s / %s %s; %s; %s to %s", a.workload.Context, a.workload.Namespace, a.workload.Kind, a.workload.Name, a.direction, a.window.Start, a.window.End)
	}
	for _, c := range a.connections {
		if c.Status == "queued" {
			v.RemainingCount++
		}
	}
	for _, f := range a.findings {
		v.CheckedRuleIDs = append(v.CheckedRuleIDs, f.RuleID)
		if f.CheckStatus == "UNKNOWN" || f.CheckStatus == "UNSUPPORTED" {
			v.Gaps = append(v.Gaps, f.Summary)
		} else {
			v.KnownFacts = append(v.KnownFacts, f.Summary)
		}
	}
	v.CheckedRuleIDs = unique(v.CheckedRuleIDs)
	v.KnownFacts = unique(v.KnownFacts)
	v.Gaps = unique(v.Gaps)
	switch s.state {
	case "needs_clarification":
		v.NextStep = "Ask the displayed clarification question."
	case "awaiting_selection":
		v.NextStep = "Present the failed connections and let the user select one."
	case "awaiting_next":
		v.NextStep = "Explain findings and limits, then offer remaining connections, a refresh, or close."
	case "closed":
		v.NextStep = "The investigation is closed."
	}
	return v
}
func actions(d core.Diagnosis) []core.NextAction {
	switch d.State {
	case "needs_clarification":
		return clarifyAction()
	case "collecting", "investigating":
		return []core.NextAction{{Action: "poll", Tool: "get_diagnosis", Instructions: "Poll this diagnosis_id for progress. Disconnecting does not cancel collection."}}
	case "awaiting_selection":
		return []core.NextAction{{Action: "select", Tool: "investigate_connection", ModuleID: "investigation", Instructions: "Show the connection queue and investigate the user's chosen connection_id."}}
	case "awaiting_next":
		out := []core.NextAction{{Action: "read_evidence", Tool: "get_evidence", ModuleID: "report", Instructions: "Explain supported findings and unknowns with their evidence IDs."}}
		if d.ResumeSummary.RemainingCount > 0 {
			out = append(out, core.NextAction{Action: "continue", Tool: "investigate_connection", Instructions: "Offer the remaining queued connections; continue only with the user's selection."})
		}
		return append(out, core.NextAction{Action: "refresh", Tool: "refresh_diagnosis", ModuleID: "recheck", Instructions: "Use a new explicit time window to check after changes; no active probes are generated."}, core.NextAction{Action: "close", Tool: "close_diagnosis", Instructions: "Close when the user finishes the investigation."})
	default:
		return []core.NextAction{}
	}
}
func (e *Engine) evidence(p core.Principal, in input) core.Envelope {
	s, _ := e.lookup(p, in.DiagnosisID)
	if s == nil {
		return core.Fail("EVIDENCE_NOT_FOUND", "Evidence was not found or has expired.")
	}
	var v core.Evidence
	found := false
	for _, a := range s.attempts {
		if x, ok := a.evidence[in.EvidenceID]; ok {
			v = x
			found = true
			break
		}
	}
	if !found {
		return core.Fail("EVIDENCE_NOT_FOUND", "Evidence was not found or has expired.")
	}
	e.touch(s)
	limit := in.Limit
	if limit == 0 {
		limit = 50
	}
	for {
		start := in.Offset
		if start > len(v.Lines) {
			start = len(v.Lines)
		}
		end := start + limit
		if end > len(v.Lines) {
			end = len(v.Lines)
		}
		page := v
		page.Offset = in.Offset
		page.Lines = append([]string{}, v.Lines[start:end]...)
		page.NextOffset = 0
		if end < len(v.Lines) {
			page.NextOffset = end
		}
		r := core.Success(page)
		b, _ := json.Marshal(r)
		if len(b) <= e.cfg.Limits.MaxToolResponseBytes {
			return r
		}
		if limit <= 1 {
			return core.Fail("RESOURCE_LIMIT", "One evidence line exceeds the configured response limit.")
		}
		limit = (limit + 1) / 2
	}
}
