// Package engine coordinates principal-owned live investigations without an LLM.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/daybrk/istio-diagnostics-mcp/docs/design"
	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
	"sync"
	"time"
)

type Analyzer func(*core.Snapshot, *core.Connection) core.Analysis
type Engine struct {
	mu              sync.Mutex
	cfg             core.Config
	collector       core.Collector
	provider        core.ProductProvider
	analyze         Analyzer
	checks          []string
	sessions        map[string]*session
	creates         map[string]operation
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	now             func() time.Time
	cursorKey       []byte
	closed          bool
	collectionSlots chan struct{}
}
type session struct {
	id, owner                 string
	principal                 core.Principal
	created, updated, expires time.Time
	state                     string
	input                     input
	question                  *core.Question
	attempts                  map[string]*attempt
	order                     []string
	current                   string
	ops                       map[string]operation
	closedAt                  string
	revision                  uint64
}
type attempt struct {
	id               string
	window           core.ResolvedWindow
	workload         *core.WorkloadRef
	direction, state string
	jobs             []*job
	connections      []core.Connection
	findings         []core.Finding
	knowledge        []core.Knowledge
	coverage         core.Coverage
	evidence         map[string]core.Evidence
	selected         string
	comparison       *core.Comparison
	baseline         string
	hashes           map[string]string
	revision         uint64
}
type job struct {
	view      core.Job
	cancel    context.CancelFunc
	active    bool
	cancelled bool
}
type operation struct {
	hash, sessionID string
	result          json.RawMessage
}
type input struct {
	OperationID        string              `json:"operation_id,omitempty"`
	DiagnosisID        string              `json:"diagnosis_id,omitempty"`
	Workload           *core.WorkloadQuery `json:"workload,omitempty"`
	Direction          string              `json:"direction,omitempty"`
	Peer               *core.PeerQuery     `json:"peer,omitempty"`
	TimeWindow         *core.TimeWindow    `json:"time_window,omitempty"`
	AttemptID          string              `json:"attempt_id,omitempty"`
	ConnectionID       string              `json:"connection_id,omitempty"`
	EvidenceID         string              `json:"evidence_id,omitempty"`
	Cursor             string              `json:"cursor,omitempty"`
	Limit              int                 `json:"limit,omitempty"`
	Offset             int                 `json:"offset,omitempty"`
	CompareToAttemptID string              `json:"compare_to_attempt_id,omitempty"`
	ModuleID           string              `json:"module_id,omitempty"`
	Action             string              `json:"action,omitempty"`
	ProjectID          string              `json:"project_id,omitempty"`
	Repo               string              `json:"repo,omitempty"`
	Question           string              `json:"question,omitempty"`
	Query              string              `json:"query,omitempty"`
	Mode               string              `json:"mode,omitempty"`
	Path               string              `json:"path,omitempty"`
}

func New(c core.Config, collector core.Collector, provider core.ProductProvider, analyzer Analyzer, checks []string) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{cfg: c, collector: collector, provider: provider, analyze: analyzer, checks: checks, sessions: map[string]*session{}, creates: map[string]operation{}, ctx: ctx, cancel: cancel, now: time.Now, cursorKey: []byte(core.NewID("cursor")), collectionSlots: make(chan struct{}, 1)}
	e.wg.Add(1)
	go e.reap()
	return e
}
func (e *Engine) Close() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	e.cancel()
	for _, s := range e.sessions {
		e.cancelAll(s)
	}
	e.mu.Unlock()
	e.wg.Wait()
	e.mu.Lock()
	e.sessions = map[string]*session{}
	e.creates = map[string]operation{}
	e.mu.Unlock()
}
func (e *Engine) reap() {
	defer e.wg.Done()
	interval := time.Duration(e.cfg.Limits.SessionIdleTTLSeconds) * time.Second / 2
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.mu.Lock()
			e.sweep()
			e.mu.Unlock()
		}
	}
}
func (e *Engine) sweep() {
	now := e.now()
	for id, s := range e.sessions {
		if !s.expires.After(now) {
			e.cancelAll(s)
			delete(e.sessions, id)
		}
	}
	for k, v := range e.creates {
		if e.sessions[v.sessionID] == nil {
			delete(e.creates, k)
		}
	}
}
func (e *Engine) cancelAll(s *session) {
	for _, a := range s.attempts {
		for _, j := range a.jobs {
			if j.active {
				j.cancelled = true
				j.cancel()
			}
		}
	}
}
func (e *Engine) touch(s *session) {
	s.updated = e.now()
	s.expires = s.updated.Add(time.Duration(e.cfg.Limits.SessionIdleTTLSeconds) * time.Second)
}
func (e *Engine) lookup(p core.Principal, id string) (*session, core.Envelope) {
	s := e.sessions[id]
	if s == nil || s.owner != p.ID || !retainsScope(p, s.principal) {
		return nil, core.Fail("SESSION_NOT_FOUND", "Investigation was not found or has expired.")
	}
	return s, core.Envelope{}
}

// A session may contain observations from any namespace in its pinned scope.
// If authorization narrows, hide the whole session rather than leak old data.
func retainsScope(current, original core.Principal) bool {
	if original.AstraCredentialScope && !current.AstraCredentialScope {
		return false
	}
	for _, scope := range original.Scopes {
		if !current.AllowsContext(scope.Context) {
			return false
		}
	}
	for _, project := range original.AstraProjects {
		if current.AstraCredentialScope {
			continue
		}
		found := false
		for _, permitted := range current.AstraProjects {
			if project == permitted {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func (e *Engine) Call(ctx context.Context, p core.Principal, name string, raw json.RawMessage) (core.Envelope, error) {
	var args any
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return core.Envelope{}, err
	}
	if err := design.Validate(name+"Input", args); err != nil {
		return core.Envelope{}, fmt.Errorf("invalid tool arguments: %w", err)
	}
	if p.ID == "" {
		return core.Fail("SCOPE_DENIED", "An authenticated principal is required."), nil
	}
	p.Scopes = core.IntersectScopes(p.Scopes, e.cfg.Kube.Contexts)
	if name == "resolve_workload" {
		var q core.WorkloadQuery
		json.Unmarshal(raw, &q)
		q, question, fault := normalizeQuery(q, p)
		if fault != nil {
			return faultEnvelope(fault), nil
		}
		if question != nil {
			return clarifyResolution(question), nil
		}
		r, err := e.collector.Resolve(ctx, p, q)
		if err != nil {
			return faultEnvelope(err), nil
		}
		if r.Candidates == nil {
			r.Candidates = []core.Candidate{}
		}
		out := core.Success(r)
		if r.Question != nil {
			out.Outcome = "needs_clarification"
			out.NextActions = clarifyAction()
		}
		return e.bound(out), nil
	}
	var in input
	json.Unmarshal(raw, &in)
	canonical, _ := json.Marshal(args)
	sum := sha256.Sum256(append([]byte(name+":"), canonical...))
	hash := hex.EncodeToString(sum[:])
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sweep()
	if e.closed {
		return core.Fail("INVALID_STATE", "Server is shutting down."), nil
	}
	var out core.Envelope
	switch name {
	case "get_capabilities":
		out = e.capabilities(p)
	case "start_diagnosis":
		out = e.start(p, in, hash)
	case "get_diagnosis":
		out = e.get(p, in)
	case "investigate_connection":
		out = e.investigate(p, in, hash)
	case "get_evidence":
		out = e.evidence(p, in)
	case "refresh_diagnosis":
		out = e.refresh(p, in, hash)
	case "cancel_operation":
		out = e.cancelOperation(p, in)
	case "close_diagnosis":
		out = e.closeSession(p, in)
	case "get_playbook":
		out = e.playbook(p, in)
	case "get_product_context":
		out = e.product(p, in, hash)
	default:
		return core.Envelope{}, fmt.Errorf("unknown tool %s", name)
	}
	return e.bound(out), nil
}
func (e *Engine) bound(r core.Envelope) core.Envelope {
	b, err := json.Marshal(r)
	if err != nil {
		return core.Fail("INTERNAL_ERROR", "Could not encode result.")
	}
	if len(b) > e.cfg.Limits.MaxToolResponseBytes {
		return core.Fail("RESOURCE_LIMIT", "Result exceeds the configured response limit; request a smaller page or increase the operator limit.")
	}
	return r
}
func faultEnvelope(err error) core.Envelope {
	var f *core.Fault
	if errors.As(err, &f) {
		r := core.Fail(f.Code, core.RedactString(f.Message))
		r.Error.Retryable = f.Retryable
		return r
	}
	if errors.Is(err, context.Canceled) {
		return core.Fail("CANCELLED", "Operation was cancelled.")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		r := core.Fail("UPSTREAM_UNAVAILABLE", "Collection deadline exceeded.")
		r.Error.Retryable = true
		return r
	}
	return core.Fail("UPSTREAM_UNAVAILABLE", "The configured data source could not complete the request.")
}
func (e *Engine) remember(s *session, key, hash string, r core.Envelope) {
	b, _ := json.Marshal(r)
	s.ops[key] = operation{hash: hash, sessionID: s.id, result: b}
}
func replay(op operation, hash string) (core.Envelope, bool) {
	if op.hash == "" {
		return core.Envelope{}, false
	}
	if op.hash != hash {
		return core.Fail("IDEMPOTENCY_CONFLICT", "This operation_id was already used with different arguments."), true
	}
	var r core.Envelope
	json.Unmarshal(op.result, &r)
	return r, true
}
func active(a *attempt, kind string) bool {
	if a == nil {
		return false
	}
	for _, j := range a.jobs {
		if j.active && j.view.Kind == kind {
			return true
		}
	}
	return false
}
func emptyCoverage() core.Coverage {
	return core.Coverage{Entries: []core.CoverageEntry{}, Limitations: []string{}}
}
func (e *Engine) newAttempt(s *session, w core.ResolvedWindow) *attempt {
	a := &attempt{id: core.NewID("attempt"), window: w, direction: s.input.Direction, state: "collecting", connections: []core.Connection{}, findings: []core.Finding{}, knowledge: []core.Knowledge{}, jobs: []*job{}, coverage: emptyCoverage(), evidence: map[string]core.Evidence{}, hashes: map[string]string{}, revision: 1}
	s.attempts[a.id] = a
	s.current = a.id
	s.order = append(s.order, a.id)
	s.state = "collecting"
	s.question = nil
	s.revision++
	return a
}
