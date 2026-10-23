package engine

import (
	"fmt"
	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
)

func question(field, message string, options []string) *core.Question {
	if options == nil {
		options = []string{}
	}
	if len(options) > 100 {
		options = options[:100]
	}
	return &core.Question{Field: field, Message: message, Options: options}
}
func normalizeQuery(q core.WorkloadQuery, p core.Principal) (core.WorkloadQuery, *core.Question, error) {
	if len(p.Scopes) == 0 {
		return q, nil, &core.Fault{Code: "SCOPE_DENIED", Message: "No Kubernetes contexts are assigned to this principal."}
	}
	if q.Context == "" {
		if len(p.Scopes) == 1 {
			q.Context = p.Scopes[0].Context
		} else {
			options := []string{}
			for _, s := range p.Scopes {
				options = append(options, s.Context)
			}
			return q, question("workload.context", "Choose the Kubernetes context.", options), nil
		}
	}
	if !p.AllowsContext(q.Context) {
		return q, nil, &core.Fault{Code: "SCOPE_DENIED", Message: "Kubernetes context is outside the assigned scope."}
	}
	if q.Namespace == "" {
		return q, question("workload.namespace", "Which namespace contains the application?", nil), nil
	}
	if !core.ValidName(q.Namespace) || (q.Kind != "Selector" && !core.ValidName(q.Name)) {
		return q, nil, &core.Fault{Code: "INVALID_ARGUMENT", Message: "Invalid Kubernetes object name."}
	}
	return q, nil, nil
}
func clarifyAction() []core.NextAction {
	return []core.NextAction{{Action: "clarify", Tool: "start_diagnosis", ModuleID: "intake", Instructions: "Ask the displayed question and resubmit start_diagnosis with diagnosis_id and a new operation_id."}}
}
func clarifyResolution(q *core.Question) core.Envelope {
	r := core.Success(core.Resolution{Candidates: []core.Candidate{}, Question: q})
	r.Outcome = "needs_clarification"
	r.NextActions = []core.NextAction{{Action: "clarify", Tool: "resolve_workload", Instructions: "Ask the displayed question before collecting any workload data."}}
	return r
}
func (e *Engine) start(p core.Principal, in input, hash string) core.Envelope {
	var s *session
	var r core.Envelope
	createKey := p.ID + "\x00" + in.OperationID
	if in.DiagnosisID == "" {
		if prev, ok := e.creates[createKey]; ok {
			if _, denied := e.lookup(p, prev.sessionID); denied.Error != nil {
				return denied
			}
			if r, yes := replay(prev, hash); yes {
				return r
			}
		}
		if len(e.sessions) >= e.cfg.Limits.MaxSessions || e.memoryUsed()+16384+jsonSize(in)+jsonSize(p) > e.cfg.Limits.MemoryBytes {
			return core.Fail("RESOURCE_LIMIT", "Session capacity is exhausted; close an existing investigation.")
		}
		now := e.now()
		s = &session{id: core.NewID("diag"), owner: p.ID, principal: p, created: now, updated: now, expires: now, state: "needs_clarification", attempts: map[string]*attempt{}, ops: map[string]operation{}}
		e.touch(s)
		e.sessions[s.id] = s
	} else {
		s, r = e.lookup(p, in.DiagnosisID)
		if s == nil {
			return r
		}
		if prev, ok := s.ops[in.OperationID]; ok {
			if r, yes := replay(prev, hash); yes {
				return r
			}
		}
		if s.state == "closed" {
			return core.Fail("SESSION_CLOSED", "Investigation is closed.")
		}
		if s.state != "needs_clarification" {
			return core.Fail("INVALID_STATE", "Scope is fixed after collection starts. Use refresh or create a new investigation.")
		}
		if !e.operationCapacity(s) {
			return core.Fail("RESOURCE_LIMIT", "Session operation capacity reached.")
		}
	}
	if in.Workload != nil {
		s.input.Workload = in.Workload
	}
	if in.Direction != "" {
		s.input.Direction = in.Direction
	}
	if in.Peer != nil {
		s.input.Peer = in.Peer
	}
	if in.TimeWindow != nil {
		s.input.TimeWindow = in.TimeWindow
	}
	e.touch(s)
	if s.input.Workload == nil {
		s.question = question("workload", "Which application should be diagnosed? Specify workload kind/name and namespace.", nil)
	} else if q, ask, err := normalizeQuery(*s.input.Workload, p); err != nil {
		r = faultEnvelope(err)
		return e.recordStart(s, in, hash, createKey, r)
	} else {
		s.input.Workload = &q
		s.question = ask
		if ask == nil && s.input.Direction == "" {
			s.question = question("direction", "Does the application fail to connect out, or can another application not connect to it?", []string{"outbound", "inbound"})
		}
		if s.question == nil && s.input.Peer != nil {
			peer := s.input.Peer
			if (peer.Kind == "workload" || peer.Kind == "service") && peer.Namespace == "" {
				s.question = question("peer.namespace", "Which namespace contains the other application or Service?", nil)
			}
		}
	}
	if s.question != nil {
		s.state = "needs_clarification"
		s.revision++
		r = e.view(s, nil, 20, "")
		r.Outcome = "needs_clarification"
		r.NextActions = clarifyAction()
		return e.recordStart(s, in, hash, createKey, r)
	}
	w, err := core.ResolveWindow(s.input.TimeWindow, e.now())
	if err != nil {
		r = core.Fail("INVALID_TIME_WINDOW", err.Error())
		return e.recordStart(s, in, hash, createKey, r)
	}
	a := e.newAttempt(s, w)
	e.launchDiagnostic(s, a, in.OperationID, nil)
	r = e.view(s, a, 20, "")
	return e.recordStart(s, in, hash, createKey, r)
}
func (e *Engine) recordStart(s *session, in input, hash, key string, r core.Envelope) core.Envelope {
	e.remember(s, in.OperationID, hash, r)
	if in.DiagnosisID == "" {
		e.creates[key] = s.ops[in.OperationID]
	}
	return r
}
func (e *Engine) get(p core.Principal, in input) core.Envelope {
	s, r := e.lookup(p, in.DiagnosisID)
	if s == nil {
		return r
	}
	e.touch(s)
	var a *attempt
	if in.AttemptID != "" {
		a = s.attempts[in.AttemptID]
		if a == nil {
			return core.Fail("INVALID_STATE", "Attempt was not found in this investigation.")
		}
	} else {
		a = s.attempts[s.current]
	}
	limit := in.Limit
	if limit == 0 {
		limit = 20
	}
	return e.view(s, a, limit, in.Cursor)
}
func (e *Engine) investigate(p core.Principal, in input, hash string) core.Envelope {
	s, r := e.lookup(p, in.DiagnosisID)
	if s == nil {
		return r
	}
	if prev, ok := s.ops[in.OperationID]; ok {
		if r, yes := replay(prev, hash); yes {
			return r
		}
	}
	a := s.attempts[s.current]
	if s.state == "closed" {
		return core.Fail("SESSION_CLOSED", "Investigation is closed.")
	}
	if active(a, "diagnostic") {
		return e.busy(a)
	}
	if a == nil || (s.state != "awaiting_selection" && s.state != "awaiting_next") {
		return core.Fail("INVALID_STATE", "Collect the application symptoms before selecting a connection.")
	}
	for i := range a.connections {
		if a.connections[i].ID == in.ConnectionID {
			c := a.connections[i]
			if c.Status == "investigated" {
				return core.Fail("INVALID_STATE", "This connection was already investigated; use refresh for a new collection.")
			}
			if !e.operationCapacity(s) {
				return core.Fail("RESOURCE_LIMIT", "Session operation capacity reached.")
			}
			a.selected = c.ID
			s.state = "investigating"
			a.state = s.state
			a.revision++
			s.revision++
			e.touch(s)
			e.launchDiagnostic(s, a, in.OperationID, &c)
			r = e.view(s, a, 20, "")
			e.remember(s, in.OperationID, hash, r)
			return r
		}
	}
	return core.Fail("CONNECTION_NOT_FOUND", "Choose a connection ID returned by this attempt.")
}
func (e *Engine) refresh(p core.Principal, in input, hash string) core.Envelope {
	s, r := e.lookup(p, in.DiagnosisID)
	if s == nil {
		return r
	}
	if prev, ok := s.ops[in.OperationID]; ok {
		if r, yes := replay(prev, hash); yes {
			return r
		}
	}
	if s.state == "closed" {
		return core.Fail("SESSION_CLOSED", "Investigation is closed.")
	}
	old := s.attempts[s.current]
	if old == nil {
		return core.Fail("INVALID_STATE", "Finish identifying the application first.")
	}
	if active(old, "diagnostic") {
		return e.busy(old)
	}
	if in.CompareToAttemptID != "" && s.attempts[in.CompareToAttemptID] == nil {
		return core.Fail("INVALID_STATE", "Comparison baseline was not found in this investigation.")
	}
	w, err := core.ResolveWindow(in.TimeWindow, e.now())
	if err != nil {
		return core.Fail("INVALID_TIME_WINDOW", err.Error())
	}
	if !e.operationCapacity(s) || e.memoryUsed()+4096 > e.cfg.Limits.MemoryBytes {
		return core.Fail("RESOURCE_LIMIT", "Session capacity reached.")
	}
	a := e.newAttempt(s, w)
	a.workload = old.workload
	a.baseline = in.CompareToAttemptID
	var chosen *core.Connection
	for _, c := range old.connections {
		if c.ID == old.selected {
			c.ID = core.NewID("connection")
			c.Status = "queued"
			c.ObservationCount = 0
			c.LastSeen = ""
			chosen = &c
			a.connections = append(a.connections, c)
			a.selected = c.ID
			break
		}
	}
	e.touch(s)
	e.launchDiagnostic(s, a, in.OperationID, chosen)
	r = e.view(s, a, 20, "")
	e.remember(s, in.OperationID, hash, r)
	return r
}
func (e *Engine) busy(a *attempt) core.Envelope {
	r := core.Fail("OPERATION_IN_PROGRESS", "A diagnostic operation is still running.")
	for _, j := range a.jobs {
		if j.active && j.view.Kind == "diagnostic" {
			r.Error.Message = fmt.Sprintf("Diagnostic operation %s is still running.", j.view.OperationID)
		}
	}
	r.NextActions = []core.NextAction{{Action: "poll", Tool: "get_diagnosis", Instructions: "Poll the running operation, or cancel it explicitly before starting another."}}
	return r
}
func (e *Engine) operationCapacity(s *session) bool {
	return len(s.ops) < 10000 && e.memoryUsed()+16384+jsonSize(e.view(s, s.attempts[s.current], 20, "")) < e.cfg.Limits.MemoryBytes
}
func peerFrom(c core.Connection, direction string) *core.PeerQuery {
	return core.PeerFromConnection(c, direction)
}
