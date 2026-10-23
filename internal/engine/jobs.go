package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
	"strings"
	"time"
)

func (e *Engine) launchDiagnostic(s *session, a *attempt, operationID string, selected *core.Connection) {
	ctx, cancel := context.WithTimeout(e.ctx, time.Duration(e.cfg.Limits.OperationBudgetSeconds)*time.Second)
	j := &job{view: core.Job{OperationID: operationID, Kind: "diagnostic", Status: "queued"}, cancel: cancel, active: true}
	a.jobs = append(a.jobs, j)
	a.revision++
	q := *s.input.Workload
	p := s.principal
	peer := s.input.Peer
	if selected != nil && peer == nil {
		peer = peerFrom(*selected, s.input.Direction)
	}
	req := core.CollectRequest{Direction: s.input.Direction, Peer: peer, Window: a.window, IncludeEnvoy: selected != nil || peer != nil}
	if a.workload != nil {
		req.Workload = *a.workload
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer cancel()
		defer func() {
			if recover() != nil {
				e.mu.Lock()
				if s.state != "closed" {
					j.view.Status = "failed"
					j.view.StopReason = "INTERNAL_ERROR: unexpected diagnostic failure"
					e.finish(s, a, j)
				}
				e.mu.Unlock()
			}
		}()
		select {
		case e.collectionSlots <- struct{}{}:
			defer func() { <-e.collectionSlots }()
		case <-ctx.Done():
			e.finishError(s, a, j, ctx.Err())
			return
		}
		e.mu.Lock()
		if s.state == "closed" || j.cancelled {
			j.view.Status = "cancelled"
			e.finish(s, a, j)
			e.mu.Unlock()
			return
		}
		j.view.Status = "running"
		j.view.StartedAt = core.Timestamp(e.now())
		a.revision++
		e.mu.Unlock()
		if req.Workload.UID == "" {
			r, err := e.collector.Resolve(ctx, p, q)
			if err != nil {
				e.finishError(s, a, j, err)
				return
			}
			if r.Truncated || len(r.Candidates) != 1 || r.Question != nil {
				e.mu.Lock()
				if s.state != "closed" {
					s.state = "needs_clarification"
					s.question = r.Question
					if s.question == nil {
						options := []string{}
						for _, c := range r.Candidates {
							options = append(options, fmt.Sprintf("%s/%s/%s", c.Workload.Namespace, c.Workload.Kind, c.Workload.Name))
						}
						s.question = question("workload", "Choose one application from the matching workloads; no workload data has been collected.", options)
					}
					j.view.Status = "completed"
					for len(s.question.Options) > 0 && e.memoryUsed() > e.cfg.Limits.MemoryBytes-4096 {
						s.question.Options = append([]string{}, s.question.Options[:len(s.question.Options)-1]...)
						s.question.Message = "Candidate list exceeds the memory budget. Refine the selector or specify workload kind/name; no workload data has been collected."
					}
					j.active = false
					j.view.FinishedAt = core.Timestamp(e.now())
					a.state = s.state
					a.revision++
					s.revision++
				}
				e.mu.Unlock()
				return
			}
			req.Workload = r.Candidates[0].Workload
		}
		e.mu.Lock()
		a.workload = &req.Workload
		e.mu.Unlock()
		if selected == nil && peer != nil {
			c := core.Connection{ID: core.NewID("connection"), Source: core.WorkloadIdentity(req.Workload), Destination: core.PeerIdentity(*peer), Port: peer.Port, Protocol: peer.Protocol, Status: "queued", CountSemantics: "log_records", PodUIDs: []string{}}
			if c.Protocol == "" {
				c.Protocol = "unknown"
			}
			if req.Direction == "inbound" {
				c.Source, c.Destination = c.Destination, c.Source
			}
			selected = &c
			e.mu.Lock()
			if s.state != "closed" {
				a.connections = append(a.connections, c)
				a.selected = c.ID
				s.state = "investigating"
				a.state = s.state
				a.revision++
			}
			e.mu.Unlock()
		}
		emit := func(progress core.Progress) {
			e.mu.Lock()
			defer e.mu.Unlock()
			if s.state == "closed" || !j.active {
				return
			}
			j.view.CompletedUnits = progress.Completed
			j.view.TotalUnits = progress.Total
			a.coverage.Entries = mergeCoverage(a.coverage.Entries, progress.Coverage)
			a.coverage = calculateCoverage(a.coverage)
			e.enforceBudget(a)
			a.revision++
			s.revision++
		}
		snapshot, err := e.collector.Collect(ctx, p, req, emit)
		if snapshot == nil {
			snapshot = &core.Snapshot{Request: req, Coverage: []core.CoverageEntry{}, Limitations: []string{"No snapshot was available."}}
		}
		snapshot.AnalysisByteLimit = e.cfg.Limits.MemoryBytes / 4
		analysis := e.analyze(snapshot, selected)
		// No access events is not success: still attempt current proxy configuration.
		if selected == nil && len(analysis.Connections) == 0 && err == nil && !req.IncludeEnvoy && ctx.Err() == nil {
			req.IncludeEnvoy = true
			next, nextErr := e.collector.Collect(ctx, p, req, emit)
			if next != nil {
				snapshot = next
				next.AnalysisByteLimit = e.cfg.Limits.MemoryBytes / 4
				analysis = e.analyze(next, nil)
			}
			err = nextErr
		}
		hashes := snapshotHashes(snapshot)
		e.mu.Lock()
		defer e.mu.Unlock()
		if s.state == "closed" {
			j.active = false
			return
		}
		a.coverage.Entries = mergeCoverage(a.coverage.Entries, snapshot.Coverage)
		a.coverage.Limitations = unique(append(a.coverage.Limitations, snapshot.Limitations...))
		a.coverage.Limitations = unique(append(a.coverage.Limitations, analysis.Limitations...))
		a.coverage = calculateCoverage(a.coverage)
		a.hashes = hashes
		e.storeAnalysis(s, a, analysis)
		if selected == nil {
			a.connections = analysis.Connections
			if a.connections == nil {
				a.connections = []core.Connection{}
			}
			if len(a.connections) > 0 {
				s.state = "awaiting_selection"
			} else {
				s.state = "awaiting_next"
				a.coverage.Limitations = unique(append(a.coverage.Limitations, "No observed failed connection was identified; absence of logs does not establish connectivity."))
			}
		} else {
			for i := range a.connections {
				if a.connections[i].ID == selected.ID {
					a.connections[i].Status = "investigated"
					for _, c := range analysis.Connections {
						if c.ID == selected.ID || core.ConnectionMatches(c, *selected) {
							a.connections[i].Port = c.Port
							a.connections[i].Protocol = c.Protocol
							a.connections[i].ObservationCount = c.ObservationCount
							a.connections[i].LastSeen = c.LastSeen
							a.connections[i].PodUIDs = c.PodUIDs
							break
						}
					}
				}
			}
			a.selected = selected.ID
			s.state = "awaiting_next"
		}
		if err != nil || ctx.Err() != nil {
			if j.cancelled || errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
				j.view.Status = "cancelled"
				j.view.StopReason = "Explicit cancellation or server shutdown"
			} else {
				j.view.Status = "partial"
				j.view.StopReason = "Collection budget or data source failure"
			}
			a.coverage.Limitations = unique(append(a.coverage.Limitations, "Collection ended before every requested source was available."))
		} else if a.coverage.PartialPods+a.coverage.UnavailablePods+a.coverage.PendingPods > 0 || len(a.coverage.Limitations) > 0 {
			j.view.Status = "partial"
		} else {
			j.view.Status = "completed"
		}
		e.compare(s, a)
		e.finish(s, a, j)
	}()
}
func (e *Engine) finish(s *session, a *attempt, j *job) {
	e.enforceBudget(a)
	j.active = false
	j.view.FinishedAt = core.Timestamp(e.now())
	if j.view.Kind == "diagnostic" && s.current == a.id {
		if s.state == "collecting" || s.state == "investigating" {
			s.state = "awaiting_next"
		}
		a.state = s.state
	}
	a.revision++
	s.revision++
	s.updated = e.now()
}
func (e *Engine) finishError(s *session, a *attempt, j *job, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s.state == "closed" {
		j.active = false
		return
	}
	if j.cancelled || errors.Is(err, context.Canceled) {
		j.view.Status = "cancelled"
	} else {
		j.view.Status = "failed"
	}
	r := faultEnvelope(err)
	j.view.StopReason = r.Error.Code + ": " + r.Error.Message
	a.coverage.Limitations = unique(append(a.coverage.Limitations, r.Error.Message))
	e.finish(s, a, j)
}
func mergeCoverage(old, new []core.CoverageEntry) []core.CoverageEntry {
	out := append([]core.CoverageEntry{}, old...)
	indices := map[string]int{}
	for i, v := range out {
		indices[v.PodUID+"\x00"+v.Source] = i
	}
	for _, v := range new {
		key := v.PodUID + "\x00" + v.Source
		if i, ok := indices[key]; ok {
			out[i] = v
		} else {
			indices[key] = len(out)
			out = append(out, v)
		}
	}
	return out
}
func calculateCoverage(c core.Coverage) core.Coverage {
	type pod struct {
		count, good, pending int
		some                 bool
	}
	m := map[string]*pod{}
	for _, v := range c.Entries {
		x := m[v.PodUID]
		if x == nil {
			x = &pod{}
			m[v.PodUID] = x
		}
		x.count++
		switch v.Status {
		case "collected":
			x.good++
			x.some = true
		case "partial", "truncated":
			x.some = true
		case "pending":
			x.pending++
		}
	}
	c.DiscoveredPods = len(m)
	c.CollectedPods = 0
	c.PartialPods = 0
	c.UnavailablePods = 0
	c.PendingPods = 0
	for _, x := range m {
		switch {
		case x.good == x.count:
			c.CollectedPods++
		case x.pending == x.count:
			c.PendingPods++
		case x.some:
			c.PartialPods++
		default:
			c.UnavailablePods++
		}
	}
	c.AttemptedPods = c.DiscoveredPods - c.PendingPods
	if c.Entries == nil {
		c.Entries = []core.CoverageEntry{}
	}
	if c.Limitations == nil {
		c.Limitations = []string{}
	}
	return c
}
func unique(v []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range v {
		if s != "" && !seen[s] {
			seen[s] = true
			if len(s) > 4096 {
				s = s[:4096]
			}
			out = append(out, s)
			if len(out) == 100 {
				break
			}
		}
	}
	return out
}
func sameConnection(a, b core.Connection) bool {
	return a.Source == b.Source && a.Destination == b.Destination && a.Port == b.Port && a.Protocol == b.Protocol
}
func snapshotHashes(s *core.Snapshot) map[string]string {
	m := map[string]string{}
	for _, p := range s.Pods {
		if raw := p.Envoy["config_dump"]; len(raw) > 0 {
			var v any
			if json.Unmarshal(raw, &v) == nil {
				b, _ := json.Marshal(v)
				sum := sha256.Sum256(b)
				m[p.Ref.Namespace+"/"+p.Ref.Name+"@"+p.Ref.UID] = hex.EncodeToString(sum[:])
			}
		}
	}
	return m
}
func (e *Engine) compare(s *session, a *attempt) {
	if a.baseline == "" {
		return
	}
	b := s.attempts[a.baseline]
	if b == nil {
		return
	}
	c := &core.Comparison{BaselineAttemptID: b.id, CurrentAttemptID: a.id, ConfigurationChanges: []string{}, SymptomChanges: []string{}, Conclusion: "inconclusive", Limitations: []string{"Different observation windows and current configuration cannot establish historical causality or successful requests. No active traffic was generated."}}
	for k, v := range a.hashes {
		if old, ok := b.hashes[k]; ok && old != v {
			c.ConfigurationChanges = append(c.ConfigurationChanges, "Current Envoy config changed for "+k)
		} else if !ok {
			c.ConfigurationChanges = append(c.ConfigurationChanges, "New pod/config observation: "+k)
		}
	}
	for k := range b.hashes {
		if _, ok := a.hashes[k]; !ok {
			c.ConfigurationChanges = append(c.ConfigurationChanges, "No comparable current observation for "+k)
		}
	}
	oldCount, newCount := 0, 0
	for _, v := range b.connections {
		oldCount += v.ObservationCount
	}
	for _, v := range a.connections {
		newCount += v.ObservationCount
	}
	c.SymptomChanges = append(c.SymptomChanges, fmt.Sprintf("Observed failure log records: baseline=%d, current=%d; these are not unique requests or error rates.", oldCount, newCount))
	if oldCount == newCount && newCount > 0 && len(c.ConfigurationChanges) == 0 {
		c.Conclusion = "unchanged"
	}
	if len(c.ConfigurationChanges) > 100 {
		c.ConfigurationChanges = c.ConfigurationChanges[:100]
		c.Limitations = append(c.Limitations, "Configuration change summary limited to 100 items.")
	}
	a.comparison = c
}
func (e *Engine) cancelOperation(p core.Principal, in input) core.Envelope {
	s, r := e.lookup(p, in.DiagnosisID)
	if s == nil {
		return r
	}
	if s.state == "closed" {
		return core.Fail("SESSION_CLOSED", "Investigation is closed.")
	}
	for _, a := range s.attempts {
		for _, j := range a.jobs {
			if j.view.OperationID == in.OperationID {
				if j.active {
					j.cancelled = true
					j.cancel()
					j.view.Status = "cancelled"
					j.view.StopReason = "Cancellation requested"
					a.revision++
					s.revision++
				}
				e.touch(s)
				return e.view(s, a, 20, "")
			}
		}
	}
	return core.Fail("INVALID_STATE", "Operation was not found in this investigation.")
}
func (e *Engine) closeSession(p core.Principal, in input) core.Envelope {
	s, r := e.lookup(p, in.DiagnosisID)
	if s == nil {
		return r
	}
	if s.state != "closed" {
		e.cancelAll(s)
		s.state = "closed"
		s.closedAt = core.Timestamp(e.now())
		s.attempts = map[string]*attempt{}
		s.order = nil
		s.current = ""
		s.ops = map[string]operation{}
		s.question = nil
		s.revision++
		e.touch(s)
		for key, op := range e.creates {
			if op.sessionID == s.id {
				delete(e.creates, key)
			}
		}
	}
	return core.Success(core.Closure{DiagnosisID: s.id, State: "closed", ClosedAt: s.closedAt})
}
func (e *Engine) storeAnalysis(s *session, a *attempt, result core.Analysis) {
	lost := map[string]bool{}
	used := e.memoryUsed()
	for _, v := range result.Evidence {
		v.AttemptID = a.id
		if v.ID == "" {
			v.ID = core.NewID("evidence")
		}
		if v.CollectedAt == "" {
			v.CollectedAt = core.Timestamp(e.now())
		}
		v.Offset = 0
		v.NextOffset = 0
		for i, line := range v.Lines {
			line = core.RedactString(line)
			if len(line) > 8192 {
				line = line[:8192]
				v.Truncated = true
			}
			v.Lines[i] = line
		}
		if v.Lines == nil {
			v.Lines = []string{}
		}
		b, _ := json.Marshal(v)
		if used+len(b)+4096 > e.cfg.Limits.MemoryBytes {
			lost[v.ID] = true
			a.coverage.Limitations = unique(append(a.coverage.Limitations, "RESOURCE_LIMIT: evidence memory budget exhausted; some observations could not be retained."))
			continue
		}
		a.evidence[v.ID] = v
		used += len(b) + 512
	}
	for _, f := range result.Findings {
		ids := []string{}
		for _, id := range f.EvidenceIDs {
			if !lost[id] {
				if _, ok := a.evidence[id]; ok {
					ids = append(ids, id)
				}
			}
		}
		if len(ids) < len(f.EvidenceIDs) {
			f.Confidence = "unknown"
			f.MissingEvidence = append(f.MissingEvidence, "Referenced observation was not retained within the memory budget.")
		}
		f.EvidenceIDs = ids
		if f.AffectedPodUIDs == nil {
			f.AffectedPodUIDs = []string{}
		}
		if f.MissingEvidence == nil {
			f.MissingEvidence = []string{}
		}
		if f.Confidence == "confirmed" && len(ids) == 0 {
			f.Confidence = "unknown"
		}
		if len(f.EvidenceIDs) > 100 {
			f.EvidenceIDs = f.EvidenceIDs[:100]
		}
		f.MissingEvidence = unique(f.MissingEvidence)
		if used+jsonSize(f)+4096 > e.cfg.Limits.MemoryBytes {
			a.coverage.Limitations = unique(append(a.coverage.Limitations, retentionLimit))
			continue
		}
		a.findings = append(a.findings, f)
		used += jsonSize(f)
	}
	for i := range a.coverage.Limitations {
		a.coverage.Limitations[i] = strings.TrimSpace(core.RedactString(a.coverage.Limitations[i]))
	}
}
