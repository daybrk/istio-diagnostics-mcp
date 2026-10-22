package engine

import (
	"context"
	"errors"
	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
	"time"
)

func (e *Engine) product(p core.Principal, in input, hash string) core.Envelope {
	s, r := e.lookup(p, in.DiagnosisID)
	if s == nil {
		return r
	}
	if s.state == "closed" {
		return core.Fail("SESSION_CLOSED", "Investigation is closed.")
	}
	if !e.cfg.Astra.Enabled || e.provider == nil {
		return core.Fail("INTEGRATION_DISABLED", "ASTRA is disabled; core diagnostics remain available.")
	}
	if prev, ok := s.ops[in.OperationID]; ok {
		if r, yes := replay(prev, hash); yes {
			return r
		}
	}
	a := s.attempts[s.current]
	if a == nil || a.workload == nil {
		return core.Fail("INVALID_STATE", "Finish identifying the application before requesting product context.")
	}
	for _, retained := range s.attempts {
		if active(retained, "knowledge") {
			return core.Fail("OPERATION_IN_PROGRESS", "A product-context operation is already running in this investigation.")
		}
	}
	if !e.operationCapacity(s) {
		return core.Fail("RESOURCE_LIMIT", "Session operation capacity reached.")
	}
	req := core.ProductRequest{Action: in.Action, ProjectID: in.ProjectID, Repo: in.Repo, Question: core.RedactString(in.Question), Query: core.RedactString(in.Query), Mode: in.Mode, Path: in.Path, Offset: in.Offset, Limit: in.Limit}
	budget := e.cfg.Astra.RequestBudgetSeconds
	if budget < 1 {
		budget = 45
	}
	ctx, cancel := context.WithTimeout(e.ctx, time.Duration(budget)*time.Second)
	j := &job{view: core.Job{OperationID: in.OperationID, Kind: "knowledge", Status: "queued", TotalUnits: 1}, cancel: cancel, active: true}
	a.jobs = append(a.jobs, j)
	a.revision++
	e.touch(s)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer cancel()
		defer func() {
			if recover() != nil {
				e.mu.Lock()
				if s.state != "closed" {
					j.view.Status = "failed"
					j.view.StopReason = "INTERNAL_ERROR: product adapter failed"
					e.finish(s, a, j)
				}
				e.mu.Unlock()
			}
		}()
		e.mu.Lock()
		if s.state == "closed" || j.cancelled {
			j.active = false
			j.view.Status = "cancelled"
			e.mu.Unlock()
			return
		}
		j.view.Status = "running"
		j.view.StartedAt = core.Timestamp(e.now())
		a.revision++
		e.mu.Unlock()
		result, err := e.provider.Query(ctx, p, req)
		e.mu.Lock()
		defer e.mu.Unlock()
		if s.state == "closed" {
			j.active = false
			return
		}
		if err != nil {
			failure := faultEnvelope(err)
			j.view.Status = "failed"
			j.view.StopReason = failure.Error.Code + ": " + failure.Error.Message
			if j.cancelled || errors.Is(err, context.Canceled) {
				j.view.Status = "cancelled"
			}
			a.knowledge = append(a.knowledge, core.Knowledge{ID: core.NewID("knowledge"), Action: req.Action, Status: "unavailable", Summary: failure.Error.Message, EvidenceIDs: []string{}, ProjectID: req.ProjectID})
		} else {
			e.storeAnalysis(s, a, core.Analysis{Evidence: result.Evidence})
			k := result.Knowledge
			if k.ID == "" {
				k.ID = core.NewID("knowledge")
			}
			ids := []string{}
			for _, id := range k.EvidenceIDs {
				if _, ok := a.evidence[id]; ok {
					ids = append(ids, id)
				}
			}
			if len(ids) != len(k.EvidenceIDs) {
				k.Status = "partial"
			}
			k.EvidenceIDs = ids
			a.knowledge = append(a.knowledge, k)
			j.view.Status = "completed"
			if k.Status != "available" {
				j.view.Status = "partial"
			}
			j.view.CompletedUnits = 1
		}
		e.finish(s, a, j)
	}()
	r = e.view(s, a, 20, "")
	e.remember(s, in.OperationID, hash, r)
	return r
}
