package engine

import (
	"encoding/json"
	"slices"
)

const retentionLimit = "RESOURCE_LIMIT: some observation, finding, connection, or coverage details could not be retained. Retained totals are incomplete; narrow the window/scope and refresh. Pod coverage counters describe the full collected snapshot."

func jsonSize(v any) int { b, _ := json.Marshal(v); return len(b) }

// This is a retained-state byte budget, including replay responses and metadata,
// not a limit on Go heap/RSS. Active jobs reserve room for terminal status.
func (e *Engine) memoryUsed() int {
	n := 0
	for _, s := range e.sessions {
		n += 2048 + len(s.id) + len(s.owner) + jsonSize(s.input) + jsonSize(s.question) + jsonSize(s.principal)
		for key, op := range s.ops {
			n += len(key) + len(op.result) + len(op.hash) + 256
		}
		for _, a := range s.attempts {
			n += 2048 + jsonSize(a.workload) + jsonSize(a.window) + jsonSize(a.hashes) + jsonSize(a.comparison)
			for _, j := range a.jobs {
				n += jsonSize(j.view) + 256
				if j.active {
					n += 4096
				}
			}
			for _, v := range a.evidence {
				n += jsonSize(v) + 256
			}
			n += jsonSize(a.connections) + jsonSize(a.findings) + jsonSize(a.knowledge) + jsonSize(a.coverage)
		}
	}
	return n
}

// Called with the coordinator lock before exposing each asynchronous update.
// Preserve replica counters and an explicit partial-result notice if details
// cannot fit; never reinterpret an omitted object as a healthy/absent object.
func (e *Engine) enforceBudget(a *attempt) {
	used, target := e.memoryUsed(), e.cfg.Limits.MemoryBytes-1024
	if used <= target {
		return
	}
	a.coverage.Limitations = unique(append(a.coverage.Limitations, retentionLimit))
	used += len(retentionLimit) + 128
	for id, v := range a.evidence {
		if used <= target {
			break
		}
		delete(a.evidence, id)
		used -= jsonSize(v) + 256
	}
	for i := range a.findings {
		f := &a.findings[i]
		ids := []string{}
		for _, id := range f.EvidenceIDs {
			if _, ok := a.evidence[id]; ok {
				ids = append(ids, id)
			}
		}
		if len(ids) != len(f.EvidenceIDs) {
			f.EvidenceIDs = ids
			f.Confidence = "unknown"
			f.MissingEvidence = unique(append(f.MissingEvidence, "Observation omitted by retained-state memory limit."))
		}
	}
	used = e.memoryUsed()
	for len(a.findings) > 0 && used > target {
		i := len(a.findings) - 1
		used -= jsonSize(a.findings[i])
		a.findings = a.findings[:i]
	}
	for len(a.connections) > 0 && used > target {
		i := len(a.connections) - 1
		used -= jsonSize(a.connections[i])
		a.connections = a.connections[:i]
	}
	for len(a.coverage.Entries) > 0 && used > target {
		i := len(a.coverage.Entries) - 1
		used -= jsonSize(a.coverage.Entries[i])
		a.coverage.Entries = a.coverage.Entries[:i]
	}
	for len(a.knowledge) > 0 && used > target {
		i := len(a.knowledge) - 1
		used -= jsonSize(a.knowledge[i])
		a.knowledge = a.knowledge[:i]
	}
	if used > target {
		a.hashes = map[string]string{}
		a.comparison = nil
	}
	if e.memoryUsed() > target {
		a.coverage.Limitations = []string{retentionLimit}
	}
	// Release backing arrays too; merely reducing length would retain discarded
	// strings and evidence references until the whole attempt expired.
	a.findings = slices.Clone(a.findings)
	a.connections = slices.Clone(a.connections)
	a.coverage.Entries = slices.Clone(a.coverage.Entries)
	a.knowledge = slices.Clone(a.knowledge)
	if len(a.findings) == 0 {
		a.findings = nil
	}
	if len(a.connections) == 0 {
		a.connections = nil
	}
	if len(a.coverage.Entries) == 0 {
		a.coverage.Entries = nil
	}
	if len(a.knowledge) == 0 {
		a.knowledge = nil
	}
	for i := range a.knowledge {
		ids := []string{}
		for _, id := range a.knowledge[i].EvidenceIDs {
			if _, ok := a.evidence[id]; ok {
				ids = append(ids, id)
			}
		}
		if len(ids) != len(a.knowledge[i].EvidenceIDs) {
			a.knowledge[i].Status = "partial"
		}
		a.knowledge[i].EvidenceIDs = ids
	}
	for _, j := range a.jobs {
		if j.view.Status == "completed" {
			j.view.Status = "partial"
		}
		if j.active {
			j.view.StopReason = "RESOURCE_LIMIT: retained details are incomplete"
		}
	}
}
