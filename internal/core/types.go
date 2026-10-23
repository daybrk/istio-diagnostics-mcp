package core

import (
	"context"
	"encoding/json"
	"fmt"
)

const Version = "2026-10-22"

type Principal struct {
	ID            string
	Scopes        []Scope
	AstraProjects []string
	// Set only for the local stdio principal; never inferred for HTTP subjects.
	AstraCredentialScope bool
}

// AllowsContext checks the server's context binding. Kubernetes RBAC controls
// access to resources in every namespace of that context.
func (p Principal) AllowsContext(context string) bool {
	for _, s := range p.Scopes {
		if s.Context == context {
			return true
		}
	}
	return false
}

type Envelope struct {
	ContractVersion string       `json:"contract_version"`
	Outcome         string       `json:"outcome"`
	Data            any          `json:"data,omitempty"`
	Warnings        []Warning    `json:"warnings"`
	NextActions     []NextAction `json:"next_actions"`
	Error           *APIError    `json:"error,omitempty"`
}

func Success(data any) Envelope {
	return Envelope{ContractVersion: Version, Outcome: "ok", Data: data, Warnings: []Warning{}, NextActions: []NextAction{}}
}

type Fault struct {
	Code, Message string
	Retryable     bool
}

func (f *Fault) Error() string { return f.Code + ": " + f.Message }
func Fail(code, message string) Envelope {
	return Envelope{ContractVersion: Version, Outcome: "error", Warnings: []Warning{}, NextActions: []NextAction{}, Error: &APIError{Code: code, Message: message, Retryable: false}}
}

type Handler interface {
	Call(context.Context, Principal, string, json.RawMessage) (Envelope, error)
}
type TimeWindow struct {
	LookbackSeconds int    `json:"lookback_seconds,omitempty"`
	Start           string `json:"start,omitempty"`
	End             string `json:"end,omitempty"`
}
type CollectRequest struct {
	Workload     WorkloadRef
	Direction    string
	Peer         *PeerQuery
	Window       ResolvedWindow
	IncludeEnvoy bool
}
type Resource struct {
	Context, Namespace, Kind, Name, UID, CollectedAt string
	Object                                           map[string]any
}
type PodSnapshot struct {
	Ref                       WorkloadRef
	Role                      string
	Object                    map[string]any
	CollectedAt               string
	LogsCurrent, LogsPrevious []byte
	Envoy                     map[string]json.RawMessage
}
type Snapshot struct {
	// Internal materialization budget, not a wire or user-controlled field.
	AnalysisByteLimit int
	Request           CollectRequest
	Pods              []PodSnapshot
	Resources         []Resource
	Coverage          []CoverageEntry
	Limitations       []string
	CollectedAt       string
}
type Progress struct {
	Completed, Total int
	Coverage         []CoverageEntry
}
type Collector interface {
	Resolve(context.Context, Principal, WorkloadQuery) (Resolution, error)
	Collect(context.Context, Principal, CollectRequest, func(Progress)) (*Snapshot, error)
}
type Analysis struct {
	Connections []Connection
	Findings    []Finding
	Evidence    []Evidence
	Limitations []string
}
type ProductRequest struct {
	Action, ProjectID, Repo, Question, Query, Mode, Path string
	Offset, Limit                                        int
}
type ProductResult struct {
	Knowledge Knowledge
	Evidence  []Evidence
	Warnings  []Warning
}
type ProductProvider interface {
	Query(context.Context, Principal, ProductRequest) (ProductResult, error)
}

func Decode[T any](v any) T {
	b, e := json.Marshal(v)
	if e != nil {
		panic(fmt.Sprint(e))
	}
	var out T
	if e = json.Unmarshal(b, &out); e != nil {
		panic(fmt.Sprint(e))
	}
	return out
}
