// Code generated from docs/design/contracts/mcp.schema.json; DO NOT EDIT.
package core

type ResolvedWindow struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type WorkloadQuery struct {
	Context   string `json:"context,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Kind      string `json:"kind"`
	Name      string `json:"name,omitempty"`
	Selector  string `json:"selector,omitempty"`
}

type WorkloadRef struct {
	Context   string `json:"context"`
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

type PeerQuery struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Namespace string `json:"namespace,omitempty"`
	Port      int    `json:"port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
}

type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type NextAction struct {
	Action       string `json:"action"`
	Tool         string `json:"tool,omitempty"`
	ModuleID     string `json:"module_id,omitempty"`
	Instructions string `json:"instructions"`
}

type APIError struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	Retryable     bool   `json:"retryable"`
	CorrelationID string `json:"correlation_id,omitempty"`
}

type Candidate struct {
	Workload WorkloadRef `json:"workload"`
	PodCount int         `json:"pod_count"`
}

type Question struct {
	Field   string   `json:"field"`
	Message string   `json:"message"`
	Options []string `json:"options"`
}

type Job struct {
	OperationID    string `json:"operation_id"`
	Kind           string `json:"kind"`
	Status         string `json:"status"`
	CompletedUnits int    `json:"completed_units"`
	TotalUnits     int    `json:"total_units"`
	StartedAt      string `json:"started_at,omitempty"`
	FinishedAt     string `json:"finished_at,omitempty"`
	StopReason     string `json:"stop_reason,omitempty"`
}

type CoverageEntry struct {
	PodUID    string `json:"pod_uid"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Source    string `json:"source"`
	Status    string `json:"status"`
	Detail    string `json:"detail"`
}

type Coverage struct {
	DiscoveredPods  int             `json:"discovered_pods"`
	AttemptedPods   int             `json:"attempted_pods"`
	CollectedPods   int             `json:"collected_pods"`
	PartialPods     int             `json:"partial_pods"`
	UnavailablePods int             `json:"unavailable_pods"`
	PendingPods     int             `json:"pending_pods"`
	Entries         []CoverageEntry `json:"entries"`
	Limitations     []string        `json:"limitations"`
}

type Finding struct {
	ID              string   `json:"id"`
	RuleID          string   `json:"rule_id"`
	CheckStatus     string   `json:"check_status"`
	Confidence      string   `json:"confidence"`
	Summary         string   `json:"summary"`
	EvidenceIDs     []string `json:"evidence_ids"`
	AffectedPodUIDs []string `json:"affected_pod_uids"`
	MissingEvidence []string `json:"missing_evidence"`
	Recommendation  string   `json:"recommendation"`
	Validation      string   `json:"validation"`
}

type Connection struct {
	ID               string   `json:"id"`
	Source           string   `json:"source"`
	Destination      string   `json:"destination"`
	Port             int      `json:"port,omitempty"`
	Protocol         string   `json:"protocol"`
	Status           string   `json:"status"`
	ObservationCount int      `json:"observation_count"`
	CountSemantics   string   `json:"count_semantics"`
	LastSeen         string   `json:"last_seen,omitempty"`
	PodUIDs          []string `json:"pod_uids"`
}

type Knowledge struct {
	ID          string   `json:"id"`
	Action      string   `json:"action"`
	Status      string   `json:"status"`
	Summary     string   `json:"summary"`
	EvidenceIDs []string `json:"evidence_ids"`
	ProjectID   string   `json:"project_id,omitempty"`
	Revision    string   `json:"revision,omitempty"`
}

type ResumeSummary struct {
	ScopeSummary         string   `json:"scope_summary"`
	SelectedConnectionID string   `json:"selected_connection_id,omitempty"`
	CheckedRuleIDs       []string `json:"checked_rule_ids"`
	KnownFacts           []string `json:"known_facts"`
	Gaps                 []string `json:"gaps"`
	NextStep             string   `json:"next_step"`
	RemainingCount       int      `json:"remaining_count"`
}

type Comparison struct {
	BaselineAttemptID    string   `json:"baseline_attempt_id"`
	CurrentAttemptID     string   `json:"current_attempt_id"`
	ConfigurationChanges []string `json:"configuration_changes"`
	SymptomChanges       []string `json:"symptom_changes"`
	Conclusion           string   `json:"conclusion"`
	Limitations          []string `json:"limitations"`
}

type DiagnosisTotals struct {
	Connections     int `json:"connections"`
	Findings        int `json:"findings"`
	Knowledge       int `json:"knowledge"`
	Jobs            int `json:"jobs"`
	CoverageEntries int `json:"coverage_entries"`
}

type Diagnosis struct {
	DiagnosisID    string          `json:"diagnosis_id"`
	State          string          `json:"state"`
	AttemptID      string          `json:"attempt_id,omitempty"`
	Window         *ResolvedWindow `json:"window,omitempty"`
	Workload       *WorkloadRef    `json:"workload,omitempty"`
	Direction      string          `json:"direction,omitempty"`
	CreatedAt      string          `json:"created_at"`
	UpdatedAt      string          `json:"updated_at"`
	ExpiresAt      string          `json:"expires_at"`
	PromptBundle   string          `json:"prompt_bundle"`
	RulesetVersion string          `json:"ruleset_version"`
	Jobs           []Job           `json:"jobs"`
	Connections    []Connection    `json:"connections"`
	Findings       []Finding       `json:"findings"`
	Knowledge      []Knowledge     `json:"knowledge"`
	Coverage       Coverage        `json:"coverage"`
	Question       *Question       `json:"question,omitempty"`
	Comparison     *Comparison     `json:"comparison,omitempty"`
	ResumeSummary  ResumeSummary   `json:"resume_summary"`
	NextCursor     string          `json:"next_cursor,omitempty"`
	Totals         DiagnosisTotals `json:"totals"`
}

type EvidenceProductSource struct {
	Provider       string `json:"provider"`
	ProjectID      string `json:"project_id,omitempty"`
	Repo           string `json:"repo,omitempty"`
	Path           string `json:"path,omitempty"`
	Citation       string `json:"citation,omitempty"`
	RevisionStatus string `json:"revision_status"`
	Revision       string `json:"revision,omitempty"`
}

type Evidence struct {
	ID            string                 `json:"id"`
	AttemptID     string                 `json:"attempt_id"`
	SourceType    string                 `json:"source_type"`
	CollectedAt   string                 `json:"collected_at"`
	ObservedAt    string                 `json:"observed_at,omitempty"`
	SourceLocator string                 `json:"source_locator"`
	PodUID        string                 `json:"pod_uid,omitempty"`
	ResourceUID   string                 `json:"resource_uid,omitempty"`
	Namespace     string                 `json:"namespace,omitempty"`
	Revision      string                 `json:"revision,omitempty"`
	Lines         []string               `json:"lines"`
	Offset        int                    `json:"offset"`
	NextOffset    int                    `json:"next_offset,omitempty"`
	Truncated     bool                   `json:"truncated"`
	ProductSource *EvidenceProductSource `json:"product_source,omitempty"`
}

type Scope struct {
	Context    string   `json:"context"`
	Namespaces []string `json:"namespaces"`
}

type CapabilitiesLimits struct {
	SessionTTLSeconds      int `json:"session_ttl_seconds"`
	MaxSessions            int `json:"max_sessions"`
	OperationBudgetSeconds int `json:"operation_budget_seconds"`
	ResponseBytes          int `json:"response_bytes"`
}

type CapabilitiesAstra struct {
	Enabled bool     `json:"enabled"`
	Status  string   `json:"status"`
	Actions []string `json:"actions"`
}

type Capabilities struct {
	ServerVersion   string             `json:"server_version"`
	ContractVersion string             `json:"contract_version"`
	PromptBundle    string             `json:"prompt_bundle"`
	RulesetVersion  string             `json:"ruleset_version"`
	Transports      []string           `json:"transports"`
	Scope           []Scope            `json:"scope"`
	Formats         []string           `json:"formats"`
	SupportedChecks []string           `json:"supported_checks"`
	Limits          CapabilitiesLimits `json:"limits"`
	Astra           CapabilitiesAstra  `json:"astra"`
}

type Resolution struct {
	Candidates []Candidate `json:"candidates"`
	Question   *Question   `json:"question,omitempty"`
	Truncated  bool        `json:"truncated"`
}

type Playbook struct {
	ModuleID             string   `json:"module_id"`
	BundleVersion        string   `json:"bundle_version"`
	Content              string   `json:"content"`
	RequiredCapabilities []string `json:"required_capabilities"`
	RelatedModules       []string `json:"related_modules"`
}

type Closure struct {
	DiagnosisID string `json:"diagnosis_id"`
	State       string `json:"state"`
	ClosedAt    string `json:"closed_at"`
}
