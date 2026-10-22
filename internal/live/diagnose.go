package live

import (
	"fmt"
	"strings"
	"time"

	"github.com/daybrk/istio-diagnostics-mcp/internal/diagnostics"
)

// Diagnose evaluates a selected proxy plus explicitly selected service evidence.
// Namespace-wide collection does not imply mesh-wide policy visibility.
func Diagnose(s Snapshot, q diagnostics.Request, service string, at time.Time) (diagnostics.Report, error) {
	var r diagnostics.Report
	var err error
	if len(s.Dump) > 0 {
		r, err = diagnostics.Trace(s.Dump, q, at)
		if err != nil {
			return r, err
		}
		audit, auditErr := diagnostics.Analyze(s.Dump, at)
		if auditErr == nil {
			r.ContextChecks = audit.Checks
		}
		r.Limitations = append(r.Limitations, "context_checks are whole-dump audit findings and are not automatically causes of this request's failure.")
	} else {
		if err = q.Validate(); err != nil {
			return r, err
		}
		r = diagnostics.Report{Verdict: "undetermined", Summary: "Proxy configuration could not be collected.", EvaluatedAt: at.UTC().Format(time.RFC3339), Checks: []diagnostics.Check{}, Path: []string{}, Limitations: []string{}}
	}
	add := func(code, status, severity, summary, source, observation, fix string) {
		r.Checks = append(r.Checks, diagnostics.Check{Code: code, Status: status, Severity: severity, Summary: summary, Evidence: []diagnostics.Evidence{{Source: source, Path: "", Observation: observation}}, Recommendation: fix})
	}
	for _, c := range s.Collection {
		if c.Status != "PASS" {
			add("COLLECTION_INCOMPLETE", "UNKNOWN", "warning", "Evidence collection incomplete.", c.Resource, c.Detail, "")
		}
	}
	pod := s.Resources["pod"]
	status := asObject(pod["status"])
	for _, v := range asList(status["conditions"]) {
		condition := asObject(v)
		if condition["type"] == "Ready" && condition["status"] != "True" {
			add("POD_NOT_READY", "FAIL", "warning", "Selected pod is not Ready.", "pod", fmt.Sprint(condition["reason"]), "Inspect container readiness, restarts and application logs.")
		}
	}
	if service != "" {
		if !dnsName.MatchString(service) || strings.Contains(service, ".") {
			return r, fmt.Errorf("service must be an unqualified Service name in the collected namespace")
		}
		svcs, ok := s.Resources["services"]
		if !ok {
			add("SERVICE_UNKNOWN", "UNKNOWN", "warning", "Services could not be collected.", "services", service, "")
		} else {
			var svc diagnostics.Object
			for _, v := range list(svcs) {
				o := asObject(v)
				if asObject(o["metadata"])["name"] == service {
					svc = o
					break
				}
			}
			if svc == nil {
				add("SERVICE_NOT_FOUND", "FAIL", "error", "Requested Service is absent in the collected namespace.", "services", s.Namespace+"/"+service, "Check the name and namespace.")
			} else {
				spec := asObject(svc["spec"])
				if spec["type"] == "ExternalName" {
					add("EXTERNAL_NAME", "UNKNOWN", "info", "Service delegates to DNS; EndpointSlices are not expected.", "service", fmt.Sprint(spec["externalName"]), "")
				} else {
					slices, collected := s.Resources["endpointslices.discovery.k8s.io"]
					count, ready := 0, 0
					for _, v := range list(slices) {
						o := asObject(v)
						labels := asObject(asObject(o["metadata"])["labels"])
						if labels["kubernetes.io/service-name"] != service {
							continue
						}
						for _, v := range asList(o["endpoints"]) {
							ep := asObject(v)
							count++
							conditions := asObject(ep["conditions"])
							if v, exists := conditions["ready"]; !exists || v == nil || v == true {
								ready++
							}
						}
					}
					if !collected {
						add("SERVICE_ENDPOINTS_UNKNOWN", "UNKNOWN", "warning", "EndpointSlices were not collected.", "endpointslices", service, "")
					} else if count == 0 {
						add("SERVICE_NO_ENDPOINTS", "FAIL", "error", "Service has no endpoints in the collected EndpointSlices.", "endpointslices", service, "Check Service selector, workload labels and endpoint controller.")
					} else if ready == 0 {
						add("SERVICE_NO_READY_ENDPOINTS", "FAIL", "warning", "No EndpointSlice endpoints are marked ready; serving/terminating and publishNotReadyAddresses need review.", "endpointslices", service, "Check readiness and Service publishing settings.")
					} else {
						add("SERVICE_ENDPOINTS_PRESENT", "PASS", "info", "EndpointSlice candidates exist; this is not a network test.", "endpointslices", fmt.Sprintf("%s: %d/%d", service, ready, count), "")
					}
				}
			}
		}
	}
	r.Limitations = append(r.Limitations, "Live v0.1 collects one namespace and one selected proxy. Cross-namespace/root policies, remote gateways and effective NetworkPolicy/RBAC decisions are not evaluated.", "No active network probes or application log collection are performed. Namespace policies are collected as context, not treated as proven causes.")
	return r, nil
}
