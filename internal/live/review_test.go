package live

import (
	"context"
	"errors"
	"github.com/daybrk/istio-diagnostics-mcp/internal/core"
	"testing"
)

func TestReviewNamedPodUnrelatedForbidden(t *testing.T) {
	f := fixture()
	f.failures["daemonsets"] = errors.New("Forbidden: cannot list daemonsets")
	c := testCollector(f)
	q := core.WorkloadQuery{Context: "cluster", Namespace: "app", Kind: "Pod", Name: "shop-old-a"}
	r, err := c.Resolve(context.Background(), testConfig().LocalPrincipal(), q)
	t.Logf("resolution=%+v err=%v", r, err)
	if err != nil {
		t.Error("unrelated controller list denied, even though exact pod identity and reads are allowed")
	}
	req := request()
	req.Workload = core.WorkloadRef{Context: q.Context, Namespace: q.Namespace, Kind: q.Kind, Name: q.Name, UID: "p1"}
	s, err := c.Collect(context.Background(), testConfig().LocalPrincipal(), req, nil)
	t.Logf("collected pods=%d coverage=%d err=%v", len(s.Pods), len(s.Coverage), err)
	if len(s.Pods) != 1 || len(s.Coverage) == 0 {
		t.Error("unrelated resource failure blocked all partial pod collection")
	}
}
