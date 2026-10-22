package live

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRunnerHelper(t *testing.T) {
	mode := os.Getenv("LIVE_RUNNER_HELPER")
	if mode == "" {
		return
	}
	if mode == "output" {
		fmt.Print(strings.Repeat("x", 65536))
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	fmt.Println("Forwarding from 127.0.0.1:54321 -> 15000")
	time.Sleep(30 * time.Second)
	os.Exit(0)
}
func helperRunner(mode string) execRunner {
	return execRunner{command: func(ctx context.Context, args []string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRunnerHelper$")
		cmd.Env = append(os.Environ(), "LIVE_RUNNER_HELPER="+mode)
		return cmd
	}}
}
func TestRealRunnerBoundsOutputAndKillsChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	r, _ := helperRunner("output").Run(ctx, nil, 100)
	if !r.Truncated || len(r.Stdout) != 100 {
		t.Fatalf("output limit not applied: %+v", r)
	}
	if time.Since(start) > time.Second {
		t.Fatal("output-limited subprocess was not cancelled promptly")
	}
}
func TestRealRunnerCancellationReapsPortForward(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p, e := helperRunner("wait").Start(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	cancel()
	select {
	case <-p.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("child not reaped after cancellation")
	}
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
}
