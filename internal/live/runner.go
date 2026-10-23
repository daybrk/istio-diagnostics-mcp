package live

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

type commandResult struct {
	Stdout    []byte
	Stderr    string
	Truncated bool
}
type runner interface {
	Run(context.Context, []string, int) (commandResult, error)
	Start(context.Context, []string) (process, error)
}
type process interface {
	Output() io.ReadCloser
	Done() <-chan error
	Close() error
}
type execRunner struct {
	command func(context.Context, []string) *exec.Cmd
}

func (r execRunner) cmd(ctx context.Context, args []string) *exec.Cmd {
	if r.command != nil {
		return r.command(ctx, args)
	}
	return exec.CommandContext(ctx, "kubectl", args...)
}

type boundedWriter struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
	cancel    context.CancelFunc
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	n := len(p)
	remaining := w.limit - w.buffer.Len()
	if remaining < 0 {
		remaining = 0
	}
	if len(p) > remaining {
		w.truncated = true
		p = p[:remaining]
		if w.cancel != nil {
			w.cancel()
		}
	}
	_, _ = w.buffer.Write(p)
	return n, nil
}
func (r execRunner) Run(ctx context.Context, args []string, limit int) (commandResult, error) {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := r.cmd(child, args)
	out := &boundedWriter{limit: limit, cancel: cancel}
	errout := &boundedWriter{limit: 4096}
	cmd.Stdout = out
	cmd.Stderr = errout
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	return commandResult{Stdout: out.buffer.Bytes(), Stderr: errout.buffer.String(), Truncated: out.truncated}, err
}

type execProcess struct {
	output *os.File
	cancel context.CancelFunc
	done   chan error
	exited chan struct{}
	once   sync.Once
}

func (p *execProcess) Output() io.ReadCloser { return p.output }
func (p *execProcess) Done() <-chan error    { return p.done }
func (p *execProcess) Close() error {
	p.once.Do(func() { p.cancel(); _ = p.output.Close(); <-p.exited })
	return nil
}
func (r execRunner) Start(ctx context.Context, args []string) (process, error) {
	child, cancel := context.WithCancel(ctx)
	read, write, e := os.Pipe()
	if e != nil {
		cancel()
		return nil, e
	}
	cmd := r.cmd(child, args)
	cmd.Stdout = write
	cmd.Stderr = write
	cmd.WaitDelay = time.Second
	if e = cmd.Start(); e != nil {
		cancel()
		_ = read.Close()
		_ = write.Close()
		return nil, e
	}
	_ = write.Close()
	p := &execProcess{output: read, cancel: cancel, done: make(chan error, 1), exited: make(chan struct{})}
	go func() { err := cmd.Wait(); p.done <- err; close(p.done); close(p.exited) }()
	return p, nil
}

var errUIDChanged = errors.New("pod UID changed or pod was deleted; collected data cannot be attributed")
