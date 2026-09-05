package task

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestCloseWaitsForActiveExecutionToObserveCancellation(t *testing.T) {
	started := make(chan struct{})
	finished := make(chan struct{})
	task := &Task{
		Name:     "lifecycle-test",
		Interval: time.Hour,
		Execute: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			close(finished)
			return ctx.Err()
		},
	}
	if err := task.Start(true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("task did not start")
	}

	closed := make(chan struct{})
	go func() {
		task.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("task close did not cancel the active execution")
	}
	select {
	case <-finished:
	default:
		t.Fatal("task close returned before the callback finished")
	}
}

func TestSignalStopDoesNotWaitForAnUncooperativeCallback(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	task := &Task{
		Name:     "terminal-signal-test",
		Interval: time.Hour,
		Execute: func(context.Context) error {
			close(started)
			<-release
			return nil
		},
	}
	if err := task.Start(true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("task did not start")
	}

	startedStop := time.Now()
	task.SignalStop()
	if elapsed := time.Since(startedStop); elapsed > 100*time.Millisecond {
		t.Fatalf("signal stop waited for callback: %v", elapsed)
	}
	close(release)
}

func TestTaskRetriesAfterTransientPanelFailure(t *testing.T) {
	var attempts atomic.Int32
	recovered := make(chan struct{})
	task := &Task{
		Name:     "panel-recovery-test",
		Interval: 10 * time.Millisecond,
		Execute: func(context.Context) error {
			attempt := attempts.Add(1)
			if attempt < 3 {
				return errors.New("panel unavailable")
			}
			if attempt == 3 {
				close(recovered)
			}
			return nil
		},
	}
	if err := task.Start(true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-recovered:
	case <-time.After(time.Second):
		t.Fatalf("task did not recover; attempts=%d", attempts.Load())
	}
	task.Close()
}
