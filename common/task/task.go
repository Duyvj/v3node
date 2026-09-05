package task

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// taskCancellationGrace is deliberately short compared with the controller
// reload timeout. Task callbacks receive a cancelled context and must unwind;
// a broken third-party client must not hold reload or shutdown forever.
const taskCancellationGrace = 10 * time.Second

type Task struct {
	Name     string
	Interval time.Duration
	Execute  func(context.Context) error
	Access   sync.RWMutex
	Running  bool
	ReloadCh chan struct{}
	Stop     chan struct{}
	Done     chan struct{}
}

func (t *Task) Start(first bool) error {
	return t.StartAfter(first, 0)
}

// StartAfter starts a periodic task with an optional initial phase offset.
// Subsequent executions retain the configured interval.
func (t *Task) StartAfter(first bool, initialDelay time.Duration) error {
	t.Access.Lock()
	if t.Running {
		t.Access.Unlock()
		return nil
	}
	t.Running = true
	stop := make(chan struct{})
	done := make(chan struct{})
	t.Stop = stop
	t.Done = done
	t.Access.Unlock()
	go func(stop <-chan struct{}, done chan struct{}) {
		defer func() {
			t.Access.Lock()
			if t.Done == done {
				t.Running = false
			}
			t.Access.Unlock()
			close(done)
		}()
		if first {
			if err := t.executeWithTimeout(stop); err != nil {
				log.Errorf("Task %s initial execution error: %v; retrying after %s", t.Name, err, t.Interval)
			}
		}

		if !first && initialDelay > 0 {
			timer := time.NewTimer(initialDelay)
			select {
			case <-timer.C:
			case <-stop:
				timer.Stop()
				return
			}
		}

		timer := time.NewTimer(t.Interval)
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				// continue
			case <-stop:
				return
			}

			if err := t.executeWithTimeout(stop); err != nil {
				// Panel outages are expected control-plane failures, not a reason to
				// permanently stop traffic/accounting synchronization. Keep the
				// periodic worker alive so it heals without restarting Xray.
				log.Errorf("Task %s execution error: %v; keeping runtime and retrying", t.Name, err)
			}
			timer.Reset(t.Interval)
		}
	}(stop, done)

	return nil
}

func (t *Task) ExecuteWithTimeout() error {
	return t.executeWithTimeout(nil)
}

func (t *Task) executeWithTimeout(stop <-chan struct{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), min(5*t.Interval, 5*time.Minute))
	defer cancel()
	done := make(chan error, 1)

	go func() {
		done <- t.Execute(ctx)
	}()

	select {
	case <-stop:
		cancel()
		return waitForTaskCancellation(t.Name, done)
	case <-ctx.Done():
		log.Errorf("Task %s execution timed out, reloading", t.Name)
		if t.ReloadCh != nil {
			select {
			case t.ReloadCh <- struct{}{}:
			default:
			}
		} else {
			log.Panic("Reload failed")
		}
		return waitForTaskCancellation(t.Name, done)
	case err := <-done:
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		return err
	}
}

func waitForTaskCancellation(name string, done <-chan error) error {
	timer := time.NewTimer(taskCancellationGrace)
	defer timer.Stop()
	select {
	case err := <-done:
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		return err
	case <-timer.C:
		return fmt.Errorf("task %s did not stop within %s", name, taskCancellationGrace)
	}
}

func (t *Task) safeStop() <-chan struct{} {
	t.Access.Lock()
	done := t.Done
	if t.Running {
		t.Running = false
		close(t.Stop)
	}
	t.Access.Unlock()
	return done
}

func (t *Task) Close() {
	if done := t.safeStop(); done != nil {
		<-done
	}
	log.Warningf("Task %s stopped", t.Name)
}

// SignalStop prevents future executions without waiting for an already-running
// callback. Terminal process shutdown uses this bounded primitive; Close keeps
// its existing wait-for-completion behavior for ordinary reloads.
func (t *Task) SignalStop() {
	_ = t.safeStop()
}
