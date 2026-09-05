package node

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	userRevisionPollInterval  = 2 * time.Second
	userRevisionMaxBackoff    = 30 * time.Second
	userRevisionPollTimeout   = 3 * time.Second
	userCredentialSyncTimeout = 30 * time.Second
)

// userRevisionPollDelay provides a small, deterministic stagger for healthy
// polls. It keeps revision changes responsive while avoiding every logical
// node hitting the panel on the same two-second boundary.
func userRevisionPollDelay(entropy uint64) time.Duration {
	return userRevisionPollInterval + time.Duration(entropy%1000)*time.Millisecond
}

type userRevisionClient interface {
	GetUserRevision(context.Context) (string, error)
}

type userRevisionIntervalClient interface {
	UserRevisionPollInterval() time.Duration
}

// userRevisionWatcher keeps the hot path independent from Redis topology.
// It polls only a tiny authenticated marker; the complete list is downloaded
// when that marker changes, and the running Xray core is not restarted.
type userRevisionWatcher struct {
	client       userRevisionClient
	last         string
	refresh      func(context.Context) error
	ctx          context.Context
	cancel       context.CancelFunc
	stop         chan struct{}
	done         chan struct{}
	startOnce    sync.Once
	closeOnce    sync.Once
	jitterSeed   uint64
	pollInterval time.Duration
}

func newUserRevisionWatcher(client userRevisionClient, initial string, refresh func(context.Context) error) *userRevisionWatcher {
	ctx, cancel := context.WithCancel(context.Background())
	pollInterval := userRevisionPollInterval
	if intervalClient, ok := client.(userRevisionIntervalClient); ok {
		pollInterval = intervalClient.UserRevisionPollInterval()
	}
	if pollInterval < time.Second {
		pollInterval = time.Second
	}
	return &userRevisionWatcher{
		client:       client,
		last:         initial,
		refresh:      refresh,
		ctx:          ctx,
		cancel:       cancel,
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
		jitterSeed:   uint64(time.Now().UnixNano()),
		pollInterval: pollInterval,
	}
}

func (w *userRevisionWatcher) Start() {
	if w == nil || w.client == nil || w.refresh == nil {
		return
	}
	w.startOnce.Do(func() { go w.run() })
}

func (w *userRevisionWatcher) run() {
	defer close(w.done)
	delay := userRevisionPollDelayFor(w.pollInterval, w.jitterSeed)
	backoff := w.pollInterval
	for {
		if !w.wait(delay) {
			return
		}
		err := w.poll()
		if err != nil {
			log.WithError(err).Debug("Fast user revision poll failed; periodic user pull remains active")
			delay = backoff
			backoff *= 2
			if backoff > userRevisionMaxBackoff {
				backoff = userRevisionMaxBackoff
			}
			continue
		}
		backoff = w.pollInterval
		w.jitterSeed++
		delay = userRevisionPollDelayFor(w.pollInterval, w.jitterSeed)
	}
}

func userRevisionPollDelayFor(interval time.Duration, entropy uint64) time.Duration {
	if interval <= 0 {
		interval = userRevisionPollInterval
	}
	return interval + time.Duration(entropy%1000)*time.Millisecond
}

func (w *userRevisionWatcher) poll() error {
	pollCtx, cancelPoll := context.WithTimeout(w.ctx, userRevisionPollTimeout)
	defer cancelPoll()
	revision, err := w.client.GetUserRevision(pollCtx)
	if err != nil {
		return err
	}
	if w.last == "" {
		w.last = revision
		return nil
	}
	if revision == w.last {
		return nil
	}

	refreshCtx, cancelRefresh := context.WithTimeout(w.ctx, userCredentialSyncTimeout)
	defer cancelRefresh()
	if err := w.refresh(refreshCtx); err != nil {
		return err
	}
	// Commit the marker only after reconciliation succeeds. A transient panel
	// or runtime failure is retried on the next two-second poll.
	w.last = revision
	return nil
}

func (w *userRevisionWatcher) wait(delay time.Duration) bool {
	if delay <= 0 {
		select {
		case <-w.stop:
			return false
		default:
			return true
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-w.stop:
		return false
	}
}

func (w *userRevisionWatcher) Close() {
	if w == nil {
		return
	}
	w.closeOnce.Do(func() {
		w.cancel()
		close(w.stop)
		w.startOnce.Do(func() { close(w.done) })
		select {
		case <-w.done:
		case <-time.After(5 * time.Second):
			log.Warn("Fast user revision watcher did not stop before timeout")
		}
	})
}
