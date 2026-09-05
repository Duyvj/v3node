package dispatcher

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

const defaultTrafficDrainTimeout = 5 * time.Second

// ErrTrafficDrainTimeout reports that a quiesce barrier was installed but an
// already-started read did not finish publishing its traffic count in time.
// Callers must not treat the associated traffic snapshot as final.
var ErrTrafficDrainTimeout = errors.New("timed out waiting for traffic reads to drain")

// ErrManagedLinkShutdownTimeout reports that a managed reader or writer did
// not return from its shutdown hook before the quiesce deadline.
var ErrManagedLinkShutdownTimeout = errors.New("timed out shutting down managed links")

type ManagedWriter struct {
	writer  buf.Writer
	manager *LinkManager
}

func (w *ManagedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.writer.WriteMultiBuffer(mb)
}

func (w *ManagedWriter) Close() error {
	if w.manager != nil {
		w.manager.RemoveWriter(w)
	}
	return common.Close(w.writer)
}

// trafficWriter makes the counter update and the quiesce decision one
// ordered operation. Once LinkManager.CloseAll establishes the barrier, a
// stale session cannot add bytes after the controller has taken its final
// durable capture.
type trafficWriter struct {
	writer  buf.Writer
	manager *LinkManager
	counter *atomic.Int64
}

func (w *trafficWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	amount := int64(mb.Len())
	if w.manager != nil {
		// Keep the whole underlying write inside the same accounting barrier as
		// reads. Count only a write accepted by the transport, and never let its
		// counter update occur after a final durable capture.
		if !w.manager.beginCounterRead() {
			buf.ReleaseMulti(mb)
			return io.ErrClosedPipe
		}
		err := w.writer.WriteMultiBuffer(mb)
		if err != nil {
			amount = 0
		}
		w.manager.finishCounterRead(w.counter, amount)
		return err
	}
	err := w.writer.WriteMultiBuffer(mb)
	if err == nil && w.counter != nil && amount > 0 {
		w.counter.Add(amount)
	}
	return err
}

func (w *trafficWriter) Close() error {
	return common.Close(w.writer)
}

func (w *trafficWriter) Interrupt() {
	common.Interrupt(w.writer)
}

type LinkManager struct {
	links        map[*ManagedWriter]buf.Reader
	mu           sync.RWMutex
	closed       bool
	quiesced     bool
	tagQuiesced  bool
	activeReads  int
	readsDrained chan struct{}
	drainTimeout time.Duration
	shutdowns    []*managedLinkShutdown
	onEmpty      func(*LinkManager)
	activeLinks  *atomic.Int64
	maxPerUser   int
	maxGlobal    int
}

func (m *LinkManager) AddLink(writer *ManagedWriter, reader buf.Reader) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || (m.maxPerUser > 0 && len(m.links) >= m.maxPerUser) {
		return false
	}
	if !m.reserveGlobalLink() {
		return false
	}
	m.links[writer] = reader
	return true
}

func (m *LinkManager) reserveGlobalLink() bool {
	if m.activeLinks == nil {
		return true
	}
	for {
		current := m.activeLinks.Load()
		if m.maxGlobal > 0 && current >= int64(m.maxGlobal) {
			return false
		}
		if m.activeLinks.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func (m *LinkManager) releaseGlobalLinks(count int) {
	if m.activeLinks != nil && count > 0 {
		m.activeLinks.Add(-int64(count))
	}
}

func (m *LinkManager) RemoveWriter(writer *ManagedWriter) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	if _, exists := m.links[writer]; !exists {
		m.mu.Unlock()
		return
	}
	delete(m.links, writer)
	m.releaseGlobalLinks(1)
	if len(m.links) == 0 {
		m.closed = true
		onEmpty := m.onEmpty
		m.mu.Unlock()
		if onEmpty != nil {
			// A read may already have returned bytes but not yet published its
			// counter update. Keep the manager discoverable until that update is
			// complete. Waiting asynchronously also avoids deadlocking a close
			// invoked by the same session goroutine.
			go func() {
				if err := m.WaitForCounterReads(); err != nil {
					// Keep the retired manager discoverable. A later registration
					// can retry the bounded drain without losing track of late bytes.
					return
				}
				onEmpty(m)
			}()
		}
		return
	}
	m.mu.Unlock()
}

func (m *LinkManager) beginCounterRead() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return false
	}
	if m.activeReads == 0 {
		m.readsDrained = make(chan struct{})
	}
	m.activeReads++
	return true
}

func (m *LinkManager) finishCounterRead(counter *atomic.Int64, amount int64) {
	if counter != nil && amount > 0 {
		counter.Add(amount)
	}
	m.mu.Lock()
	m.activeReads--
	if m.activeReads == 0 {
		close(m.readsDrained)
	}
	m.mu.Unlock()
}

func (m *LinkManager) IsQuiesced() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.quiesced || m.tagQuiesced
}

func (m *LinkManager) CanRemove() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.closed && !m.quiesced && !m.tagQuiesced && len(m.links) == 0 && m.activeReads == 0
}

func (m *LinkManager) IsAtCapacity() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.maxPerUser > 0 && len(m.links) >= m.maxPerUser {
		return true
	}
	return m.activeLinks != nil && m.maxGlobal > 0 && m.activeLinks.Load() >= int64(m.maxGlobal)
}

func (m *LinkManager) trafficDrainTimeout() time.Duration {
	if m.drainTimeout > 0 {
		return m.drainTimeout
	}
	return defaultTrafficDrainTimeout
}

func (m *LinkManager) waitForCounterReads(timeout time.Duration) error {
	return m.waitForCounterReadsContext(context.Background(), timeout)
}

func (m *LinkManager) waitForCounterReadsContext(ctx context.Context, timeout time.Duration) error {
	m.mu.RLock()
	if m.activeReads == 0 {
		m.mu.RUnlock()
		return nil
	}
	drained := m.readsDrained
	m.mu.RUnlock()

	if timeout <= 0 {
		return ErrTrafficDrainTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ErrTrafficDrainTimeout
	}
}

func (m *LinkManager) WaitForCounterReads() error {
	return m.waitForCounterReads(m.trafficDrainTimeout())
}

func (m *LinkManager) beginCloseAll(quiesce bool) []*managedLinkShutdown {
	m.mu.Lock()
	if quiesce {
		m.quiesced = true
	}
	links := m.detachLinksLocked()
	shutdowns := m.trackShutdownLocked(links)
	m.mu.Unlock()
	return shutdowns
}

func (m *LinkManager) beginTagClose() []*managedLinkShutdown {
	m.mu.Lock()
	m.tagQuiesced = true
	links := m.detachLinksLocked()
	shutdowns := m.trackShutdownLocked(links)
	m.mu.Unlock()
	return shutdowns
}

func (m *LinkManager) detachLinksLocked() map[*ManagedWriter]buf.Reader {
	if m.closed {
		return nil
	}
	m.closed = true

	links := m.links
	m.links = make(map[*ManagedWriter]buf.Reader)
	m.releaseGlobalLinks(len(links))
	return links
}

func (m *LinkManager) trackShutdownLocked(links map[*ManagedWriter]buf.Reader) []*managedLinkShutdown {
	pending := m.shutdowns[:0]
	for _, shutdown := range m.shutdowns {
		// A completed shutdown hook may have reported an error once, but it no
		// longer threatens liveness or accounting. Retaining it would replay the
		// same error on every retry and make graceful shutdown impossible forever.
		if _, done := shutdown.result(); !done {
			pending = append(pending, shutdown)
		}
	}
	m.shutdowns = pending
	if len(links) > 0 {
		m.shutdowns = append(m.shutdowns, interruptManagedLinks(links))
	}
	return append([]*managedLinkShutdown(nil), m.shutdowns...)
}

func (m *LinkManager) reactivateUser() {
	m.mu.Lock()
	wasQuiesced := m.quiesced
	m.quiesced = false
	if wasQuiesced && !m.tagQuiesced {
		m.closed = false
	}
	m.mu.Unlock()
}

func (m *LinkManager) reactivateTag() {
	m.mu.Lock()
	wasQuiesced := m.tagQuiesced
	m.tagQuiesced = false
	if wasQuiesced && !m.quiesced {
		m.closed = false
	}
	m.mu.Unlock()
}

type managedLinkShutdown struct {
	mu      sync.Mutex
	pending int
	err     error
	done    chan struct{}
}

func interruptManagedLinks(links map[*ManagedWriter]buf.Reader) *managedLinkShutdown {
	shutdown := &managedLinkShutdown{
		pending: len(links) * 2,
		done:    make(chan struct{}),
	}
	if shutdown.pending == 0 {
		close(shutdown.done)
		return shutdown
	}
	for w, r := range links {
		go func(writer buf.Writer) {
			shutdown.finish(common.Close(writer))
		}(w.writer)
		go func(reader buf.Reader) {
			shutdown.finish(common.Interrupt(reader))
		}(r)
	}
	return shutdown
}

func (s *managedLinkShutdown) finish(err error) {
	s.mu.Lock()
	s.err = errors.Join(s.err, err)
	s.pending--
	if s.pending == 0 {
		close(s.done)
	}
	s.mu.Unlock()
}

func (s *managedLinkShutdown) result() (error, bool) {
	select {
	case <-s.done:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.err, true
	default:
		return nil, false
	}
}

func (s *managedLinkShutdown) waitUntil(deadline time.Time) error {
	return s.waitUntilContext(context.Background(), deadline)
}

func (s *managedLinkShutdown) waitUntilContext(ctx context.Context, deadline time.Time) error {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		if err, done := s.result(); done {
			return err
		}
		return ErrManagedLinkShutdownTimeout
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-s.done:
		err, _ := s.result()
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ErrManagedLinkShutdownTimeout
	}
}

func (m *LinkManager) finishCloseAll(shutdowns []*managedLinkShutdown) error {
	return m.finishCloseAllContext(context.Background(), shutdowns)
}

func (m *LinkManager) finishCloseAllContext(ctx context.Context, shutdowns []*managedLinkShutdown) error {
	deadline := time.Now().Add(m.trafficDrainTimeout())
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	var shutdownErr error
	for _, shutdown := range shutdowns {
		shutdownErr = errors.Join(shutdownErr, shutdown.waitUntilContext(ctx, deadline))
	}
	// CounterReader publishes its final byte count before signaling the drain.
	// The controller can therefore capture immediately after a successful
	// CloseAll without racing a late read completion.
	drainErr := m.waitForCounterReadsContext(ctx, time.Until(deadline))
	return errors.Join(shutdownErr, drainErr)
}

func (m *LinkManager) closeAll(quiesce bool) error {
	shutdowns := m.beginCloseAll(quiesce)
	return m.finishCloseAll(shutdowns)
}

func (m *LinkManager) CloseAll() error {
	return m.closeAll(false)
}

func (m *LinkManager) QuiesceAll() error {
	return m.closeAll(true)
}
