package node

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestUserRevisionPollDelayStaggersWithinThreeSeconds(t *testing.T) {
	first := userRevisionPollDelay(0)
	second := userRevisionPollDelay(999)
	if first != userRevisionPollInterval || second != 2999*time.Millisecond {
		t.Fatalf("unexpected stagger: first=%s second=%s", first, second)
	}
	if first < 2*time.Second || second >= 3*time.Second {
		t.Fatalf("stagger outside responsive range: first=%s second=%s", first, second)
	}
}

type revisionClientStub struct {
	revision string
	err      error
}

func (s *revisionClientStub) GetUserRevision(context.Context) (string, error) {
	return s.revision, s.err
}

func TestUserRevisionWatcherRefreshesOnlyAfterAChange(t *testing.T) {
	client := &revisionClientStub{revision: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	refreshes := 0
	watcher := newUserRevisionWatcher(
		client,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		func(context.Context) error {
			refreshes++
			return nil
		},
	)

	if err := watcher.poll(); err != nil {
		t.Fatal(err)
	}
	if refreshes != 1 || watcher.last != client.revision {
		t.Fatalf("change was not committed after refresh: refreshes=%d last=%q", refreshes, watcher.last)
	}
	if err := watcher.poll(); err != nil {
		t.Fatal(err)
	}
	if refreshes != 1 {
		t.Fatalf("unchanged revision caused %d refreshes", refreshes)
	}
}

func TestUserRevisionWatcherRetriesFailedReconciliation(t *testing.T) {
	client := &revisionClientStub{revision: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	wantErr := errors.New("temporary sync failure")
	watcher := newUserRevisionWatcher(
		client,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		func(context.Context) error { return wantErr },
	)

	if err := watcher.poll(); !errors.Is(err, wantErr) {
		t.Fatalf("poll error=%v, want %v", err, wantErr)
	}
	if watcher.last != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("failed reconciliation incorrectly committed revision %q", watcher.last)
	}
}

func TestUserRevisionWatcherPropagatesPanelFailure(t *testing.T) {
	wantErr := errors.New("panel unavailable")
	watcher := newUserRevisionWatcher(
		&revisionClientStub{err: wantErr},
		"",
		func(context.Context) error { return nil },
	)
	if err := watcher.poll(); !errors.Is(err, wantErr) {
		t.Fatalf("poll error=%v, want %v", err, wantErr)
	}
}
