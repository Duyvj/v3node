package state

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOnlineTrackerTTLAndCanonicalAddress(t *testing.T) {
	tracker := mustOnlineTracker(t, time.Minute, 4, 2)
	start := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)

	if err := tracker.ObserveAt(1, "::ffff:192.0.2.1", start); err != nil {
		t.Fatalf("ObserveAt mapped IPv4: %v", err)
	}
	if err := tracker.ObserveAt(1, "192.0.2.1", start.Add(30*time.Second)); err != nil {
		t.Fatalf("ObserveAt IPv4: %v", err)
	}
	if got := tracker.SnapshotAt(start.Add(89 * time.Second)); !reflect.DeepEqual(got, []OnlineUser{{UserID: 1, IPs: []string{"192.0.2.1"}}}) {
		t.Fatalf("Snapshot before expiry = %#v", got)
	}
	if got := tracker.SnapshotAt(start.Add(90 * time.Second)); len(got) != 0 {
		t.Fatalf("Snapshot at expiry = %#v, want empty", got)
	}
}

func TestOnlineTrackerPerUserLRU(t *testing.T) {
	tracker := mustOnlineTracker(t, time.Hour, 8, 2)
	start := time.Unix(1_800_000_000, 0)
	mustObserve(t, tracker, 1, "192.0.2.1", start)
	mustObserve(t, tracker, 1, "192.0.2.2", start.Add(time.Second))
	mustObserve(t, tracker, 1, "192.0.2.1", start.Add(2*time.Second))
	mustObserve(t, tracker, 1, "192.0.2.3", start.Add(3*time.Second))

	want := []OnlineUser{{UserID: 1, IPs: []string{"192.0.2.1", "192.0.2.3"}}}
	if got := tracker.SnapshotAt(start.Add(4 * time.Second)); !reflect.DeepEqual(got, want) {
		t.Fatalf("Snapshot = %#v, want %#v", got, want)
	}
}

func TestOnlineTrackerGlobalLRU(t *testing.T) {
	tracker := mustOnlineTracker(t, time.Hour, 3, 3)
	start := time.Unix(1_800_000_000, 0)
	mustObserve(t, tracker, 1, "192.0.2.1", start)
	mustObserve(t, tracker, 2, "192.0.2.2", start.Add(time.Second))
	mustObserve(t, tracker, 3, "192.0.2.3", start.Add(2*time.Second))
	// Refresh user 1 so user 2 is globally least recent.
	mustObserve(t, tracker, 1, "192.0.2.1", start.Add(3*time.Second))
	mustObserve(t, tracker, 4, "192.0.2.4", start.Add(4*time.Second))

	want := []OnlineUser{
		{UserID: 1, IPs: []string{"192.0.2.1"}},
		{UserID: 3, IPs: []string{"192.0.2.3"}},
		{UserID: 4, IPs: []string{"192.0.2.4"}},
	}
	if got := tracker.SnapshotAt(start.Add(5 * time.Second)); !reflect.DeepEqual(got, want) {
		t.Fatalf("Snapshot = %#v, want %#v", got, want)
	}
}

func TestOnlineTrackerSnapshotDeterministicAndIndependent(t *testing.T) {
	tracker := mustOnlineTracker(t, time.Hour, 8, 4)
	start := time.Unix(1_800_000_000, 0)
	mustObserve(t, tracker, 9, "2001:db8::2", start)
	mustObserve(t, tracker, 2, "2001:db8::1", start.Add(time.Second))
	mustObserve(t, tracker, 2, "192.0.2.9", start.Add(2*time.Second))

	want := []OnlineUser{
		{UserID: 2, IPs: []string{"192.0.2.9", "2001:db8::1"}},
		{UserID: 9, IPs: []string{"2001:db8::2"}},
	}
	first := tracker.SnapshotAt(start.Add(3 * time.Second))
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("Snapshot = %#v, want %#v", first, want)
	}
	first[0].IPs[0] = "mutated"
	if second := tracker.SnapshotAt(start.Add(3 * time.Second)); !reflect.DeepEqual(second, want) {
		t.Fatalf("snapshot mutation affected tracker: %#v", second)
	}
}

func TestOnlineTrackerClampsClockRegression(t *testing.T) {
	tracker := mustOnlineTracker(t, time.Minute, 4, 2)
	start := time.Unix(1_800_000_000, 0)
	mustObserve(t, tracker, 1, "192.0.2.1", start)
	// A backward wall-clock correction must not reorder expiration state.
	mustObserve(t, tracker, 2, "192.0.2.2", start.Add(-time.Hour))
	if got := tracker.LenAt(start.Add(59 * time.Second)); got != 2 {
		t.Fatalf("Len before expiry = %d, want 2", got)
	}
	if got := tracker.PurgeAt(start.Add(time.Minute)); got != 2 {
		t.Fatalf("Purge at expiry = %d, want 2", got)
	}
}

func TestOnlineTrackerForgetUserAndInvalidInput(t *testing.T) {
	tracker := mustOnlineTracker(t, time.Hour, 4, 2)
	start := time.Unix(1_800_000_000, 0)
	for _, invalid := range []string{"", "not-an-ip", "fe80::1%eth0", strings.Repeat("1", 65)} {
		if err := tracker.ObserveAt(1, invalid, start); !errors.Is(err, ErrInvalidIP) {
			t.Fatalf("ObserveAt(%q) error = %v", invalid, err)
		}
	}
	if err := tracker.ObserveAt(0, "192.0.2.1", start); !errors.Is(err, ErrInvalidUserID) {
		t.Fatalf("invalid user error = %v", err)
	}
	mustObserve(t, tracker, 1, "192.0.2.1", start)
	mustObserve(t, tracker, 1, "192.0.2.2", start)
	mustObserve(t, tracker, 2, "192.0.2.3", start)
	if removed := tracker.ForgetUser(1); removed != 2 {
		t.Fatalf("ForgetUser removed %d, want 2", removed)
	}
	if tracker.LenAt(start) != 1 {
		t.Fatalf("Len after ForgetUser = %d, want 1", tracker.LenAt(start))
	}
}

func TestOnlineTrackerConcurrentBounded(t *testing.T) {
	const (
		global  = 64
		perUser = 4
		workers = 16
	)
	tracker := mustOnlineTracker(t, time.Hour, global, perUser)
	start := time.Unix(1_800_000_000, 0)

	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func(worker int) {
			defer wait.Done()
			for iteration := 0; iteration < 500; iteration++ {
				address := fmt.Sprintf("198.51.%d.%d", worker%10, iteration%250+1)
				if err := tracker.ObserveAt(worker%20+1, address, start.Add(time.Duration(iteration)*time.Millisecond)); err != nil {
					t.Errorf("ObserveAt: %v", err)
					return
				}
				if iteration%25 == 0 {
					_ = tracker.SnapshotAt(start.Add(time.Duration(iteration) * time.Millisecond))
				}
			}
		}(worker)
	}
	wait.Wait()

	rows := tracker.SnapshotAt(start.Add(time.Second))
	total := 0
	for _, row := range rows {
		if len(row.IPs) > perUser {
			t.Fatalf("user %d retained %d IPs, limit %d", row.UserID, len(row.IPs), perUser)
		}
		total += len(row.IPs)
	}
	if total > global || tracker.LenAt(start.Add(time.Second)) > global {
		t.Fatalf("global entries = %d, limit %d", total, global)
	}
}

func TestOnlineTrackerConstructorValidation(t *testing.T) {
	tests := []struct {
		ttl             time.Duration
		global, perUser int
		want            error
	}{
		{ttl: 0, global: 1, perUser: 1, want: ErrInvalidTTL},
		{ttl: time.Second, global: 0, perUser: 1, want: ErrInvalidCapacity},
		{ttl: time.Second, global: 2, perUser: 3, want: ErrInvalidCapacity},
		{ttl: time.Second, global: MaxOnlineEntries + 1, perUser: 1, want: ErrInvalidCapacity},
	}
	for _, test := range tests {
		if _, err := NewOnlineTracker(test.ttl, test.global, test.perUser); !errors.Is(err, test.want) {
			t.Fatalf("NewOnlineTracker(%s,%d,%d) error = %v, want %v", test.ttl, test.global, test.perUser, err, test.want)
		}
	}
}

func TestOnlineTrackerReserveDoesNotReportUntilObserved(t *testing.T) {
	tracker, err := NewOnlineTracker(time.Minute, 10, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Reserve(7, "192.0.2.7"); err != nil {
		t.Fatal(err)
	}
	if !tracker.Has(7, "192.0.2.7") || tracker.UserLen(7) != 1 {
		t.Fatal("reserved device is not retained for enforcement")
	}
	if got := tracker.SnapshotReportableMap(); len(got) != 0 {
		t.Fatalf("reserved low-traffic device was reported: %#v", got)
	}
	if err := tracker.Observe(7, "192.0.2.7"); err != nil {
		t.Fatal(err)
	}
	got := tracker.SnapshotReportableMap()
	if len(got[7]) != 1 || got[7][0] != "192.0.2.7" {
		t.Fatalf("observed device was not promoted: %#v", got)
	}
}

func mustOnlineTracker(t *testing.T, ttl time.Duration, global, perUser int) *OnlineTracker {
	t.Helper()
	tracker, err := NewOnlineTracker(ttl, global, perUser)
	if err != nil {
		t.Fatalf("NewOnlineTracker: %v", err)
	}
	return tracker
}

func mustObserve(t *testing.T, tracker *OnlineTracker, userID int, address string, now time.Time) {
	t.Helper()
	if err := tracker.ObserveAt(userID, address, now); err != nil {
		t.Fatalf("ObserveAt(%d,%q): %v", userID, address, err)
	}
}
