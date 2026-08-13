package app

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/Duyvj/v3node/internal/state"
)

// A panel user ID is scoped to a node. Two controllers may therefore receive
// the same integer ID without sharing traffic counters or device admissions.
func TestPerNodeAccountingStateDoesNotMixSameUserID(t *testing.T) {
	firstTraffic, err := state.NewTrafficAccumulator(10)
	if err != nil {
		t.Fatal(err)
	}
	secondTraffic, err := state.NewTrafficAccumulator(10)
	if err != nil {
		t.Fatal(err)
	}
	firstOnline, err := state.NewOnlineTracker(time.Minute, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	secondOnline, err := state.NewOnlineTracker(time.Minute, 10, 2)
	if err != nil {
		t.Fatal(err)
	}

	first := &Controller{traffic: firstTraffic, online: firstOnline}
	second := &Controller{traffic: secondTraffic, online: secondOnline}
	if err := first.traffic.Add(7, 100, 200); err != nil {
		t.Fatal(err)
	}
	if err := second.traffic.Add(7, 300, 400); err != nil {
		t.Fatal(err)
	}
	if err := first.online.Observe(7, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := second.online.Observe(7, "198.51.100.2"); err != nil {
		t.Fatal(err)
	}

	firstBatch := first.traffic.Snapshot()
	secondBatch := second.traffic.Snapshot()
	if len(firstBatch.Users) != 1 || firstBatch.Users[0].Upload != 100 || firstBatch.Users[0].Download != 200 {
		t.Fatalf("first traffic = %#v", firstBatch.Users)
	}
	if len(secondBatch.Users) != 1 || secondBatch.Users[0].Upload != 300 || secondBatch.Users[0].Download != 400 {
		t.Fatalf("second traffic = %#v", secondBatch.Users)
	}
	wantFirst := map[int][]string{7: {"192.0.2.1"}}
	wantSecond := map[int][]string{7: {"198.51.100.2"}}
	if got := first.online.SnapshotMap(); !reflect.DeepEqual(got, wantFirst) {
		t.Fatalf("first online state = %#v, want %#v", got, wantFirst)
	}
	if got := second.online.SnapshotMap(); !reflect.DeepEqual(got, wantSecond) {
		t.Fatalf("second online state = %#v, want %#v", got, wantSecond)
	}

	active := map[int]map[netip.Addr]bool{7: {netip.MustParseAddr("192.0.2.1"): true}}
	policy := map[int]struct{}{7: {}}
	first.online.ReconcileSnapshot(active, policy)
	if second.online.Has(7, "192.0.2.1") {
		t.Fatal("one node's device reconciliation leaked into another node")
	}
}
