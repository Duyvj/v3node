package core

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/Duyvj/v3node/common/counter"
	"github.com/Duyvj/v3node/core/app/dispatcher"
)

func TestPrepareUserTrafficCaptureContextReturnsAtDeadlineWhenUserMapIsWriteLocked(t *testing.T) {
	core := New(nil)
	core.dispatcher = &dispatcher.DefaultDispatcher{}
	core.users.mapLock.Lock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := core.PrepareUserTrafficCaptureContext(ctx, "node", 0)
	core.users.mapLock.Unlock()

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("capture error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("capture ignored its context while waiting for the user map: %v", elapsed)
	}
}

func TestGetUserTrafficSnapshotAggregatesByUIDWithoutReset(t *testing.T) {
	core := New(nil)
	core.dispatcher = &dispatcher.DefaultDispatcher{}
	core.users.uidMap["node|uuid-a"] = 9
	core.users.uidMap["node|uuid-b"] = 9

	traffic := counter.NewTrafficCounter()
	traffic.Rx("node|uuid-a", 600)
	traffic.Tx("node|uuid-a", 400)
	traffic.Rx("node|uuid-b", 1_500)
	core.dispatcher.Counter.Store("node", traffic)

	snapshot := core.GetUserTrafficSnapshot("node")
	if snapshot[9] != 2_500 {
		t.Fatalf("expected traffic from both UUIDs to aggregate to UID 9, got %d", snapshot[9])
	}
	if got := traffic.GetDownCount("node|uuid-a") + traffic.GetUpCount("node|uuid-a"); got != 1_000 {
		t.Fatalf("snapshot reset the underlying counter: got %d", got)
	}
}

func TestGetUserTrafficSnapshotAndSliceNeverLosesConcurrentAdds(t *testing.T) {
	core := New(nil)
	core.dispatcher = &dispatcher.DefaultDispatcher{}
	core.users.uidMap["node|uuid-a"] = 9

	traffic := counter.NewTrafficCounter()
	traffic.Rx("node|uuid-a", 1)
	core.dispatcher.Counter.Store("node", traffic)

	const workers = 8
	const additions = 25_000
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < additions; j++ {
				traffic.Rx("node|uuid-a", 1)
			}
		}()
	}

	var captured int64
	for i := 0; i < 100; i++ {
		_, report, err := core.GetUserTrafficSnapshotAndSlice("node", 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range report {
			captured += item.Upload + item.Download
		}
	}
	wg.Wait()
	_, report, err := core.GetUserTrafficSnapshotAndSlice("node", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range report {
		captured += item.Upload + item.Download
	}

	want := int64(1 + workers*additions)
	if captured != want {
		t.Fatalf("atomic capture lost traffic: got %d, want %d", captured, want)
	}
}

func TestPreparedTrafficCaptureSubtractsOnlyAfterDurableCommit(t *testing.T) {
	core := New(nil)
	core.dispatcher = &dispatcher.DefaultDispatcher{}
	core.users.uidMap["node|uuid-a"] = 9
	traffic := counter.NewTrafficCounter()
	traffic.Rx("node|uuid-a", 100)
	core.dispatcher.Counter.Store("node", traffic)

	capture, err := core.PrepareUserTrafficCapture("node", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := traffic.GetDownCount("node|uuid-a"); got != 100 {
		t.Fatalf("prepare mutated the live counter before fsync: %d", got)
	}
	traffic.Rx("node|uuid-a", 50)
	capture.Commit()
	if got := traffic.GetDownCount("node|uuid-a"); got != 50 {
		t.Fatalf("commit removed concurrent bytes: got %d, want 50", got)
	}
	capture.Commit()
	if got := traffic.GetDownCount("node|uuid-a"); got != 50 {
		t.Fatalf("capture commit was not idempotent: %d", got)
	}
}

func TestGetUserTrafficSnapshotAndSliceReadsBeforeFilteredReset(t *testing.T) {
	core := New(nil)
	core.dispatcher = &dispatcher.DefaultDispatcher{}
	core.users.uidMap["node|uuid-a"] = 9
	core.users.uidMap["node|uuid-b"] = 9

	traffic := counter.NewTrafficCounter()
	traffic.Rx("node|uuid-a", 600)
	traffic.Tx("node|uuid-a", 400)
	traffic.Rx("node|uuid-b", 1_500)
	core.dispatcher.Counter.Store("node", traffic)

	snapshot, report, err := core.GetUserTrafficSnapshotAndSlice("node", 1)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot[9] != 2_500 {
		t.Fatalf("expected pre-reset aggregate of 2500 bytes, got %d", snapshot[9])
	}
	if len(report) != 1 || report[0].UID != 9 || report[0].Download != 1_500 {
		t.Fatalf("expected only traffic above the report threshold, got %#v", report)
	}
	if got := traffic.GetDownCount("node|uuid-a") + traffic.GetUpCount("node|uuid-a"); got != 1_000 {
		t.Fatalf("traffic at the report threshold should not reset, got %d", got)
	}
	if got := traffic.GetDownCount("node|uuid-b"); got != 0 {
		t.Fatalf("reported traffic should reset, got %d", got)
	}
}

func TestShadowsocks2022RejectsShortCredentialWithoutPanicking(t *testing.T) {
	if _, err := buildSSUsers("node", []panel.UserInfo{{Id: 1, Uuid: "short"}},
		"2022-blake3-aes-256-gcm", "server-key"); err == nil {
		t.Fatal("short Shadowsocks 2022 credential was accepted")
	}
}

func TestAddUsersDoesNotPublishInvalidCredentialOwnership(t *testing.T) {
	core := New(nil)
	params := &AddUsersParams{
		Tag:   "node",
		Users: []panel.UserInfo{{Id: 9, Uuid: "short"}},
		NodeInfo: &panel.NodeInfo{
			Type: "shadowsocks",
			Common: &panel.CommonNode{
				Cipher:    "2022-blake3-aes-256-gcm",
				ServerKey: "server-key",
			},
		},
	}
	if _, err := core.AddUsers(params); err == nil {
		t.Fatal("invalid credential was accepted")
	}
	if len(core.users.uidMap) != 0 {
		t.Fatal("failed add published a phantom traffic owner")
	}
}

func TestClassicShadowsocksRejectsUnknownCipher(t *testing.T) {
	if _, err := buildSSUsers("node", []panel.UserInfo{{Id: 1, Uuid: "secret"}},
		"not-a-cipher", ""); err == nil {
		t.Fatal("unknown Shadowsocks cipher was accepted")
	}
}
