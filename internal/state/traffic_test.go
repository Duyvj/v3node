package state

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

func TestTrafficSnapshotAckPreservesNewIncrements(t *testing.T) {
	accumulator := mustTrafficAccumulator(t, 3)
	mustAddTraffic(t, accumulator, 2, 10, 20)

	first := accumulator.Snapshot()
	assertTrafficBatch(t, first, []UserTraffic{{UserID: 2, Upload: 10, Download: 20}})
	if first.ID == 0 {
		t.Fatal("non-empty snapshot has zero ID")
	}

	mustAddTraffic(t, accumulator, 2, 3, 4)
	mustAddTraffic(t, accumulator, 1, 5, 6)

	// Snapshot is a defensive copy and must retry the same in-flight payload.
	first.Users[0].Upload = 999
	retry := accumulator.Snapshot()
	assertTrafficBatch(t, retry, []UserTraffic{{UserID: 2, Upload: 10, Download: 20}})
	if retry.ID != first.ID {
		t.Fatalf("retry ID = %d, want %d", retry.ID, first.ID)
	}
	if accumulator.Ack(first.ID + 1) {
		t.Fatal("stale ACK accepted")
	}
	if !accumulator.Ack(first.ID) {
		t.Fatal("active ACK rejected")
	}

	second := accumulator.Snapshot()
	assertTrafficBatch(t, second, []UserTraffic{
		{UserID: 1, Upload: 5, Download: 6},
		{UserID: 2, Upload: 3, Download: 4},
	})
	if second.ID == first.ID || second.ID == 0 {
		t.Fatalf("second snapshot ID = %d, first = %d", second.ID, first.ID)
	}
	if !accumulator.Ack(second.ID) {
		t.Fatal("second ACK rejected")
	}
	if accumulator.Len() != 0 || accumulator.HasInFlight() {
		t.Fatalf("accumulator retained state after ACK: len=%d inFlight=%v", accumulator.Len(), accumulator.HasInFlight())
	}
	if accumulator.Ack(0) {
		t.Fatal("empty batch ACK accepted")
	}
}

func TestTrafficCapacityIncludesInFlightUsers(t *testing.T) {
	accumulator := mustTrafficAccumulator(t, 2)
	mustAddTraffic(t, accumulator, 1, 1, 0)
	mustAddTraffic(t, accumulator, 2, 1, 0)
	batch := accumulator.Snapshot()

	if err := accumulator.Add(3, 1, 0); !errors.Is(err, ErrTrafficCapacity) {
		t.Fatalf("Add beyond capacity error = %v, want ErrTrafficCapacity", err)
	}
	mustAddTraffic(t, accumulator, 1, 2, 0)
	if !accumulator.Ack(batch.ID) {
		t.Fatal("ACK rejected")
	}
	if accumulator.Len() != 1 {
		t.Fatalf("Len after ACK = %d, want 1 pending user", accumulator.Len())
	}
	mustAddTraffic(t, accumulator, 3, 1, 0)
}

func TestTrafficAddBatchPreflightIsAtomic(t *testing.T) {
	accumulator := mustTrafficAccumulator(t, 2)
	mustAddTraffic(t, accumulator, 1, 10, 20)

	// User 2 would fit, but user 3 makes the complete batch exceed capacity.
	// Neither the update to user 1 nor either new user may be retained.
	err := accumulator.AddBatch([]UserTraffic{
		{UserID: 1, Upload: 1, Download: 2},
		{UserID: 2, Upload: 3, Download: 4},
		{UserID: 3, Upload: 5, Download: 6},
	})
	if !errors.Is(err, ErrTrafficCapacity) {
		t.Fatalf("AddBatch capacity error = %v, want ErrTrafficCapacity", err)
	}
	batch := accumulator.Snapshot()
	assertTrafficBatch(t, batch, []UserTraffic{{UserID: 1, Upload: 10, Download: 20}})
}

func TestTrafficAddBatchValidationAndDuplicateAggregation(t *testing.T) {
	accumulator := mustTrafficAccumulator(t, 2)
	err := accumulator.AddBatch([]UserTraffic{
		{UserID: 1, Upload: 10},
		{UserID: 0, Upload: 20},
	})
	if !errors.Is(err, ErrInvalidUserID) {
		t.Fatalf("AddBatch validation error = %v, want ErrInvalidUserID", err)
	}
	if accumulator.Len() != 0 {
		t.Fatalf("invalid batch changed accumulator: len=%d", accumulator.Len())
	}
	if err := accumulator.AddBatch([]UserTraffic{
		{UserID: 1, Upload: math.MaxInt64 - 1, Download: 2},
		{UserID: 1, Upload: 10, Download: 3},
		{UserID: 2},
	}); err != nil {
		t.Fatal(err)
	}
	batch := accumulator.Snapshot()
	assertTrafficBatch(t, batch, []UserTraffic{{UserID: 1, Upload: math.MaxInt64, Download: 5}})
}

func TestTrafficSaturatesAndZeroDeltaDoesNotConsumeCapacity(t *testing.T) {
	accumulator := mustTrafficAccumulator(t, 1)
	if err := accumulator.Add(2, 0, 0); err != nil {
		t.Fatalf("zero Add: %v", err)
	}
	if accumulator.Len() != 0 {
		t.Fatalf("zero Add consumed capacity: len=%d", accumulator.Len())
	}
	mustAddTraffic(t, accumulator, 1, math.MaxInt64-2, math.MaxInt64)
	mustAddTraffic(t, accumulator, 1, 100, 1)
	batch := accumulator.Snapshot()
	assertTrafficBatch(t, batch, []UserTraffic{{UserID: 1, Upload: math.MaxInt64, Download: math.MaxInt64}})
}

func TestTrafficConcurrentAddAndSnapshot(t *testing.T) {
	const (
		workers    = 24
		increments = 2_000
		users      = 8
	)
	accumulator := mustTrafficAccumulator(t, users)

	var writers sync.WaitGroup
	writers.Add(workers)
	var done atomic.Bool
	for worker := 0; worker < workers; worker++ {
		go func(worker int) {
			defer writers.Done()
			userID := worker%users + 1
			for count := 0; count < increments; count++ {
				if err := accumulator.Add(userID, 1, 2); err != nil {
					t.Errorf("concurrent Add: %v", err)
					return
				}
			}
		}(worker)
	}
	go func() {
		writers.Wait()
		done.Store(true)
	}()

	var uploaded, downloaded int64
	for !done.Load() {
		batch := accumulator.Snapshot()
		if batch.Empty() {
			continue
		}
		for _, user := range batch.Users {
			uploaded += user.Upload
			downloaded += user.Download
		}
		if !accumulator.Ack(batch.ID) {
			t.Fatal("concurrent ACK rejected")
		}
	}
	for {
		batch := accumulator.Snapshot()
		if batch.Empty() {
			break
		}
		for _, user := range batch.Users {
			uploaded += user.Upload
			downloaded += user.Download
		}
		if !accumulator.Ack(batch.ID) {
			t.Fatal("drain ACK rejected")
		}
	}

	want := int64(workers * increments)
	if uploaded != want || downloaded != 2*want {
		t.Fatalf("reported upload/download = %d/%d, want %d/%d", uploaded, downloaded, want, 2*want)
	}
}

func TestTrafficCheckpointRoundTripAndReplace(t *testing.T) {
	accumulator := mustTrafficAccumulator(t, 4)
	if accumulator.CheckpointDirty() {
		t.Fatal("new empty accumulator is unexpectedly dirty")
	}
	mustAddTraffic(t, accumulator, 2, 10, 20)
	if !accumulator.CheckpointDirty() {
		t.Fatal("traffic addition did not dirty the checkpoint")
	}
	active := accumulator.Snapshot()
	mustAddTraffic(t, accumulator, 2, 3, 4)
	mustAddTraffic(t, accumulator, 1, 5, 6)

	path := filepath.Join(t.TempDir(), "traffic.json")
	if err := accumulator.SaveCheckpoint(path); err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}
	if accumulator.CheckpointDirty() {
		t.Fatal("successful checkpoint did not clear dirty state")
	}
	// Exercise atomic replacement of an existing checkpoint.
	if err := accumulator.SaveCheckpoint(path); err != nil {
		t.Fatalf("replace SaveCheckpoint: %v", err)
	}

	restored, err := LoadTrafficAccumulator(path, 4)
	if err != nil {
		t.Fatalf("LoadTrafficAccumulator: %v", err)
	}
	if restored.CheckpointDirty() {
		t.Fatal("restored checkpoint is unexpectedly dirty")
	}
	retry := restored.Snapshot()
	if retry.ID != active.ID {
		t.Fatalf("restored active ID = %d, want %d", retry.ID, active.ID)
	}
	assertTrafficBatch(t, retry, []UserTraffic{{UserID: 2, Upload: 10, Download: 20}})
	if !restored.Ack(retry.ID) {
		t.Fatal("restored active ACK rejected")
	}
	pending := restored.Snapshot()
	assertTrafficBatch(t, pending, []UserTraffic{
		{UserID: 1, Upload: 5, Download: 6},
		{UserID: 2, Upload: 3, Download: 4},
	})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat checkpoint: %v", err)
	}
	// Windows does not expose Unix ACLs through os.FileMode.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("checkpoint permissions = %o, want no group/other access", info.Mode().Perm())
	}
}

func TestTrafficCheckpointRejectsInvalidData(t *testing.T) {
	directory := t.TempDir()
	tests := map[string]string{
		"unknown field":  `{"version":1,"surprise":true}`,
		"trailing JSON":  `{"version":1} {"version":1}`,
		"duplicate":      `{"version":1,"pending":[{"user_id":1,"upload":1,"download":0},{"user_id":1,"upload":2,"download":0}]}`,
		"zero traffic":   `{"version":1,"pending":[{"user_id":1,"upload":0,"download":0}]}`,
		"invalid active": `{"version":1,"active":{"id":0,"users":[{"user_id":1,"upload":1,"download":0}]}}`,
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, name+".json")
			if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if _, err := LoadTrafficAccumulator(path, 4); err == nil {
				t.Fatal("invalid checkpoint accepted")
			}
		})
	}
}

func TestStateConstructorsValidateBounds(t *testing.T) {
	for _, capacity := range []int{-1, 0, MaxTrafficUsers + 1} {
		if _, err := NewTrafficAccumulator(capacity); !errors.Is(err, ErrInvalidCapacity) {
			t.Fatalf("NewTrafficAccumulator(%d) error = %v", capacity, err)
		}
	}
	accumulator := mustTrafficAccumulator(t, 1)
	if err := accumulator.Add(0, 1, 1); !errors.Is(err, ErrInvalidUserID) {
		t.Fatalf("Add invalid user error = %v", err)
	}
	if err := accumulator.Add(1, -1, 0); !errors.Is(err, ErrInvalidTraffic) {
		t.Fatalf("Add negative traffic error = %v", err)
	}
}

func mustTrafficAccumulator(t *testing.T, maxUsers int) *TrafficAccumulator {
	t.Helper()
	accumulator, err := NewTrafficAccumulator(maxUsers)
	if err != nil {
		t.Fatalf("NewTrafficAccumulator: %v", err)
	}
	return accumulator
}

func mustAddTraffic(t *testing.T, accumulator *TrafficAccumulator, userID int, upload, download int64) {
	t.Helper()
	if err := accumulator.Add(userID, upload, download); err != nil {
		t.Fatalf("Add(%d): %v", userID, err)
	}
}

func assertTrafficBatch(t *testing.T, batch TrafficBatch, want []UserTraffic) {
	t.Helper()
	if len(batch.Users) != len(want) {
		t.Fatalf("batch users = %#v, want %#v", batch.Users, want)
	}
	for index := range want {
		if batch.Users[index] != want[index] {
			t.Fatalf("batch user[%d] = %#v, want %#v", index, batch.Users[index], want[index])
		}
	}
}
