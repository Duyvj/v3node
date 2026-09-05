package node

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestParallelNodeWorkBoundsConcurrencyAndKeepsIndexedErrors(t *testing.T) {
	var mu sync.Mutex
	active, maxActive := 0, 0
	errs := parallelNodeWork(context.Background(), 9, func(_ context.Context, i int) error {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		defer func() {
			mu.Lock()
			active--
			mu.Unlock()
		}()
		time.Sleep(time.Millisecond)
		if i == 2 {
			return fmt.Errorf("node %d failed", i)
		}
		return nil
	})

	if maxActive > maxConcurrentNodePreparation {
		t.Fatalf("parallel preparation exceeded limit: got %d, limit %d", maxActive, maxConcurrentNodePreparation)
	}
	if errs[2] == nil {
		t.Fatalf("indexed errors were not retained: %#v", errs)
	}
	if errs[0] != nil || errs[1] != nil || errs[3] != nil {
		t.Fatalf("unexpected errors: %#v", errs)
	}
}

func TestParallelNodeWorkDoesNotLetCancellationHideEarlierIndexedResult(t *testing.T) {
	errs := parallelNodeWork(context.Background(), 3, func(_ context.Context, i int) error {
		if i == 0 {
			time.Sleep(5 * time.Millisecond)
			return nil
		}
		if i == 1 {
			return errors.New("node one failed")
		}
		return nil
	})
	if errs[0] != nil {
		t.Fatalf("node 0 was incorrectly reported after peer cancellation: %v", errs[0])
	}
	if errs[1] == nil {
		t.Fatal("node 1 failure was lost")
	}
}

func TestParallelNodeWorkContextCancellationIsReported(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	errs := parallelNodeWork(ctx, 3, func(context.Context, int) error {
		t.Fatal("work should not start after cancellation")
		return nil
	})
	for i, err := range errs {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("node %d error = %v, want context cancellation", i, err)
		}
	}
}
