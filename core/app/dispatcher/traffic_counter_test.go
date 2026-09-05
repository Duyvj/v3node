package dispatcher

import (
	"sync"
	"testing"

	"github.com/Duyvj/v3node/common/counter"
)

func TestTrafficCounterInitializationIsAtomic(t *testing.T) {
	dispatcher := &DefaultDispatcher{}
	const workers = 128
	results := make(chan *counter.TrafficCounter, workers)
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			results <- dispatcher.trafficCounter("node")
		}()
	}
	group.Wait()
	close(results)

	var first *counter.TrafficCounter
	for result := range results {
		if first == nil {
			first = result
			continue
		}
		if result != first {
			t.Fatal("concurrent sessions received detached traffic counters")
		}
	}
	stored, ok := dispatcher.Counter.Load("node")
	if !ok || stored != first {
		t.Fatal("dispatcher did not retain the shared counter")
	}
}
