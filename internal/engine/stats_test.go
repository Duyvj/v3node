package engine

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
)

type fakeStatsService interface{}

func TestStatsClientRejectsUnboundedResponseLimit(t *testing.T) {
	if _, err := NewStatsClient("127.0.0.1:10085", time.Second, (64<<20)+1); err == nil {
		t.Fatal("expected oversized stats response limit to be rejected")
	}
}

func TestStatsClientPollWireContract(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "v2ray.core.app.stats.command.StatsService",
		HandlerType: (*fakeStatsService)(nil),
		Methods: []grpc.MethodDesc{{
			MethodName: "QueryStats",
			Handler: func(_ any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
				request := new(queryStatsRequest)
				if err := decode(request); err != nil {
					return nil, err
				}
				if request.Pattern != "user>>>" || request.Reset_ {
					t.Errorf("unexpected request: %#v", request)
				}
				return &queryStatsResponse{Stat: []*statMessage{
					{Name: "user>>>uid-9>>>traffic>>>uplink", Value: 123},
					{Name: "user>>>uid-9>>>traffic>>>downlink", Value: 456},
				}}, nil
			},
		}},
	}, struct{}{})
	go server.Serve(listener)
	defer server.Stop()

	client, err := NewStatsClient(listener.Addr().String(), time.Second, 32<<20)
	if err != nil {
		t.Fatal(err)
	}
	sample, err := client.Poll(context.Background(), 1, map[string]int{"uid-9": 9})
	if err != nil {
		t.Fatal(err)
	}
	if got := sample.Deltas[9]; got.Upload != 123 || got.Download != 456 {
		t.Fatalf("unexpected result: %#v", sample.Deltas)
	}
	if !client.Commit(sample) {
		t.Fatal("sample commit was rejected")
	}
}

func TestStatsClientCumulativeBaselineIsCommittedAfterRetention(t *testing.T) {
	responses := [][]*statMessage{
		{{Name: "user>>>uid-9>>>traffic>>>uplink", Value: 100}},
		{{Name: "user>>>uid-9>>>traffic>>>uplink", Value: 150}},
		{{Name: "user>>>uid-9>>>traffic>>>uplink", Value: 170}},
		{{Name: "user>>>uid-9>>>traffic>>>uplink", Value: 3}},
		{{Name: "user>>>uid-9>>>traffic>>>uplink", Value: 8}},
		{},
		{{Name: "user>>>uid-9>>>traffic>>>uplink", Value: 10}},
	}
	client := newSequenceStatsClient(t, responses)
	users := map[string]int{"uid-9": 9}

	// Simulate accumulator retention failure by deliberately not committing
	// the first sample. The next poll must include all 150 cumulative bytes.
	discarded, err := client.Poll(context.Background(), 11, users)
	if err != nil {
		t.Fatal(err)
	}
	if got := discarded.Deltas[9].Upload; got != 100 {
		t.Fatalf("discarded delta = %d, want 100", got)
	}
	retry, err := client.Poll(context.Background(), 11, users)
	if err != nil {
		t.Fatal(err)
	}
	if got := retry.Deltas[9].Upload; got != 150 {
		t.Fatalf("uncommitted retry delta = %d, want 150", got)
	}
	if !client.Commit(retry) {
		t.Fatal("retry commit was rejected")
	}
	if client.Commit(discarded) {
		t.Fatal("stale sample commit was accepted")
	}

	next, err := client.Poll(context.Background(), 11, users)
	if err != nil {
		t.Fatal(err)
	}
	if got := next.Deltas[9].Upload; got != 20 {
		t.Fatalf("incremental delta = %d, want 20", got)
	}
	if !client.Commit(next) {
		t.Fatal("incremental sample commit was rejected")
	}

	// A counter drop in the same generation indicates an engine-side reset.
	reset, err := client.Poll(context.Background(), 11, users)
	if err != nil {
		t.Fatal(err)
	}
	if got := reset.Deltas[9].Upload; got != 3 {
		t.Fatalf("reset delta = %d, want 3", got)
	}
	if !client.Commit(reset) {
		t.Fatal("reset sample commit was rejected")
	}

	// An explicit engine generation transition always starts from zero even
	// when the new process happens to expose a larger counter immediately.
	generation, err := client.Poll(context.Background(), 12, users)
	if err != nil {
		t.Fatal(err)
	}
	if got := generation.Deltas[9].Upload; got != 8 {
		t.Fatalf("new generation delta = %d, want 8", got)
	}
	if !client.Commit(generation) {
		t.Fatal("new generation sample commit was rejected")
	}

	// A transiently omitted row must not erase its baseline and cause the full
	// cumulative value to be counted again when it reappears.
	sparse, err := client.Poll(context.Background(), 12, users)
	if err != nil {
		t.Fatal(err)
	}
	if len(sparse.Deltas) != 0 {
		t.Fatalf("sparse response deltas = %#v, want none", sparse.Deltas)
	}
	if !client.Commit(sparse) {
		t.Fatal("sparse sample commit was rejected")
	}
	resumed, err := client.Poll(context.Background(), 12, users)
	if err != nil {
		t.Fatal(err)
	}
	if got := resumed.Deltas[9].Upload; got != 2 {
		t.Fatalf("resumed delta = %d, want 2", got)
	}
}

func newSequenceStatsClient(t *testing.T, responses [][]*statMessage) *StatsClient {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	index := 0
	server := grpc.NewServer()
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "v2ray.core.app.stats.command.StatsService",
		HandlerType: (*fakeStatsService)(nil),
		Methods: []grpc.MethodDesc{{
			MethodName: "QueryStats",
			Handler: func(_ any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
				request := new(queryStatsRequest)
				if err := decode(request); err != nil {
					return nil, err
				}
				if request.Reset_ {
					t.Error("cumulative stats query unexpectedly requested reset")
				}
				mu.Lock()
				defer mu.Unlock()
				if index >= len(responses) {
					t.Fatalf("unexpected stats poll %d", index+1)
				}
				response := &queryStatsResponse{Stat: responses[index]}
				index++
				return response, nil
			},
		}},
	}, struct{}{})
	go server.Serve(listener)
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	client, err := NewStatsClient(listener.Addr().String(), time.Second, 32<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}
