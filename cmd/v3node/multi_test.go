package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Duyvj/v3node/internal/config"
	"github.com/Duyvj/v3node/internal/engine"
)

type workerRunnerFunc func(context.Context) error

func (f workerRunnerFunc) Run(ctx context.Context) error { return f(ctx) }

func TestListenerRegistryRejectsSameNumericPortAcrossTCPAndUDP(t *testing.T) {
	registry := newListenerRegistry()
	releaseTCP, err := registry.Reserve(engine.NodeSpec{Protocol: "vless", Port: 443}, "tcp-node")
	if err != nil {
		t.Fatal(err)
	}
	defer releaseTCP()
	if _, err := registry.Reserve(engine.NodeSpec{Protocol: "hysteria2", Port: 443}, "udp-node"); err == nil {
		t.Fatal("same numeric TCP/UDP port was accepted for different nodes")
	}
}

func TestListenerRegistryStaleReleaseCannotDropNewClaim(t *testing.T) {
	registry := newListenerRegistry()
	oldRelease, err := registry.Reserve(engine.NodeSpec{Protocol: "vless", Port: 443}, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	newRelease, err := registry.Reserve(engine.NodeSpec{Protocol: "vless", Port: 443}, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	oldRelease()
	if _, err := registry.Reserve(engine.NodeSpec{Protocol: "vless", Port: 443}, "node-b"); err == nil {
		t.Fatal("stale release removed the newer listener claim")
	}
	newRelease()
	releaseB, err := registry.Reserve(engine.NodeSpec{Protocol: "vless", Port: 443}, "node-b")
	if err != nil {
		t.Fatalf("latest release retained listener claim: %v", err)
	}
	releaseB()
}

func TestListenerRegistryFailedSamePortCandidateKeepsActiveClaim(t *testing.T) {
	registry := newListenerRegistry()
	activeRelease, err := registry.Reserve(engine.NodeSpec{Protocol: "vless", Port: 443}, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	candidateRelease, err := registry.Reserve(engine.NodeSpec{Protocol: "vless", Port: 443}, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	candidateRelease()
	if _, err := registry.Reserve(engine.NodeSpec{Protocol: "vless", Port: 443}, "node-b"); err == nil {
		t.Fatal("failed candidate release removed the active same-port claim")
	}
	activeRelease()
	otherRelease, err := registry.Reserve(engine.NodeSpec{Protocol: "vless", Port: 443}, "node-b")
	if err != nil {
		t.Fatalf("active release retained its last lease: %v", err)
	}
	otherRelease()
}

func TestListenerRegistryAllowsSameOwnerPortMigration(t *testing.T) {
	registry := newListenerRegistry()
	releaseOld, err := registry.Reserve(engine.NodeSpec{Protocol: "vless", Port: 443}, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	releaseNew, err := registry.Reserve(engine.NodeSpec{Protocol: "hysteria2", Port: 8443}, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	releaseOld()
	if releaseOther, err := registry.Reserve(engine.NodeSpec{Protocol: "vless", Port: 443}, "node-b"); err != nil {
		t.Fatalf("old port was not released after migration: %v", err)
	} else {
		releaseOther()
	}
	if _, err := registry.Reserve(engine.NodeSpec{Protocol: "vless", Port: 8443}, "node-b"); err == nil {
		t.Fatal("new port claim was lost during migration")
	}
	releaseNew()
}

type shortWriter struct {
	destination bytes.Buffer
	maximum     int
	err         error
}

func (w *shortWriter) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if len(data) > w.maximum {
		data = data[:w.maximum]
	}
	return w.destination.Write(data)
}

func TestNodePrefixWriterHandlesPartialWritesAndLines(t *testing.T) {
	destination := &shortWriter{maximum: 2}
	w := &nodePrefixWriter{destination: destination, prefix: "[n] "}
	first := []byte("first\nsec")
	if n, err := w.Write(first); err != nil || n != len(first) {
		t.Fatalf("first write = %d, %v", n, err)
	}
	second := []byte("ond\n")
	if n, err := w.Write(second); err != nil || n != len(second) {
		t.Fatalf("second write = %d, %v", n, err)
	}
	if got, want := destination.destination.String(), "[n] first\n[n] second\n"; got != want {
		t.Fatalf("prefixed output = %q, want %q", got, want)
	}
}

func TestNodePrefixWriterReturnsOriginalInputCountOnPrefixError(t *testing.T) {
	wantErr := errors.New("write failed")
	w := &nodePrefixWriter{destination: &shortWriter{maximum: 1, err: wantErr}, prefix: "[n] "}
	if n, err := w.Write([]byte("payload")); n != 0 || !errors.Is(err, wantErr) {
		t.Fatalf("write result = %d, %v", n, err)
	}
}

func TestAllManagementAddressesIncludesEveryWorkerAndIsSorted(t *testing.T) {
	configs := []config.Config{
		{Engine: config.EngineConfig{StatsListen: "127.0.0.1:12085", ClashListen: "127.0.0.1:12086"}},
		{Engine: config.EngineConfig{StatsListen: "127.0.0.1:10085", ClashListen: "127.0.0.1:10086"}},
	}
	want := []string{"127.0.0.1:10085", "127.0.0.1:10086", "127.0.0.1:12085", "127.0.0.1:12086"}
	if got := allManagementAddresses(configs); !reflect.DeepEqual(got, want) {
		t.Fatalf("management addresses = %#v, want %#v", got, want)
	}
}

func TestSingletonDoesNotRequireMultiNodeListenerRegistry(t *testing.T) {
	if guard := listenerGuardForWorkers(1); guard != nil {
		t.Fatal("singleton unexpectedly received a multi-node listener registry")
	}
	if guard := listenerGuardForWorkers(2); guard == nil {
		t.Fatal("multi-node workers did not receive a listener registry")
	}
}

func TestRunWorkerBundlesCancelsPeersWhenWorkerFails(t *testing.T) {
	wantErr := errors.New("worker failed")
	peerStopped := make(chan struct{})
	var stopped atomic.Bool
	workers := []*workerBundle{
		{name: "failed", runner: workerRunnerFunc(func(context.Context) error { return wantErr })},
		{name: "peer", runner: workerRunnerFunc(func(ctx context.Context) error {
			<-ctx.Done()
			stopped.Store(true)
			close(peerStopped)
			return nil
		})},
	}
	result := make(chan error, 1)
	go func() { result <- runWorkerBundles(context.Background(), workers) }()
	select {
	case err := <-result:
		if !errors.Is(err, wantErr) || !stopped.Load() {
			t.Fatalf("run result = %v, peer stopped = %v", err, stopped.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("worker failure did not cancel and join peer")
	}
	select {
	case <-peerStopped:
	default:
		t.Fatal("peer shutdown was not observed before return")
	}
}

func TestRunWorkerBundlesRejectsUninitializedWorker(t *testing.T) {
	if err := runWorkerBundles(context.Background(), []*workerBundle{nil}); err == nil {
		t.Fatal("nil worker was accepted")
	}
	if err := runWorkerBundles(context.Background(), []*workerBundle{{name: "missing-runner"}}); err == nil {
		t.Fatal("worker without runner was accepted")
	}
}
