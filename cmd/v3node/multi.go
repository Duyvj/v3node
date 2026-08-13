package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/Duyvj/v3node/internal/app"
	"github.com/Duyvj/v3node/internal/config"
	"github.com/Duyvj/v3node/internal/engine"
	"github.com/Duyvj/v3node/internal/panel"
	noderuntime "github.com/Duyvj/v3node/internal/runtime"
)

type panelClient interface {
	app.PanelAPI
	Close()
}

type workerBundle struct {
	name       string
	config     config.Config
	panel      panelClient
	supervisor *noderuntime.Supervisor
	runner     workerRunner
}

type workerRunner interface {
	Run(context.Context) error
}

type checkCandidate struct {
	config   config.Config
	compiled app.CompiledState
	renderer engine.Renderer
}

type checkCandidateFetcher func(context.Context, config.Config, io.Writer) (checkCandidate, error)
type checkCandidateValidator func(context.Context, checkCandidate, io.Writer, io.Writer, bool) error

type listenerClaim struct {
	port    uint16
	owner   string
	network string
	leases  map[uint64]struct{}
}

// listenerRegistry is intentionally conservative: the product contract for
// multi-node mode requires different panel ports, so equal numeric ports are
// rejected even when TCP and UDP could technically coexist. This also avoids
// ambiguous wildcard IPv4/IPv6 bind behavior across kernels.
type listenerRegistry struct {
	mu         sync.Mutex
	claims     map[uint16]listenerClaim
	generation uint64
}

func newListenerRegistry() *listenerRegistry {
	return &listenerRegistry{claims: make(map[uint16]listenerClaim)}
}

func listenerGuardForWorkers(count int) app.ListenerGuard {
	if count <= 1 {
		return nil
	}
	return newListenerRegistry()
}

func (r *listenerRegistry) Reserve(node engine.NodeSpec, owner string) (func(), error) {
	if node.Port == 0 {
		return nil, errors.New("listener port is zero")
	}
	network := "tcp"
	if node.Protocol == "hysteria2" || node.Protocol == "tuic" {
		network = "udp"
	} else if node.Protocol == "shadowsocks" {
		network = "tcp+udp"
	}
	r.mu.Lock()
	existing, claimed := r.claims[node.Port]
	if claimed && existing.owner != owner {
		r.mu.Unlock()
		return nil, fmt.Errorf("port %d is already reserved by %s (%s)", node.Port, existing.owner, existing.network)
	}
	r.generation++
	generation := r.generation
	if !claimed {
		existing = listenerClaim{port: node.Port, owner: owner, network: network, leases: make(map[uint64]struct{})}
	}
	existing.network = network
	existing.leases[generation] = struct{}{}
	r.claims[node.Port] = existing
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			if current, ok := r.claims[node.Port]; ok && current.owner == owner {
				delete(current.leases, generation)
				if len(current.leases) == 0 {
					delete(r.claims, node.Port)
				}
			}
			r.mu.Unlock()
		})
	}, nil
}

func allManagementAddresses(configs []config.Config) []string {
	addresses := make([]string, 0, len(configs)*2)
	for _, cfg := range configs {
		addresses = append(addresses, cfg.Engine.StatsListen, cfg.Engine.ClashListen)
	}
	sort.Strings(addresses)
	return addresses
}

func newWorkerBundle(cfg config.Config, stdout, stderr io.Writer, guard app.ListenerGuard) (*workerBundle, error) {
	name := cfg.NodeName()
	logger := log.New(stderr, "v3node["+name+"]: ", log.LstdFlags|log.LUTC|log.Lmsgprefix)
	client, err := newPanelClient(cfg)
	if err != nil {
		return nil, err
	}
	supervisor, err := noderuntime.NewSupervisor(noderuntime.SupervisorOptions{
		Directory:   filepath.Join(cfg.Engine.StateDir, "engine"),
		StopTimeout: cfg.Engine.StopTimeout.Duration,
		Stdout:      &nodePrefixWriter{destination: stdout, prefix: "v3node[" + name + "] engine: "},
		Stderr:      &nodePrefixWriter{destination: stderr, prefix: "v3node[" + name + "] engine: "},
		Logger:      logger,
		HealthProbe: statsHealthProbe(cfg.Engine.StatsListen),
	})
	if err != nil {
		client.Close()
		return nil, err
	}
	controller, err := app.NewController(app.ControllerOptions{
		Config:        cfg,
		Panel:         client,
		Supervisor:    supervisor,
		Logger:        logger,
		ListenerGuard: guard,
	})
	if err != nil {
		client.Close()
		_ = supervisor.Close(context.Background())
		return nil, err
	}
	return &workerBundle{name: name, config: cfg, panel: client, supervisor: supervisor, runner: controller}, nil
}

func statsHealthProbe(address string) noderuntime.HealthProbe {
	return func(ctx context.Context) error {
		var lastErr error
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", address)
			if err == nil {
				return connection.Close()
			}
			lastErr = err
			select {
			case <-ctx.Done():
				return fmt.Errorf("stats API is not listening: %w", lastErr)
			case <-ticker.C:
			}
		}
	}
}

func runWorkerBundles(ctx context.Context, workers []*workerBundle) error {
	if len(workers) == 0 {
		return errors.New("no node workers configured")
	}
	for index, worker := range workers {
		if worker == nil || worker.runner == nil {
			return fmt.Errorf("node worker %d is not initialized", index)
		}
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wait sync.WaitGroup
	errorsByWorker := make(chan error, len(workers))
	for _, worker := range workers {
		worker := worker
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := worker.runner.Run(runCtx); err != nil {
				errorsByWorker <- fmt.Errorf("node %s: %w", worker.name, err)
				cancel()
			} else if runCtx.Err() == nil {
				errorsByWorker <- fmt.Errorf("node %s: controller stopped unexpectedly", worker.name)
				cancel()
			}
			if worker.panel != nil {
				worker.panel.Close()
			}
		}()
	}
	wait.Wait()
	close(errorsByWorker)
	var result []error
	for err := range errorsByWorker {
		result = append(result, err)
	}
	return errors.Join(result...)
}

type nodePrefixWriter struct {
	mu          sync.Mutex
	destination io.Writer
	prefix      string
	initialized bool
	atLineStart bool
}

func (w *nodePrefixWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.destination == nil {
		return len(data), nil
	}
	if !w.initialized {
		w.initialized = true
		w.atLineStart = true
	}
	written := 0
	for len(data) > 0 {
		if w.atLineStart {
			prefix := []byte(w.prefix)
			for len(prefix) > 0 {
				n, err := w.destination.Write(prefix)
				prefix = prefix[n:]
				if err != nil {
					return written, err
				}
				if n == 0 {
					return written, io.ErrShortWrite
				}
			}
			w.atLineStart = false
		}
		index := bytes.IndexByte(data, '\n')
		chunk := data
		if index >= 0 {
			chunk = data[:index+1]
		}
		for len(chunk) > 0 {
			n, err := w.destination.Write(chunk)
			written += n
			chunk = chunk[n:]
			if err != nil {
				return written, err
			}
			if n == 0 {
				return written, io.ErrShortWrite
			}
		}
		consumed := len(data)
		if index >= 0 {
			consumed = index + 1
		}
		data = data[consumed:]
		if index >= 0 {
			w.atLineStart = true
		}
	}
	return written, nil
}

func fetchCheckCandidate(ctx context.Context, cfg config.Config, stderr io.Writer) (checkCandidate, error) {
	client, err := newPanelClient(cfg)
	if err != nil {
		return checkCandidate{}, err
	}
	defer client.Close()
	node, changed, err := client.GetNodeConfig(ctx)
	if err != nil {
		return checkCandidate{}, err
	}
	if !changed || node == nil {
		return checkCandidate{}, errors.New("panel returned no node configuration")
	}
	users, changed, err := client.GetUsers(ctx)
	if err != nil {
		return checkCandidate{}, err
	}
	if !changed {
		return checkCandidate{}, errors.New("panel returned no user configuration")
	}
	compiled, err := app.CompileState(*node, users, cfg)
	if err != nil {
		return checkCandidate{}, err
	}
	for _, warning := range engine.SecurityWarnings(compiled.Node) {
		fmt.Fprintf(stderr, "v3node[%s]: security warning: %s\n", cfg.NodeName(), warning)
	}
	if compiled.Node.TLS.ManagedSelfSigned && runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return checkCandidate{}, errors.New("self-signed TLS check must run as the v3node service user (sudo -u v3node v3node check)")
	}
	renderer, err := engine.Select(cfg.Engine.Backend, compiled.Node)
	if err != nil {
		return checkCandidate{}, err
	}
	if err := app.ValidateBackendPolicies(renderer.Name(), compiled.Users); err != nil {
		return checkCandidate{}, err
	}
	return checkCandidate{config: cfg, compiled: compiled, renderer: renderer}, nil
}

func validateCheckCandidate(ctx context.Context, candidate checkCandidate, stdout, stderr io.Writer, renderOnly bool) error {
	if err := app.EnsureManagedCertificate(candidate.compiled.Node); err != nil {
		return fmt.Errorf("prepare managed TLS certificate: %w", err)
	}
	apiSecret, err := app.LoadOrCreateAPISecret(candidate.config.Engine.StateDir)
	if err != nil {
		return err
	}
	rendered, err := candidate.renderer.Render(candidate.compiled.Node, candidate.compiled.Users, engine.Options{
		LogLevel:            candidate.config.Runtime.LogLevel,
		StatsListen:         candidate.config.Engine.StatsListen,
		ClashListen:         candidate.config.Engine.ClashListen,
		ProtectedManagement: candidate.config.ProtectedManagement,
		ClashSecret:         apiSecret,
		AddressStrategy:     candidate.config.Network.AddressStrategy,
		DNSServers:          candidate.config.Network.DNSServers,
		BlockPrivate:        candidate.config.Network.BlockPrivate != nil && *candidate.config.Network.BlockPrivate,
	})
	if err != nil {
		return err
	}
	if !renderOnly {
		binary := candidate.config.Engine.SingBoxBinary
		if rendered.Backend == "xray" {
			binary = candidate.config.Engine.XrayBinary
		}
		if err := noderuntime.CheckEngineConfig(ctx, rendered.Backend, binary, rendered.Config, stderr); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "OK: node=%s id=%d backend=%s protocol=%s port=%d users=%d config_bytes=%d\n", candidate.config.NodeName(), candidate.config.Panel.NodeID, rendered.Backend, candidate.compiled.Node.Protocol, candidate.compiled.Node.Port, len(candidate.compiled.Users), len(rendered.Config))
	return nil
}

// Keep the concrete type referenced so compile-time interface drift is caught.
var _ panelClient = (*panel.Client)(nil)
