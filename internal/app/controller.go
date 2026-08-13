package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Duyvj/v3node/internal/config"
	"github.com/Duyvj/v3node/internal/engine"
	"github.com/Duyvj/v3node/internal/model"
	noderuntime "github.com/Duyvj/v3node/internal/runtime"
	"github.com/Duyvj/v3node/internal/state"
)

const (
	trafficForceFlushInterval = 5 * time.Minute
	connectionsPollInterval   = 5 * time.Second
	aliveStateMaxAge          = 5 * time.Minute
)

type PanelAPI interface {
	GetNodeConfig(context.Context) (*model.NodeConfig, bool, error)
	GetUsers(context.Context) ([]model.User, bool, error)
	GetAlive(context.Context) (model.AliveUsers, error)
	ReportTraffic(context.Context, []model.UserTraffic) error
	ReportOnline(context.Context, model.OnlineUsers) error
}

type ConnectionsAPI interface {
	Snapshot(context.Context) ([]engine.ActiveConnection, error)
	Close(context.Context, string) error
}

// ListenerGuard coordinates public listener claims when several isolated
// workers share one v3node process. It is deliberately optional so the
// single-node controller and its existing tests keep their behavior.
type ListenerGuard interface {
	Reserve(engine.NodeSpec, string) (release func(), err error)
}

type ControllerOptions struct {
	Config        config.Config
	Panel         PanelAPI
	Supervisor    *noderuntime.Supervisor
	Logger        *log.Logger
	ListenerGuard ListenerGuard
}

type Controller struct {
	cfg         config.Config
	panel       PanelAPI
	supervisor  *noderuntime.Supervisor
	logger      *log.Logger
	stats       *engine.StatsClient
	connections ConnectionsAPI
	apiSecret   string
	traffic     *state.TrafficAccumulator
	online      *state.OnlineTracker

	runtimePath        string
	trafficPath        string
	desiredNode        *model.NodeConfig
	desiredUsers       []model.User
	haveUsers          bool
	desiredDirty       bool
	active             RuntimeState
	haveActive         bool
	activeHash         [32]byte
	alive              model.AliveUsers
	aliveReady         bool
	aliveUpdatedAt     time.Time
	lastOnlineReport   map[int]map[netip.Addr]struct{}
	lastOnlineReportAt time.Time
	connectionsSeeded  bool
	lastCheckpoint     time.Time
	lastTrafficFlush   time.Time
	rejectedDevices    atomic.Uint64
	listenerGuard      ListenerGuard
	listenerRelease    func()
}

func NewController(opts ControllerOptions) (*Controller, error) {
	if opts.Panel == nil || opts.Supervisor == nil {
		return nil, errors.New("panel client and engine supervisor are required")
	}
	if opts.Logger == nil {
		opts.Logger = log.New(os.Stderr, "v3node: ", log.LstdFlags|log.LUTC|log.Lmsgprefix)
	}
	if err := os.MkdirAll(opts.Config.Engine.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create controller state directory: %w", err)
	}
	trafficPath := filepath.Join(opts.Config.Engine.StateDir, "traffic.json")
	accumulator, err := restoreTrafficAccumulator(trafficPath, opts.Config.Runtime.MaxUsers, opts.Logger)
	if err != nil {
		return nil, err
	}
	online, err := state.NewOnlineTracker(
		opts.Config.Runtime.OnlineIPTTL.Duration,
		opts.Config.Runtime.MaxOnlineIPs,
		opts.Config.Runtime.MaxIPsPerUser,
	)
	if err != nil {
		return nil, err
	}
	stats, err := engine.NewStatsClient(
		opts.Config.Engine.StatsListen,
		opts.Config.Runtime.HTTPTimeout.Duration,
		opts.Config.Runtime.MaxStatsResponseBytes,
	)
	if err != nil {
		return nil, err
	}
	apiSecret, err := LoadOrCreateAPISecret(opts.Config.Engine.StateDir)
	if err != nil {
		_ = stats.Close()
		return nil, err
	}
	connections, err := engine.NewConnectionsClient(opts.Config.Engine.ClashListen, opts.Config.Runtime.HTTPTimeout.Duration, opts.Config.Runtime.MaxOnlineIPs, apiSecret)
	if err != nil {
		_ = stats.Close()
		return nil, err
	}
	return &Controller{
		cfg:              opts.Config,
		panel:            opts.Panel,
		supervisor:       opts.Supervisor,
		logger:           opts.Logger,
		stats:            stats,
		connections:      connections,
		apiSecret:        apiSecret,
		traffic:          accumulator,
		online:           online,
		runtimePath:      filepath.Join(opts.Config.Engine.StateDir, "runtime.json"),
		trafficPath:      trafficPath,
		alive:            make(model.AliveUsers),
		lastOnlineReport: make(map[int]map[netip.Addr]struct{}),
		listenerGuard:    opts.ListenerGuard,
	}, nil
}

func restoreTrafficAccumulator(path string, maxUsers int, logger *log.Logger) (*state.TrafficAccumulator, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return state.NewTrafficAccumulator(maxUsers)
	}
	if err != nil {
		return nil, fmt.Errorf("inspect traffic state: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("traffic state path is not a regular file")
	}
	accumulator, loadErr := state.LoadTrafficAccumulator(path, maxUsers)
	if loadErr == nil {
		return accumulator, nil
	}
	quarantine := fmt.Sprintf("%s.corrupt-%s", path, time.Now().UTC().Format("20060102T150405.000000000Z"))
	if renameErr := os.Rename(path, quarantine); renameErr != nil {
		return nil, errors.Join(fmt.Errorf("restore traffic state: %w", loadErr), fmt.Errorf("quarantine invalid traffic state: %w", renameErr))
	}
	if logger != nil {
		logger.Printf("invalid traffic checkpoint quarantined as %s: %v", filepath.Base(quarantine), loadErr)
	}
	return state.NewTrafficAccumulator(maxUsers)
}

func (c *Controller) Run(ctx context.Context) error {
	c.restoreLastKnownGood(ctx)
	if changed, err := c.syncPanel(ctx); err != nil {
		c.logger.Printf("initial panel synchronization failed; last-known-good remains active: %v", err)
	} else if changed {
		c.logger.Printf("initial panel state applied")
	}

	pullTimer := time.NewTimer(c.jitter(c.pullInterval()))
	pushTimer := time.NewTimer(c.jitter(c.pushInterval()))
	statsTimer := time.NewTimer(c.jitter(c.statsInterval()))
	connectionsTimer := time.NewTimer(c.jitter(connectionsPollInterval))
	healthTimer := time.NewTimer(10 * time.Second)
	checkpointTimer := time.NewTimer(30 * time.Second)
	defer stopTimer(pullTimer)
	defer stopTimer(pushTimer)
	defer stopTimer(statsTimer)
	defer stopTimer(connectionsTimer)
	defer stopTimer(healthTimer)
	defer stopTimer(checkpointTimer)

	pullFailures := 0
	pushFailures := 0
	for {
		select {
		case <-ctx.Done():
			return c.shutdown(ctx)
		case <-pullTimer.C:
			_, err := c.syncPanel(ctx)
			if err != nil {
				pullFailures++
				c.logger.Printf("panel synchronization failed (attempt %d): %v", pullFailures, err)
				resetTimer(pullTimer, c.retryDelay(pullFailures, c.pullInterval()))
			} else {
				pullFailures = 0
				resetTimer(pullTimer, c.jitter(c.pullInterval()))
			}
		case <-pushTimer.C:
			if err := c.pushReports(ctx); err != nil {
				pushFailures++
				c.logger.Printf("panel report failed (attempt %d): %v", pushFailures, err)
				resetTimer(pushTimer, c.retryDelay(pushFailures, c.pushInterval()))
			} else {
				pushFailures = 0
				resetTimer(pushTimer, c.jitter(c.pushInterval()))
			}
		case <-statsTimer.C:
			if err := c.collectStats(ctx); err != nil && c.haveActive && c.supervisor.Healthy() {
				c.logger.Printf("traffic collection failed: %v", err)
			}
			resetTimer(statsTimer, c.jitter(c.statsInterval()))
		case <-connectionsTimer.C:
			if err := c.collectConnections(ctx); err != nil && c.haveActive && c.active.Backend == "sing-box" && c.supervisor.Healthy() {
				c.logger.Printf("online connection collection failed: %v", err)
			}
			resetTimer(connectionsTimer, c.jitter(connectionsPollInterval))
		case <-healthTimer.C:
			c.recoverEngine(ctx)
			resetTimer(healthTimer, 10*time.Second)
		case <-checkpointTimer.C:
			if err := c.saveTrafficCheckpoint(); err != nil {
				c.logger.Printf("traffic checkpoint failed: %v", err)
			}
			resetTimer(checkpointTimer, 30*time.Second)
		}
	}
}

func (c *Controller) restoreLastKnownGood(ctx context.Context) {
	stateValue, err := LoadRuntimeState(
		c.runtimePath,
		c.cfg.Runtime.MaxUsers,
		c.cfg.Runtime.PullIntervalMin.Duration,
		c.cfg.Runtime.PullIntervalMax.Duration,
		c.cfg.Runtime.PushIntervalMin.Duration,
		c.cfg.Runtime.PushIntervalMax.Duration,
	)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			c.logger.Printf("last-known-good metadata is unavailable: %v", err)
		}
		return
	}
	if c.listenerGuard != nil && stateValue.Listener.Port == 0 {
		// Runtime-state v2 did not record a public listener, so a multi-node
		// process cannot reserve it before starting the old engine. Wait for a
		// fresh panel reconciliation instead of risking an in-process collision.
		c.logger.Printf("last-known-good metadata predates multi-node listener isolation; waiting for panel synchronization")
		return
	}
	binary := c.binaryFor(stateValue.Backend)
	expectedHash, err := stateValue.ConfigHash()
	if err != nil {
		c.logger.Printf("last-known-good metadata has an invalid generation hash: %v", err)
		return
	}
	var release func()
	if c.listenerGuard != nil && stateValue.Listener.Port != 0 {
		release, err = c.listenerGuard.Reserve(engine.NodeSpec{
			Protocol: stateValue.Listener.Protocol,
			Listen:   stateValue.Listener.Listen,
			Port:     stateValue.Listener.Port,
		}, c.cfg.NodeName())
		if err != nil {
			c.logger.Printf("last-known-good public listener could not be reserved: %v", err)
			return
		}
	}
	checkCtx, cancel := context.WithTimeout(ctx, c.cfg.Engine.CheckTimeout.Duration)
	defer cancel()
	if err := c.supervisor.StartExisting(checkCtx, stateValue.Backend, binary, expectedHash); err != nil {
		if release != nil {
			release()
		}
		c.logger.Printf("last-known-good engine could not start: %v", err)
		return
	}
	c.active = stateValue
	c.haveActive = true
	c.activeHash = expectedHash
	c.listenerRelease = release
	c.logger.Printf("last-known-good %s engine started before panel synchronization", stateValue.Backend)
}

func (c *Controller) syncPanel(ctx context.Context) (bool, error) {
	type nodeResult struct {
		node    *model.NodeConfig
		changed bool
		err     error
	}
	type usersResult struct {
		users   []model.User
		changed bool
		err     error
	}
	type aliveResult struct {
		alive model.AliveUsers
		err   error
	}
	nodeResults := make(chan nodeResult, 1)
	usersResults := make(chan usersResult, 1)
	aliveResults := make(chan aliveResult, 1)
	go func() {
		node, changed, err := c.panel.GetNodeConfig(ctx)
		nodeResults <- nodeResult{node: node, changed: changed, err: err}
	}()
	go func() {
		users, changed, err := c.panel.GetUsers(ctx)
		usersResults <- usersResult{users: users, changed: changed, err: err}
	}()
	go func() {
		alive, err := c.panel.GetAlive(ctx)
		aliveResults <- aliveResult{alive: alive, err: err}
	}()

	nodeResponse := <-nodeResults
	usersResponse := <-usersResults
	aliveResponse := <-aliveResults
	var syncErrors []error
	controlPlaneReady := true
	if nodeResponse.err != nil {
		syncErrors = append(syncErrors, nodeResponse.err)
		controlPlaneReady = false
	} else if nodeResponse.changed {
		c.desiredNode = nodeResponse.node
		c.desiredDirty = true
	}
	if usersResponse.err != nil {
		syncErrors = append(syncErrors, usersResponse.err)
		controlPlaneReady = false
	} else if usersResponse.changed {
		c.setDesiredUsers(usersResponse.users)
		c.haveUsers = true
		c.desiredDirty = true
	}
	if aliveResponse.err != nil {
		if c.aliveReady && !c.aliveUpdatedAt.IsZero() && time.Since(c.aliveUpdatedAt) >= aliveStateMaxAge {
			c.alive = make(model.AliveUsers)
			c.aliveReady = false
			c.logger.Printf("panel alive-list refresh failed; stale counts discarded: %v", aliveResponse.err)
		} else {
			c.logger.Printf("panel alive-list refresh failed; recent counts retained: %v", aliveResponse.err)
		}
	} else {
		c.alive = aliveResponse.alive
		c.aliveReady = true
		c.aliveUpdatedAt = time.Now()
	}
	changed := false
	// Node and users form one desired generation. Do not combine a freshly
	// fetched half with a stale half when either control-plane request failed in
	// this cycle. Successfully fetched state remains staged for the next cycle.
	if controlPlaneReady && c.desiredDirty && c.desiredNode != nil && c.haveUsers {
		if err := c.reconcile(ctx); err != nil {
			syncErrors = append(syncErrors, err)
		} else {
			changed = true
		}
	}
	return changed, errors.Join(syncErrors...)
}

func (c *Controller) reconcile(ctx context.Context) error {
	compiled, err := CompileState(*c.desiredNode, c.desiredUsers, c.cfg)
	if err != nil {
		return fmt.Errorf("compile desired panel state: %w", err)
	}
	renderer, err := engine.Select(c.cfg.Engine.Backend, compiled.Node)
	if err != nil {
		return err
	}
	if err := ValidateBackendPolicies(renderer.Name(), compiled.Users); err != nil {
		return err
	}
	if err := EnsureManagedCertificate(compiled.Node); err != nil {
		return fmt.Errorf("prepare managed TLS certificate: %w", err)
	}
	for _, warning := range engine.SecurityWarnings(compiled.Node) {
		c.logger.Printf("security warning: %s", warning)
	}
	rendered, err := renderer.Render(compiled.Node, compiled.Users, engine.Options{
		LogLevel:            c.cfg.Runtime.LogLevel,
		StatsListen:         c.cfg.Engine.StatsListen,
		ClashListen:         c.cfg.Engine.ClashListen,
		ProtectedManagement: append([]string(nil), c.cfg.ProtectedManagement...),
		ClashSecret:         c.apiSecret,
		AddressStrategy:     c.cfg.Network.AddressStrategy,
		DNSServers:          append([]string(nil), c.cfg.Network.DNSServers...),
		BlockPrivate:        c.cfg.Network.BlockPrivate != nil && *c.cfg.Network.BlockPrivate,
	})
	if err != nil {
		return fmt.Errorf("render %s engine config: %w", renderer.Name(), err)
	}
	candidateHash := sha256.Sum256(rendered.Config)
	wasHealthy := c.haveActive && c.supervisor.Healthy()
	replacesEngine := !c.haveActive || !wasHealthy || c.active.Backend != rendered.Backend || c.activeHash != candidateHash
	var candidateRelease func()
	if c.listenerGuard != nil && replacesEngine {
		candidateRelease, err = c.listenerGuard.Reserve(compiled.Node, c.cfg.NodeName())
		if err != nil {
			return fmt.Errorf("reserve public listener: %w", err)
		}
	}
	// Drain the old cumulative generation immediately before an engine
	// replacement. The StatsClient baseline is committed only after the whole
	// delta batch has been retained.
	if wasHealthy && replacesEngine {
		if err := c.collectStats(ctx); err != nil {
			if candidateRelease != nil {
				candidateRelease()
			}
			return fmt.Errorf("collect final traffic before engine update: %w", err)
		}
		if err := c.saveTrafficCheckpoint(); err != nil {
			if candidateRelease != nil {
				candidateRelease()
			}
			return fmt.Errorf("checkpoint traffic before engine update: %w", err)
		}
	}
	// A semantic panel update is also a natural opportunity to flush counters
	// for users removed from the new generation. Reporting failure does not
	// delay revocations; the bounded accumulator keeps the batch for retry.
	if c.haveActive {
		if err := c.reportTraffic(ctx, true); err != nil {
			c.logger.Printf("traffic flush before engine update failed; retained for retry: %v", err)
		}
	}
	checkCtx, cancel := context.WithTimeout(ctx, c.cfg.Engine.CheckTimeout.Duration)
	defer cancel()
	if err := c.supervisor.Apply(checkCtx, rendered.Backend, c.binaryFor(rendered.Backend), rendered.Config); err != nil {
		if candidateRelease != nil {
			candidateRelease()
		}
		return fmt.Errorf("apply engine configuration: %w", err)
	}
	runtimeState := RuntimeStateFromCompiled(rendered.Backend, compiled, rendered.Users, candidateHash)
	persistErr := SaveRuntimeState(c.runtimePath, runtimeState)
	// Seed the new policy generation from actual connections. This also makes
	// a lowered device limit take effect when Apply can keep an identical data
	// plane configuration running.
	reseedConnections := c.resetOnlinePolicyState(runtimeState, replacesEngine)
	c.active = runtimeState
	c.haveActive = true
	c.activeHash = candidateHash
	if replacesEngine && c.listenerRelease != nil {
		c.listenerRelease()
	}
	if replacesEngine {
		c.listenerRelease = candidateRelease
	}
	if reseedConnections {
		c.connectionsSeeded = false
	}
	c.logger.Printf("applied %s generation: protocol=%s users=%d", rendered.Backend, compiled.Node.Protocol, len(compiled.Users))
	if persistErr != nil {
		// The engine is already serving this generation. Keep the in-memory
		// mapping aligned with it and leave desiredDirty set so persistence is
		// retried, rather than accounting new traffic with stale user metadata.
		return fmt.Errorf("persist runtime metadata: %w", persistErr)
	}
	c.desiredDirty = false
	return nil
}

func (c *Controller) resetOnlinePolicyState(next RuntimeState, replacesEngine bool) bool {
	if !c.haveActive {
		return true
	}
	if replacesEngine {
		for _, userID := range c.active.EngineUsers {
			c.online.ForgetUser(userID)
			delete(c.lastOnlineReport, userID)
		}
		clearOnlineReport(c.lastOnlineReport)
		c.lastOnlineReportAt = time.Time{}
		return true
	}
	reseed := false
	for engineName, userID := range c.active.EngineUsers {
		nextUserID, exists := next.EngineUsers[engineName]
		previous := c.active.Policies[userID]
		current := next.Policies[userID]
		if !exists || nextUserID != userID || current.DeviceLimit != previous.DeviceLimit {
			c.online.ForgetUser(userID)
			delete(c.lastOnlineReport, userID)
			reseed = true
		}
	}
	// Runtime state written by older builds contains policy rows for every
	// user. Check those rows too; ForgetUser is idempotent when this overlaps
	// the engine-user loop above.
	for userID, previous := range c.active.Policies {
		current, exists := next.Policies[userID]
		if !exists || current.DeviceLimit != previous.DeviceLimit {
			c.online.ForgetUser(userID)
			delete(c.lastOnlineReport, userID)
			reseed = true
		}
	}
	if len(c.lastOnlineReport) == 0 {
		c.lastOnlineReportAt = time.Time{}
	}
	return reseed
}

func (c *Controller) collectStats(ctx context.Context) error {
	if !c.haveActive || !c.supervisor.Healthy() || len(c.active.EngineUsers) == 0 {
		return nil
	}
	sample, err := c.stats.Poll(ctx, c.supervisor.Generation(), c.active.EngineUsers)
	if err != nil {
		return err
	}
	batch := make([]state.UserTraffic, 0, len(sample.Deltas))
	for userID, delta := range sample.Deltas {
		batch = append(batch, state.UserTraffic{UserID: userID, Upload: delta.Upload, Download: delta.Download})
	}
	if err := c.traffic.AddBatch(batch); errors.Is(err, state.ErrTrafficCapacity) {
		// Small per-user counters below the panel threshold must not let churn
		// occupy every slot forever. Flush all retained users, then retry the
		// same uncommitted cumulative sample.
		if flushErr := c.reportTraffic(ctx, true); flushErr != nil {
			return errors.Join(err, fmt.Errorf("force traffic flush at capacity: %w", flushErr))
		}
		if err = c.traffic.AddBatch(batch); err != nil {
			return fmt.Errorf("retain traffic after capacity flush: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("retain traffic batch: %w", err)
	}
	if !c.stats.Commit(sample) {
		return errors.New("commit cumulative stats baseline: stale sample")
	}
	if len(sample.Deltas) > 0 && time.Since(c.lastCheckpoint) >= 15*time.Second {
		if err := c.saveTrafficCheckpoint(); err != nil {
			return fmt.Errorf("checkpoint collected traffic: %w", err)
		}
	}
	return nil
}

func (c *Controller) collectConnections(ctx context.Context) error {
	if !c.haveActive || c.active.Backend != "sing-box" || !c.supervisor.Healthy() {
		return nil
	}
	connections, err := c.connections.Snapshot(ctx)
	if err != nil {
		return err
	}
	return c.processConnections(ctx, connections)
}

type connectionDeviceKey struct {
	userID  int
	address netip.Addr
}

type connectionDeviceObservation struct {
	key       connectionDeviceKey
	startedAt time.Time
	traffic   int64
}

func (c *Controller) processConnections(ctx context.Context, connections []engine.ActiveConnection) error {
	observations := make(map[connectionDeviceKey]connectionDeviceObservation, min(len(connections), 1024))
	for _, connection := range connections {
		userID, known := c.active.EngineUsers[connection.User]
		if !known {
			continue
		}
		key := connectionDeviceKey{userID: userID, address: connection.SourceIP.Unmap()}
		observation, exists := observations[key]
		if !exists {
			observation = connectionDeviceObservation{key: key, startedAt: connection.StartedAt}
		} else if connection.StartedAt.Before(observation.startedAt) {
			observation.startedAt = connection.StartedAt
		}
		observation.traffic = saturatingAddTraffic(observation.traffic, saturatingTraffic(connection.Upload, connection.Download))
		observations[key] = observation
	}
	// Snapshot() is complete and bounded. Reconcile retained policy slots with
	// that authoritative local view so disconnected devices free a slot on the
	// next poll instead of lingering until online_ip_ttl. Only already-admitted
	// pairs are retained here; new IPs still pass through the policy check below.
	activeAddresses := make(map[int]map[netip.Addr]bool)
	policyUsers := make(map[int]struct{})
	for key := range observations {
		if c.active.Policies[key.userID].DeviceLimit > 0 {
			policyUsers[key.userID] = struct{}{}
			addresses := activeAddresses[key.userID]
			if addresses == nil {
				addresses = make(map[netip.Addr]bool)
				activeAddresses[key.userID] = addresses
			}
			addresses[key.address] = false
		}
	}
	snapshotState := c.online.ReconcileSnapshot(activeAddresses, policyUsers)
	snapshotGeneration := snapshotState.Generation

	// The first complete snapshot seeds every user deterministically. Later
	// snapshots only need deterministic ordering for users with an actual
	// device limit; unlimited users can be processed directly from the bounded
	// observation map. This avoids allocating and sorting a second full online-
	// IP slice every five seconds on the common no-limit path.
	seedAll := !c.connectionsSeeded
	devices := make([]connectionDeviceObservation, 0)
	if seedAll {
		devices = make([]connectionDeviceObservation, 0, len(observations))
	}
	for _, observation := range observations {
		if seedAll || c.active.Policies[observation.key.userID].DeviceLimit > 0 {
			devices = append(devices, observation)
		}
	}
	sort.Slice(devices, func(i, j int) bool {
		if !devices[i].startedAt.Equal(devices[j].startedAt) {
			return devices[i].startedAt.Before(devices[j].startedAt)
		}
		if devices[i].key.userID != devices[j].key.userID {
			return devices[i].key.userID < devices[j].key.userID
		}
		return devices[i].key.address.Compare(devices[j].key.address) < 0
	})

	localCounts := snapshotState.LiveByUser
	if c.connectionsSeeded && c.aliveReady {
		reportCurrent := !c.lastOnlineReportAt.IsZero() && !c.aliveUpdatedAt.Before(c.lastOnlineReportAt)
		for userID := range policyUsers {
			reportedLocal := 0
			if reportCurrent {
				reportedLocal = c.lastReportedCount(userID)
			}
			remoteBaseline := c.alive[userID] - reportedLocal
			if remoteBaseline > 0 {
				localCounts[userID] += remoteBaseline
			}
		}
	}
	rejected := make(map[connectionDeviceKey]struct{})
	admitted := make(map[connectionDeviceKey]struct{})
	processDevice := func(device connectionDeviceObservation) error {
		userID := device.key.userID
		address := device.key.address.String()
		policy := c.active.Policies[userID]
		if policy.DeviceLimit > 0 {
			known := activeAddresses[userID][device.key.address]
			count := localCounts[userID]
			if !known {
				if count >= policy.DeviceLimit {
					rejected[device.key] = struct{}{}
					return nil
				}
				count++
			}
			localCounts[userID] = count
			if err := c.online.Reserve(userID, address); err != nil {
				return err
			}
			admitted[device.key] = struct{}{}
		}
		// Traffic is aggregated per user/IP. Splitting activity over many tiny
		// connections can no longer evade the panel's reporting threshold.
		if device.traffic >= c.active.DeviceOnlineMinBytes {
			if err := c.online.Observe(userID, address); err != nil {
				return err
			}
		}
		return nil
	}
	for _, device := range devices {
		if err := processDevice(device); err != nil {
			return err
		}
	}
	if !seedAll {
		for _, device := range observations {
			if c.active.Policies[device.key.userID].DeviceLimit > 0 {
				continue
			}
			if err := processDevice(device); err != nil {
				return err
			}
		}
	}
	c.connectionsSeeded = true

	if len(rejected) == 0 {
		return nil
	}
	ids := make([]string, 0)
	seenIDs := make(map[string]struct{})
	for _, connection := range connections {
		userID, known := c.active.EngineUsers[connection.User]
		if !known {
			continue
		}
		key := connectionDeviceKey{userID: userID, address: connection.SourceIP.Unmap()}
		if _, shouldClose := rejected[key]; !shouldClose {
			continue
		}
		if _, duplicate := seenIDs[connection.ID]; duplicate {
			continue
		}
		seenIDs[connection.ID] = struct{}{}
		ids = append(ids, connection.ID)
	}
	if err := c.closeRejectedConnections(ctx, ids); err != nil {
		// Do not let a newly admitted replacement occupy a slot when an older
		// over-limit connection could not be closed. The next complete poll will
		// retry deterministically from the live connection set.
		for key := range admitted {
			c.online.ForgetIfAcceptedIn(key.userID, key.address.String(), snapshotGeneration)
		}
		return err
	}
	return nil
}

func (c *Controller) lastReportedCount(userID int) int {
	if c.lastOnlineReport == nil {
		return 0
	}
	return len(c.lastOnlineReport[userID])
}

func (c *Controller) closeRejectedConnections(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	timeout := c.cfg.Runtime.HTTPTimeout.Duration
	if timeout <= 0 || timeout > 5*time.Second {
		timeout = 5 * time.Second
	}
	closeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	workers := min(len(ids), 8)
	jobs := make(chan string)
	var wait sync.WaitGroup
	var failed atomic.Uint64
	var firstErr error
	var errorMu sync.Mutex
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for id := range jobs {
				if err := c.connections.Close(closeCtx, id); err != nil {
					failed.Add(1)
					errorMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errorMu.Unlock()
					continue
				}
				c.rejectedDevices.Add(1)
			}
		}()
	}

	sent := 0
enqueue:
	for _, id := range ids {
		select {
		case jobs <- id:
			sent++
		case <-closeCtx.Done():
			break enqueue
		}
	}
	close(jobs)
	wait.Wait()
	failedCount := int(failed.Load()) + len(ids) - sent
	if failedCount == 0 {
		return nil
	}
	if firstErr == nil {
		firstErr = closeCtx.Err()
	}
	return fmt.Errorf("close rejected device connections: %d of %d failed: %w", failedCount, len(ids), firstErr)
}

func (c *Controller) pushReports(ctx context.Context) error {
	if !c.haveActive {
		return nil
	}
	var reportErrors []error
	if err := c.collectStats(ctx); err != nil {
		reportErrors = append(reportErrors, err)
	}
	forceTraffic := c.trafficForceDue(time.Now())
	if err := c.reportTraffic(ctx, forceTraffic); err != nil {
		reportErrors = append(reportErrors, err)
	}
	if err := c.reportOnline(ctx); err != nil {
		reportErrors = append(reportErrors, err)
	}
	if err := c.saveTrafficCheckpoint(); err != nil {
		reportErrors = append(reportErrors, err)
	}
	return errors.Join(reportErrors...)
}

func (c *Controller) reportOnline(ctx context.Context) error {
	online := c.online.SnapshotReportableMap()
	onlinePayload := make(model.OnlineUsers, len(online))
	for userID, addresses := range online {
		onlinePayload[userID] = addresses
	}
	if err := c.panel.ReportOnline(ctx, onlinePayload); err != nil {
		return err
	}
	c.rememberOnlineReport(onlinePayload)
	return nil
}

func (c *Controller) rememberOnlineReport(online model.OnlineUsers) {
	reported := make(map[int]map[netip.Addr]struct{}, len(online))
	for userID, values := range online {
		addresses := make(map[netip.Addr]struct{}, len(values))
		for _, value := range values {
			address, err := netip.ParseAddr(value)
			if err == nil && address.Zone() == "" {
				addresses[address.Unmap()] = struct{}{}
			}
		}
		if len(addresses) > 0 {
			reported[userID] = addresses
		}
	}
	clearOnlineReport(c.lastOnlineReport)
	c.lastOnlineReport = reported
	c.lastOnlineReportAt = time.Now()
}

func clearOnlineReport(report map[int]map[netip.Addr]struct{}) {
	for userID, addresses := range report {
		clear(addresses)
		delete(report, userID)
	}
}

func (c *Controller) reportTraffic(ctx context.Context, force bool) error {
	for {
		var batch state.TrafficBatch
		if force {
			batch = c.traffic.Snapshot()
		} else {
			batch = c.traffic.SnapshotAbove(c.active.NodeReportMinBytes)
		}
		if batch.Empty() {
			if force {
				c.lastTrafficFlush = time.Now()
			}
			return nil
		}
		payload := make([]model.UserTraffic, 0, len(batch.Users))
		for _, user := range batch.Users {
			payload = append(payload, model.UserTraffic{
				UserID:   user.UserID,
				Upload:   user.Upload,
				Download: user.Download,
			})
		}
		if err := c.panel.ReportTraffic(ctx, payload); err != nil {
			return err
		}
		if !c.traffic.Ack(batch.ID) {
			return errors.New("traffic batch acknowledgement raced with state update")
		}
		if !force {
			return nil
		}
	}
}

func (c *Controller) saveTrafficCheckpoint() error {
	if !c.traffic.CheckpointDirty() {
		return nil
	}
	if err := c.traffic.SaveCheckpoint(c.trafficPath); err != nil {
		return err
	}
	c.lastCheckpoint = time.Now()
	return nil
}

func (c *Controller) recoverEngine(ctx context.Context) {
	if !c.haveActive || c.supervisor.Healthy() {
		return
	}
	checkCtx, cancel := context.WithTimeout(ctx, c.cfg.Engine.CheckTimeout.Duration)
	defer cancel()
	if err := c.supervisor.StartExisting(checkCtx, c.active.Backend, c.binaryFor(c.active.Backend), c.activeHash); err != nil {
		c.logger.Printf("engine recovery failed: %v", err)
		return
	}
	c.logger.Printf("engine recovered from last-known-good configuration")
}

func (c *Controller) shutdown(parent context.Context) error {
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), c.cfg.Engine.StopTimeout.Duration)
	defer cancel()
	var shutdownErrors []error
	if err := c.collectStats(stopCtx); err != nil {
		shutdownErrors = append(shutdownErrors, fmt.Errorf("collect final traffic: %w", err))
	}
	if err := c.saveTrafficCheckpoint(); err != nil {
		shutdownErrors = append(shutdownErrors, fmt.Errorf("save final traffic checkpoint: %w", err))
	}
	statsErr := c.stats.Close()
	engineErr := c.supervisor.Close(stopCtx)
	if c.listenerRelease != nil {
		c.listenerRelease()
		c.listenerRelease = nil
	}
	return errors.Join(errors.Join(shutdownErrors...), statsErr, engineErr)
}

func (c *Controller) setDesiredUsers(users []model.User) {
	// Allocate an exact-size replacement and wipe the old backing array.
	// Reusing a longer slice would retain removed credentials in its tail.
	nextUsers := append([]model.User(nil), users...)
	if cap(c.desiredUsers) > 0 {
		clear(c.desiredUsers[:cap(c.desiredUsers)])
	}
	c.desiredUsers = nextUsers
}

func (c *Controller) trafficForceDue(now time.Time) bool {
	return c.lastTrafficFlush.IsZero() || !now.Before(c.lastTrafficFlush.Add(trafficForceFlushInterval))
}

func (c *Controller) binaryFor(backend string) string {
	if backend == "xray" {
		return c.cfg.Engine.XrayBinary
	}
	return c.cfg.Engine.SingBoxBinary
}

func (c *Controller) pullInterval() time.Duration {
	if c.haveActive {
		return c.active.PullInterval()
	}
	return 30 * time.Second
}

func (c *Controller) pushInterval() time.Duration {
	if c.haveActive {
		return c.active.PushInterval()
	}
	return 30 * time.Second
}

func (c *Controller) statsInterval() time.Duration {
	interval := c.cfg.Runtime.StatsInterval.Duration
	if push := c.pushInterval(); interval > push {
		return push
	}
	return interval
}

func (c *Controller) retryDelay(failures int, maximum time.Duration) time.Duration {
	if failures < 1 {
		failures = 1
	}
	shift := failures - 1
	if shift > 5 {
		shift = 5
	}
	delay := 2 * time.Second * time.Duration(1<<shift)
	if delay > maximum {
		delay = maximum
	}
	return c.jitter(delay)
}

func (c *Controller) jitter(value time.Duration) time.Duration {
	if value <= 0 {
		return time.Second
	}
	var random [1]byte
	if _, err := rand.Read(random[:]); err != nil {
		return value
	}
	factor := 90 + int(random[0])%21
	return value * time.Duration(factor) / 100
}

func saturatingTraffic(left, right uint64) int64 {
	if left > math.MaxInt64 || right > math.MaxInt64 || left+right < left || left+right > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(left + right)
}

func saturatingAddTraffic(left, right int64) int64 {
	if left < 0 || right < 0 || left > math.MaxInt64-right {
		return math.MaxInt64
	}
	return left + right
}

func resetTimer(timer *time.Timer, duration time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(duration)
}

func stopTimer(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}
