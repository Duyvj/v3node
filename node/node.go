package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/Duyvj/v3node/conf"
	"github.com/Duyvj/v3node/core"
	log "github.com/sirupsen/logrus"
)

// maxConcurrentNodePreparation limits panel requests made while a runtime is
// being prepared. Preparation is independent per node, but an unbounded fan
// out can overload a panel (and a VPS with many assigned nodes).
const maxConcurrentNodePreparation = 4

type Node struct {
	controllers []*Controller
	NodeInfos   []*panel.NodeInfo
}

// RuntimeSnapshot is the last fully prepared desired state required to start
// Xray without reaching the panel. It intentionally excludes Agent tokens;
// callers rebuild per-node clients from the live root-owned config file.
type RuntimeSnapshot struct {
	NodeInfos     []*panel.NodeInfo               `json:"node_infos"`
	Users         [][]panel.UserInfo              `json:"users"`
	Alive         []map[int]int                   `json:"alive"`
	DeviceConfigs []*conf.GlobalDeviceLimitConfig `json:"device_configs,omitempty"`
}

type controllerCloseResult struct {
	controller *Controller
	wasActive  bool
	err        error
}

// UpdateFallbackConfig installs only the signed user-snapshot source. It is a
// control-plane client setting and therefore must not close or rebuild Xray
// listeners when Redis HA becomes ready or temporarily unavailable.
func (n *Node) UpdateFallbackConfig(config *conf.GlobalDeviceLimitConfig) {
	for _, controller := range n.controllers {
		if controller != nil {
			controller.UpdateFallbackConfig(config)
		}
	}
}

func New(nodes []conf.NodeConfig) (*Node, error) {
	return NewContext(context.Background(), nodes)
}

func NewContext(ctx context.Context, nodes []conf.NodeConfig) (*Node, error) {
	n := &Node{
		controllers: make([]*Controller, len(nodes)),
		NodeInfos:   make([]*panel.NodeInfo, len(nodes)),
	}
	errs := parallelNodeWork(ctx, len(nodes), func(workCtx context.Context, i int) error {
		node := nodes[i]
		p, err := panel.New(&node)
		if err != nil {
			return err
		}
		info, err := p.GetNodeInfo(workCtx)
		if err != nil {
			return fmt.Errorf("get node info for node %d: %w", node.NodeID, err)
		}
		if info == nil || info.Common == nil {
			return fmt.Errorf("get node info for node %d: panel returned an empty node configuration", node.NodeID)
		}
		if nodes[i].DisableSniffing != nil && *nodes[i].DisableSniffing {
			info.DisableSniffing = true
		}
		n.controllers[i] = NewController(p, &nodes[i], info)
		n.NodeInfos[i] = info
		return nil
	})
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	if err := ValidateUniqueServerPorts(n.NodeInfos); err != nil {
		return nil, err
	}
	return n, nil
}

// NewFromRuntimeSnapshot prepares controllers from a previously validated
// last-known-good state. Background polling still uses fresh API clients and
// resumes automatically when the panel becomes available again.
func NewFromRuntimeSnapshot(nodes []conf.NodeConfig, snapshot RuntimeSnapshot) (*Node, error) {
	if len(nodes) != len(snapshot.NodeInfos) || len(nodes) != len(snapshot.Users) || len(nodes) != len(snapshot.Alive) {
		return nil, fmt.Errorf("runtime snapshot shape does not match assigned nodes")
	}
	if len(snapshot.DeviceConfigs) > 0 && len(snapshot.DeviceConfigs) != len(nodes) {
		return nil, fmt.Errorf("runtime snapshot Redis fallback shape does not match assigned nodes")
	}
	n := &Node{
		controllers: make([]*Controller, len(nodes)),
		NodeInfos:   make([]*panel.NodeInfo, len(nodes)),
	}
	for i := range nodes {
		if len(snapshot.DeviceConfigs) > 0 {
			nodes[i].GlobalDeviceLimitConfig = cloneDeviceConfig(snapshot.DeviceConfigs[i])
		}
		info := snapshot.NodeInfos[i]
		if info == nil || info.Common == nil {
			return nil, fmt.Errorf("runtime snapshot node %d is empty", i)
		}
		if nodes[i].DisableSniffing != nil && *nodes[i].DisableSniffing {
			info.DisableSniffing = true
		}
		if info.Id != nodes[i].NodeID {
			return nil, fmt.Errorf("runtime snapshot node ID %d does not match assignment %d", info.Id, nodes[i].NodeID)
		}
		pt := strings.TrimSpace(info.Common.PanelType)
		if pt != "" &&
			!strings.EqualFold(pt, "v2node") &&
			!strings.EqualFold(pt, "v2board") &&
			!strings.EqualFold(pt, "zboard") {
			return nil, fmt.Errorf("runtime snapshot node %d has invalid panel type %q", info.Id, info.Common.PanelType)
		}
		if err := panel.ValidateUserListSnapshot(snapshot.Users[i]); err != nil {
			return nil, fmt.Errorf("runtime snapshot users for node %d: %w", info.Id, err)
		}
		client, err := panel.New(&nodes[i])
		if err != nil {
			return nil, err
		}
		controller := NewController(client, &nodes[i], info)
		controller.tag = info.Tag
		controller.userList = append([]panel.UserInfo(nil), snapshot.Users[i]...)
		controller.aliveMap = cloneAliveMap(snapshot.Alive[i])
		controller.prepared = true
		n.controllers[i] = controller
		n.NodeInfos[i] = info
	}
	if err := ValidateUniqueServerPorts(n.NodeInfos); err != nil {
		return nil, err
	}
	return n, nil
}

// RuntimeSnapshot returns an isolated copy suitable for atomic persistence.
func (n *Node) RuntimeSnapshot() (RuntimeSnapshot, error) {
	snapshot := RuntimeSnapshot{
		NodeInfos:     make([]*panel.NodeInfo, len(n.controllers)),
		Users:         make([][]panel.UserInfo, len(n.controllers)),
		Alive:         make([]map[int]int, len(n.controllers)),
		DeviceConfigs: make([]*conf.GlobalDeviceLimitConfig, len(n.controllers)),
	}
	for i, controller := range n.controllers {
		if controller == nil {
			return RuntimeSnapshot{}, fmt.Errorf("runtime snapshot controller %d is empty", i)
		}
		controller.userSyncMu.Lock()
		info, err := cloneNodeInfo(controller.info)
		if err != nil {
			controller.userSyncMu.Unlock()
			return RuntimeSnapshot{}, fmt.Errorf("clone runtime node %d: %w", i, err)
		}
		snapshot.NodeInfos[i] = info
		snapshot.Users[i] = append([]panel.UserInfo(nil), controller.userList...)
		snapshot.Alive[i] = cloneAliveMap(controller.aliveMap)
		snapshot.DeviceConfigs[i] = cloneDeviceConfig(controller.conf.GlobalDeviceLimitConfig)
		controller.userSyncMu.Unlock()
	}
	return snapshot, nil
}

func cloneDeviceConfig(source *conf.GlobalDeviceLimitConfig) *conf.GlobalDeviceLimitConfig {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.RedisSentinelAddrs = append([]string(nil), source.RedisSentinelAddrs...)
	if source.SyncEnabled != nil {
		enabled := *source.SyncEnabled
		cloned.SyncEnabled = &enabled
	}
	return &cloned
}

func cloneNodeInfo(source *panel.NodeInfo) (*panel.NodeInfo, error) {
	if source == nil {
		return nil, fmt.Errorf("node info is empty")
	}
	encoded, err := json.Marshal(source)
	if err != nil {
		return nil, err
	}
	var cloned panel.NodeInfo
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		return nil, err
	}
	return &cloned, nil
}

func cloneAliveMap(source map[int]int) map[int]int {
	cloned := make(map[int]int, len(source))
	for id, count := range source {
		cloned[id] = count
	}
	return cloned
}

// ValidateUniqueServerPorts performs an agent-side preflight before any
// inbound is opened. V2Board also validates assignments, but this second check
// keeps a stale or malformed manifest from tearing down a working core.
func ValidateUniqueServerPorts(infos []*panel.NodeInfo) error {
	type owner struct {
		nodeID int
		tag    string
	}
	ports := make(map[int]owner, len(infos))
	for _, info := range infos {
		if info == nil || info.Common == nil {
			return fmt.Errorf("validate node ports: received empty node configuration")
		}
		port := info.Common.ServerPort
		if port <= 0 || port > 65535 {
			return fmt.Errorf("node %d has invalid server_port %d", info.Id, port)
		}
		if previous, exists := ports[port]; exists {
			return fmt.Errorf(
				"duplicate server_port %d on this VPS agent: node %d (%s) conflicts with existing node %d (%s)",
				port,
				info.Id,
				info.Tag,
				previous.nodeID,
				previous.tag,
			)
		}
		ports[port] = owner{nodeID: info.Id, tag: info.Tag}
	}
	return nil
}

func (n *Node) Prepare(ctx context.Context, nodes []conf.NodeConfig) error {
	errs := parallelNodeWork(ctx, len(nodes), func(workCtx context.Context, i int) error {
		return n.controllers[i].Prepare(workCtx)
	})
	for i, err := range errs {
		if err != nil {
			nodeConfig := nodes[i]
			return fmt.Errorf("prepare node controller [%s-%d] error: %w", nodeConfig.APIHost, nodeConfig.NodeID, err)
		}
	}
	return nil
}

// parallelNodeWork runs independent per-node preparation with a small bounded
// worker pool. Errors are retained by index so callers can report the same
// first failing node they would have reported in the old sequential loop.
func parallelNodeWork(ctx context.Context, count int, work func(context.Context, int) error) []error {
	errs := make([]error, count)
	if count == 0 {
		return errs
	}
	workers := count
	if workers > maxConcurrentNodePreparation {
		workers = maxConcurrentNodePreparation
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	var firstFailureMu sync.Mutex
	firstFailure := -1
	completed := make([]bool, count)
	var wg sync.WaitGroup
	wg.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-workCtx.Done():
					return
				case i, ok := <-jobs:
					if !ok {
						return
					}
					if workCtx.Err() != nil {
						return
					}
					err := work(workCtx, i)
					firstFailureMu.Lock()
					completed[i] = true
					if err == nil {
						firstFailureMu.Unlock()
						continue
					}
					if firstFailure < 0 {
						firstFailure = i
						errs[i] = err
						cancel()
					} else if ctx.Err() != nil || !errors.Is(err, context.Canceled) {
						// A parent cancellation is a real result. Preserve other
						// errors too; only cancellation caused by another worker is
						// omitted so it cannot hide the original failure.
						errs[i] = err
					}
					firstFailureMu.Unlock()
				}
			}
		}()
	}
queueLoop:
	for i := 0; i < count; i++ {
		select {
		case <-workCtx.Done():
			// Stop queuing work after either the parent is canceled or a
			// worker has failed and canceled the derived context.
			break queueLoop
		case jobs <- i:
		}
		if workCtx.Err() != nil {
			break
		}
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		for i := range errs {
			if !completed[i] && errs[i] == nil {
				errs[i] = err
			}
		}
	}
	return errs
}

func (n *Node) Start(nodes []conf.NodeConfig, core *core.V2Core) error {
	for i, node := range nodes {
		err := n.controllers[i].Start(core)
		if err != nil {
			// Close the failed controller too: AddNode may already have bound its
			// port before a later initialization step failed.
			for j := i; j >= 0; j-- {
				if closeErr := n.controllers[j].Close(); closeErr != nil {
					log.Errorf("rollback controller failed: %v", closeErr)
				}
			}
			return fmt.Errorf("start node controller [%s-%d] error: %s",
				node.APIHost,
				node.NodeID,
				err)
		}
	}
	return nil
}

func (n *Node) Close() error {
	results := closeControllersConcurrently(n.controllers, func(controller *Controller) error {
		return controller.Close()
	})

	var closeErr error
	for _, result := range results {
		if result.err != nil {
			log.Errorf("close controller failed: %v", result.err)
			closeErr = errors.Join(closeErr, result.err)
		}
	}
	if closeErr == nil {
		return nil
	}

	// Closing a multi-node Agent is transactional from the caller's
	// perspective. A controller whose Close failed restores itself. Bring every
	// other controller that closed successfully back before reload reports that
	// it retained the previous runtime. Restore in reverse configuration order,
	// matching the previous sequential rollback behavior.
	var restoreErr error
	for index := len(results) - 1; index >= 0; index-- {
		result := results[index]
		if result.controller == nil || !result.wasActive || result.err != nil {
			continue
		}
		if err := result.controller.Start(result.controller.server); err != nil {
			restoreErr = errors.Join(restoreErr, err)
		}
	}
	if restoreErr != nil {
		return fmt.Errorf("close node controllers: %w; restore previous controllers: %v", closeErr, restoreErr)
	}
	return fmt.Errorf("close node controllers: %w; previous controllers restored", closeErr)
}

// Shutdown is the non-transactional terminal counterpart to Close. It does
// not restart controllers after a failed drain, because process termination
// must remain fail-closed for new connections.
func (n *Node) Shutdown(ctx context.Context) error {
	var shutdownErr error
	for _, controller := range n.controllers {
		if controller == nil {
			continue
		}
		if err := controller.Shutdown(ctx); err != nil {
			shutdownErr = errors.Join(shutdownErr, err)
		}
	}
	return shutdownErr
}

// TerminalShutdownFinished reports whether every controller that may touch
// the current core completed its terminal transition. A caller must not tear
// down that core while a pre-existing lifecycle operation still owns it.
func (n *Node) TerminalShutdownFinished() bool {
	if n == nil {
		return true
	}
	for _, controller := range n.controllers {
		if !controller.terminalShutdownFinished() {
			return false
		}
	}
	return true
}

// BeginTerminalCoreOperations closes admission for every controller before
// terminal accounting starts. This must happen as one runtime-wide phase: a
// slow drain for one node must not leave another node able to enter the core.
func (n *Node) BeginTerminalCoreOperations() {
	if n == nil {
		return
	}
	for _, controller := range n.controllers {
		if controller != nil {
			controller.beginTerminalCoreOperations()
		}
	}
}

// CloseCoreOperations waits only for callbacks that were admitted before the
// runtime-wide terminal admission phase. It intentionally does not reopen or
// newly close admission here, because the caller's deadline may already have
// elapsed after a preceding controller drain.
func (n *Node) CloseCoreOperations(ctx context.Context) error {
	if n == nil {
		return nil
	}
	var waitErr error
	for _, controller := range n.controllers {
		if controller != nil {
			waitErr = errors.Join(waitErr, controller.waitForCoreOperations(ctx))
		}
	}
	return waitErr
}

func closeControllersConcurrently(controllers []*Controller, closeController func(*Controller) error) []controllerCloseResult {
	results := make([]controllerCloseResult, len(controllers))
	var wait sync.WaitGroup
	for index, c := range controllers {
		if c == nil {
			continue
		}

		// Each controller owns a distinct inbound/tag. Closing them concurrently
		// makes the traffic-drain deadline apply once per Agent instead of once
		// per node (N nodes previously took up to N * 5 seconds).
		c.userSyncMu.Lock()
		wasActive := c.started
		c.userSyncMu.Unlock()
		results[index] = controllerCloseResult{controller: c, wasActive: wasActive}
		wait.Add(1)
		go func(index int, controller *Controller) {
			defer wait.Done()
			results[index].err = closeController(controller)
		}(index, c)
	}
	wait.Wait()
	return results
}
