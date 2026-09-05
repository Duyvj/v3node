package node

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/Duyvj/v3node/common/task"
	"github.com/Duyvj/v3node/conf"
	"github.com/Duyvj/v3node/core"
	"github.com/Duyvj/v3node/limiter"
	log "github.com/sirupsen/logrus"
)

type Controller struct {
	server                  *core.V2Core
	apiClient               *panel.Client
	tag                     string
	limiter                 controllerLimiter
	userList                []panel.UserInfo
	aliveMap                map[int]int
	conf                    *conf.NodeConfig
	info                    *panel.NodeInfo
	nodeInfoMonitorPeriodic *task.Task
	userReportPeriodic      *task.Task
	renewCertPeriodic       *task.Task
	deviceSyncWatcher       *deviceSyncWatcher
	userRevisionWatcher     *userRevisionWatcher
	userRevision            string
	metrics                 *nodeMetricsCollector
	lifecycleMu             sync.Mutex
	coreOpsMu               sync.Mutex
	coreOps                 *coreOperationExecutor
	userSyncMu              sync.Mutex
	trafficReportMu         sync.Mutex
	pendingTraffic          []panel.UserTraffic
	pendingTrafficReportID  string
	queuedTraffic           []panel.UserTraffic
	quiescedUsers           []panel.UserInfo
	trafficSpoolLoaded      bool
	trafficSpoolWriter      func(string, *trafficSpoolState) error
	closing                 bool
	terminalShutdown        bool
	terminalFence           atomic.Bool
	terminalFinished        atomic.Bool
	inboundActive           bool
	prepared                bool
	started                 bool
}

// controllerLimiter is the controller-owned limiter surface. Keeping the
// dependency behavioral lets lifecycle tests hold an online-device snapshot
// at the exact teardown boundary without replacing the process-wide limiter
// registry or weakening the race assertion.
type controllerLimiter interface {
	UpdateAliveList(map[int]int)
	UpdateUser(string, []panel.UserInfo, []panel.UserInfo, []panel.UserInfo)
	GetOnlineDevice() (*[]panel.OnlineUser, error)
}

// NewController return a Node controller with default parameters.
func NewController(api *panel.Client, conf *conf.NodeConfig, info *panel.NodeInfo) *Controller {
	controller := &Controller{
		apiClient: api,
		info:      info,
		conf:      conf,
		coreOps:   newCoreOperationExecutor(nil),
	}
	return controller
}

func (c *Controller) UpdateFallbackConfig(config *conf.GlobalDeviceLimitConfig) {
	c.userSyncMu.Lock()
	cloned := cloneDeviceConfig(config)
	c.conf.GlobalDeviceLimitConfig = cloned
	c.apiClient.UpdateFallbackConfig(cloned)
	c.userSyncMu.Unlock()
}

// Prepare fetches all panel-side state and certificates without binding an
// inbound. Reload uses this while the previous runtime is still healthy.
func (c *Controller) Prepare(ctx context.Context) error {
	var err error
	if c.info == nil {
		c.info, err = c.apiClient.GetNodeInfo(ctx)
		if err != nil {
			return fmt.Errorf("get node info error: %s", err)
		}
		if c.info == nil || c.info.Common == nil {
			return fmt.Errorf("get node info error: panel returned an empty node configuration")
		}
	}
	c.tag = c.info.Tag
	// Read the revision before the user snapshot. If a device changes between
	// these calls, the watcher observes the newer revision and immediately
	// performs one more credential-only reconciliation after startup.
	if revision, revisionErr := c.apiClient.GetUserRevision(ctx); revisionErr == nil {
		c.userRevision = revision
	} else {
		log.WithFields(log.Fields{"tag": c.tag, "err": revisionErr}).Debug("User revision endpoint unavailable; periodic pull remains active")
	}
	c.userList, err = c.apiClient.GetUserList(ctx)
	if err != nil {
		return fmt.Errorf("get user list error: %s", err)
	}
	if c.userList == nil {
		return fmt.Errorf("get user list error: panel returned not-modified before an initial user list")
	}
	c.aliveMap, err = c.apiClient.GetUserAlive(ctx)
	if err != nil {
		return fmt.Errorf("failed to get user alive list: %s", err)
	}
	if c.info.Security == panel.Tls {
		if err := c.requestCertContext(ctx); err != nil {
			return fmt.Errorf("request cert error: %s", err)
		}
	}
	c.prepared = true
	return nil
}

// Start implement the Start() function of the service interface
func (c *Controller) Start(x *core.V2Core) error {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	c.userSyncMu.Lock()
	if c.terminalFence.Load() || c.terminalShutdown || c.started || c.inboundActive {
		c.userSyncMu.Unlock()
		return fmt.Errorf("node controller %s is already active", c.tag)
	}
	c.closing = false
	c.userSyncMu.Unlock()
	// Init Core
	c.server = x
	if err := c.coreExecutor().install(x); err != nil {
		return fmt.Errorf("node controller %s core is terminally shut down", c.tag)
	}
	if !c.prepared {
		if err := c.Prepare(context.Background()); err != nil {
			return err
		}
	}
	if err := c.restoreTrafficSpool(); err != nil {
		return fmt.Errorf("restore durable traffic batch: %s", err)
	}
	if c.terminalFence.Load() {
		return fmt.Errorf("node controller %s is terminally shut down", c.tag)
	}
	node := c.info
	// A controller reused by rollback can retain a deletion transaction whose
	// counters became durable during Close. Do not briefly re-authorize those
	// credentials in the replacement core; syncUsers will finalize the retained
	// transaction and re-add only UUIDs that are present in the latest panel
	// list.
	runtimeUsers := removeUsersByCredential(c.userList, c.quiescedUsers)

	// add limiter
	l := limiter.AddLimiter(c.info.Type, c.tag, runtimeUsers, c.aliveMap, c.conf.GlobalDeviceLimitConfig, c.conf.APIHost)
	c.limiter = l
	c.metrics = newNodeMetricsCollector()
	if c.terminalFence.Load() {
		limiter.DeleteLimiter(c.tag)
		c.limiter = nil
		return fmt.Errorf("node controller %s is terminally shut down", c.tag)
	}
	// Add new tag
	err := c.coreExecutor().addNode(context.Background(), false, c.tag, node)
	if err != nil {
		return fmt.Errorf("add new node error: %s", err)
	}
	c.inboundActive = true
	c.started = true
	added := 0
	if len(runtimeUsers) > 0 {
		added, err = c.coreExecutor().addUsers(context.Background(), false, &core.AddUsersParams{
			Tag:      c.tag,
			Users:    runtimeUsers,
			NodeInfo: node,
		})
		if err != nil {
			return fmt.Errorf("add users error: %s", err)
		}
	}
	// A controller can be restarted on the same core when a multi-node close or
	// reload is rolled back. Remove the tag-level rejection barrier only after
	// the listener and all runtime users are ready again.
	if c.terminalFence.Load() {
		_ = c.coreExecutor().removeNode(context.Background(), false, c.tag)
		c.inboundActive = false
		c.started = false
		limiter.DeleteLimiter(c.tag)
		c.limiter = nil
		return fmt.Errorf("node controller %s is terminally shut down", c.tag)
	}
	if err := c.coreExecutor().reactivateNodeLinks(context.Background(), c.tag); err != nil {
		return err
	}
	log.WithField("tag", c.tag).Infof("Added %d new users", added)
	c.info = node
	c.startBackgroundServices()
	return nil
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	c.stopBackgroundServices()

	c.userSyncMu.Lock()
	c.closing = true
	defer c.userSyncMu.Unlock()
	if !c.started || c.server == nil {
		if c.limiter != nil {
			limiter.DeleteLimiter(c.tag)
			c.limiter = nil
		}
		return nil
	}

	// Stop accepting new connections before the last atomic counter capture.
	// If any later durability barrier fails, restore this same controller on the
	// old core before returning so a failed reload does not silently leave the
	// supposedly retained runtime offline.
	if c.inboundActive {
		if err := c.coreExecutor().removeNode(context.Background(), false, c.tag); err != nil {
			c.closing = false
			c.startBackgroundServices()
			return fmt.Errorf("del node error: %s", err)
		}
		c.inboundActive = false
	}
	if err := c.coreExecutor().quiesceNodeLinks(context.Background(), false, c.tag); err != nil {
		return c.restoreAfterCloseFailureLocked(fmt.Errorf("drain node links: %w", err))
	}
	if err := c.spoolOutstandingTrafficWithUsersLocked(); err != nil {
		return c.restoreAfterCloseFailureLocked(fmt.Errorf("persist traffic: %w", err))
	}

	if c.limiter != nil {
		limiter.DeleteLimiter(c.tag)
		c.limiter = nil
	}
	c.started = false
	return nil
}

// Shutdown permanently stops this controller. Unlike Close, it deliberately
// leaves the inbound quiesced when accounting cannot be made durable: terminal
// process shutdown must never reopen admission after SIGINT or SIGTERM.
func (c *Controller) Shutdown(ctx context.Context) error {
	if !lockControllerForShutdown(ctx, &c.lifecycleMu) {
		return c.terminalOutcome("not attempted", ctx.Err())
	}
	defer c.lifecycleMu.Unlock()
	// Install terminal state while holding the same gate that owns every
	// admission and rollback restoration. There is no atomic-check gap between
	// this transition and AddNode/ReactivateNodeLinks.
	c.terminalFence.Store(true)
	c.terminalShutdown = true
	// Production Start already bound the executor.  Preserve compatibility with
	// partially constructed controllers used by recovery tests before closing
	// admission for the terminal-only operations below.
	c.coreExecutor().installIfUnset(c.server)
	c.beginTerminalCoreOperations()
	defer c.terminalFinished.Store(true)
	c.signalBackgroundServices()

	if !lockControllerForShutdown(ctx, &c.userSyncMu) {
		return c.terminalOutcome("not attempted", ctx.Err())
	}
	defer c.userSyncMu.Unlock()
	c.closing = true
	if !c.started || c.server == nil {
		if c.limiter != nil {
			limiter.DeleteLimiter(c.tag)
			c.limiter = nil
		}
		return c.terminalOutcome("not attempted", ctx.Err())
	}

	var shutdownErr error
	if c.inboundActive {
		if err := c.coreExecutor().removeNode(ctx, true, c.tag); err != nil {
			shutdownErr = errors.Join(shutdownErr, fmt.Errorf("del node: %w", err))
		} else {
			c.inboundActive = false
		}
	}
	// Keep the tag rejection barrier installed even when either the listener
	// removal or durable spool fails. A later terminal attempt may retry the
	// accounting work, but it must never reactivate this inbound.
	if err := ctx.Err(); err != nil {
		shutdownErr = errors.Join(shutdownErr, fmt.Errorf("persist traffic: not attempted: %w", err))
	} else if err := c.coreExecutor().quiesceNodeLinks(ctx, true, c.tag); err != nil {
		shutdownErr = errors.Join(shutdownErr, fmt.Errorf("drain node links: %w", err))
	}
	if err := ctx.Err(); err != nil {
		shutdownErr = errors.Join(shutdownErr, fmt.Errorf("persist traffic: incomplete: %w", err))
	} else if err := c.spoolOutstandingTrafficWithUsersLockedContext(ctx); err != nil {
		shutdownErr = errors.Join(shutdownErr, fmt.Errorf("persist traffic: incomplete: %w", err))
	} else {
		c.terminalOutcome("success", nil)
	}
	if c.limiter != nil {
		limiter.DeleteLimiter(c.tag)
		c.limiter = nil
	}
	c.started = false
	if shutdownErr == nil && ctx.Err() == nil {
		return nil
	}
	return c.terminalOutcome("failure", errors.Join(shutdownErr, ctx.Err()))
}

func (c *Controller) terminalOutcome(outcome string, err error) error {
	tag, nodeID := c.terminalIdentity()
	log.WithFields(log.Fields{"tag": tag, "node": nodeID, "outcome": outcome, "err": err}).Info("Terminal traffic spool outcome")
	if err == nil {
		return nil
	}
	return fmt.Errorf("terminal traffic spool %s (tag=%q node=%d): %w", outcome, tag, nodeID, err)
}

func (c *Controller) terminalIdentity() (string, int) {
	tag := c.tag
	nodeID := 0
	if c.info != nil {
		if tag == "" {
			tag = c.info.Tag
		}
		nodeID = c.info.Id
	}
	if nodeID == 0 && c.conf != nil {
		nodeID = c.conf.NodeID
	}
	return tag, nodeID
}

func (c *Controller) terminalShutdownFinished() bool {
	return c == nil || c.terminalFinished.Load()
}

func lockControllerForShutdown(ctx context.Context, mutex *sync.Mutex) bool {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if mutex.TryLock() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

func (c *Controller) stopBackgroundServices() {
	if c.userRevisionWatcher != nil {
		c.userRevisionWatcher.Close()
		c.userRevisionWatcher = nil
	}
	if c.deviceSyncWatcher != nil {
		c.deviceSyncWatcher.Close()
		c.deviceSyncWatcher = nil
	}
	if c.nodeInfoMonitorPeriodic != nil {
		c.nodeInfoMonitorPeriodic.Close()
		c.nodeInfoMonitorPeriodic = nil
	}
	if c.userReportPeriodic != nil {
		c.userReportPeriodic.Close()
		c.userReportPeriodic = nil
	}
	if c.renewCertPeriodic != nil {
		c.renewCertPeriodic.Close()
		c.renewCertPeriodic = nil
	}
}

// signalBackgroundServices is the terminal counterpart to stopBackgroundServices.
// It never waits for callbacks: the core gate makes any callback that survives
// its cancellation harmless before runtime closes the core.
func (c *Controller) signalBackgroundServices() {
	if c.nodeInfoMonitorPeriodic != nil {
		c.nodeInfoMonitorPeriodic.SignalStop()
		c.nodeInfoMonitorPeriodic = nil
	}
	if c.userReportPeriodic != nil {
		c.userReportPeriodic.SignalStop()
		c.userReportPeriodic = nil
	}
	if c.renewCertPeriodic != nil {
		c.renewCertPeriodic.SignalStop()
		c.renewCertPeriodic = nil
	}
	// These watchers can invoke controller callbacks. Signal their cancellation
	// off the terminal deadline path; core leases reject any late callback.
	if c.userRevisionWatcher != nil {
		watcher := c.userRevisionWatcher
		c.userRevisionWatcher = nil
		go watcher.Close()
	}
	if c.deviceSyncWatcher != nil {
		watcher := c.deviceSyncWatcher
		c.deviceSyncWatcher = nil
		go watcher.Close()
	}
}

func (c *Controller) startBackgroundServices() {
	if c.info == nil || c.server == nil || !c.started {
		return
	}
	c.startTasks(c.info)
	c.userRevisionWatcher = newUserRevisionWatcher(c.apiClient, c.userRevision, c.syncUserCredentials)
	c.userRevisionWatcher.Start()
	// Publish the freshly generated/self-signed certificate fingerprint right
	// after a successful start instead of waiting for the traffic interval.
	c.reportNodeStatusImmediately()
	c.deviceSyncWatcher = newDeviceSyncWatcher(c.conf.GlobalDeviceLimitConfig, c.conf.APIHost)
	if c.deviceSyncWatcher != nil {
		if err := c.deviceSyncWatcher.Start(c.conf.APIHost, c.refreshUsersImmediately); err != nil {
			c.deviceSyncWatcher = nil
			log.WithError(err).WithField("tag", c.tag).Warn("Device UUID fast-sync disabled")
		} else {
			log.WithField("tag", c.tag).Info("Start device UUID fast-sync watcher")
		}
	}
}

// restoreAfterCloseFailureLocked requires userSyncMu and is the rollback half
// of Close. Live counters were not committed when the durable spool failed, so
// reinstalling the inbound on the same core preserves every byte for retry.
func (c *Controller) restoreAfterCloseFailureLocked(cause error) error {
	if c.terminalFence.Load() {
		// A SIGINT/SIGTERM arrived while a transactional reload close was
		// draining. Do not let its rollback reopen this inbound; Shutdown owns
		// the final fail-closed transition once Close releases lifecycleMu.
		return cause
	}
	restoreErr := c.restoreInboundLocked()
	if restoreErr == nil {
		c.closing = false
		c.startBackgroundServices()
		return cause
	}
	return fmt.Errorf("%w; restore previous node runtime: %v", cause, restoreErr)
}

func (c *Controller) restoreInboundLocked() error {
	if c.inboundActive {
		return c.coreExecutor().reactivateNodeLinks(context.Background(), c.tag)
	}
	if err := c.coreExecutor().addNode(context.Background(), false, c.tag, c.info); err != nil {
		return fmt.Errorf("re-add inbound: %w", err)
	}
	c.inboundActive = true
	runtimeUsers := removeUsersByCredential(c.userList, c.quiescedUsers)
	if len(runtimeUsers) > 0 {
		_, err := c.coreExecutor().addUsers(context.Background(), false, &core.AddUsersParams{Tag: c.tag, Users: runtimeUsers, NodeInfo: c.info})
		if err != nil {
			_ = c.coreExecutor().removeNode(context.Background(), false, c.tag)
			c.inboundActive = false
			return fmt.Errorf("restore users: %w", err)
		}
	}
	return c.coreExecutor().reactivateNodeLinks(context.Background(), c.tag)
}
