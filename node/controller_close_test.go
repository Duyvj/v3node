package node

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/Duyvj/v3node/common/task"
	"github.com/Duyvj/v3node/conf"
	vcore "github.com/Duyvj/v3node/core"
	"github.com/Duyvj/v3node/limiter"
	log "github.com/sirupsen/logrus"
)

func TestMultiNodeCloseRestoresEarlierControllersWhenLaterSpoolFails(t *testing.T) {
	spoolDirectory := withTemporaryTrafficSpool(t)
	panelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/v1/server/UniProxy/user":
			_, _ = w.Write([]byte(`{"users":[]}`))
		case "/api/v1/server/UniProxy/alivelist":
			_, _ = w.Write([]byte(`{"alive":{}}`))
		default:
			_, _ = w.Write([]byte(`{"data":true}`))
		}
	}))
	defer panelServer.Close()

	controllers := make([]*Controller, 0, 2)
	infos := make([]*panel.NodeInfo, 0, 2)
	configs := make([]conf.NodeConfig, 0, 2)
	for id := 1; id <= 2; id++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		_ = listener.Close()
		config := conf.NodeConfig{
			APIHost: panelServer.URL, NodeID: id, Key: "agent-token", AgentID: "agent-a",
		}
		client, err := panel.New(&config)
		if err != nil {
			t.Fatal(err)
		}
		info := &panel.NodeInfo{
			Id: id, Tag: "close-test-" + string(rune('0'+id)), Type: "vmess",
			PushInterval: time.Hour, PullInterval: time.Hour,
			Common: &panel.CommonNode{ListenIP: "127.0.0.1", ServerPort: port},
		}
		controller := NewController(client, &config, info)
		if err := controller.Prepare(context.Background()); err != nil {
			t.Fatal(err)
		}
		configs = append(configs, config)
		infos = append(infos, info)
		controllers = append(controllers, controller)
	}

	limiter.Init()
	core := vcore.New(conf.New())
	core.ReloadCh = make(chan struct{}, 1)
	if err := core.Start(infos); err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	nodes := &Node{controllers: controllers, NodeInfos: infos}
	if err := nodes.Start(configs, core); err != nil {
		t.Fatal(err)
	}

	// An empty traffic batch normally needs no file. Turn only the second
	// controller's target into a directory so its final durable commit fails
	// after the first controller has already closed successfully.
	blockedPath := controllers[1].trafficSpoolPath()
	if err := os.MkdirAll(blockedPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := nodes.Close(); err == nil {
		t.Fatal("multi-node close unexpectedly ignored the second spool failure")
	}
	for index, controller := range controllers {
		if !controller.started || !controller.inboundActive || controller.closing {
			t.Fatalf("controller %d was not restored: started=%v inbound=%v closing=%v",
				index, controller.started, controller.inboundActive, controller.closing)
		}
		if _, err := core.GetUserManager(controller.tag); err != nil {
			t.Fatalf("controller %d inbound is unavailable after rollback: %v", index, err)
		}
	}

	if err := os.Remove(blockedPath); err != nil {
		t.Fatal(err)
	}
	if err := nodes.Close(); err != nil {
		t.Fatalf("retry after repairing the spool failed: %v", err)
	}
	for index, controller := range controllers {
		if controller.started || controller.inboundActive {
			t.Fatalf("controller %d remained active after a durable close", index)
		}
	}
	if _, err := os.Stat(spoolDirectory); err != nil {
		t.Fatalf("traffic spool directory disappeared: %v", err)
	}
}

func TestControllerShutdownDoesNotRestoreInboundAfterSpoolFailure(t *testing.T) {
	withTemporaryTrafficSpool(t)
	panelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/v1/server/UniProxy/user":
			_, _ = w.Write([]byte(`{"users":[]}`))
		case "/api/v1/server/UniProxy/alivelist":
			_, _ = w.Write([]byte(`{"alive":{}}`))
		default:
			_, _ = w.Write([]byte(`{"data":true}`))
		}
	}))
	defer panelServer.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	config := conf.NodeConfig{APIHost: panelServer.URL, NodeID: 3, Key: "agent-token", AgentID: "agent-a"}
	client, err := panel.New(&config)
	if err != nil {
		t.Fatal(err)
	}
	info := &panel.NodeInfo{
		Id: 3, Tag: "terminal-shutdown-test", Type: "vmess", PushInterval: time.Hour, PullInterval: time.Hour,
		Common: &panel.CommonNode{ListenIP: "127.0.0.1", ServerPort: port},
	}
	controller := NewController(client, &config, info)
	if err := controller.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}

	limiter.Init()
	core := vcore.New(conf.New())
	if err := core.Start([]*panel.NodeInfo{info}); err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	if err := controller.Start(core); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(controller.trafficSpoolPath(), 0o700); err != nil {
		t.Fatal(err)
	}

	err = controller.Shutdown(context.Background())
	if err == nil {
		t.Fatal("terminal shutdown unexpectedly ignored spool failure")
	}
	if !controller.closing || controller.inboundActive {
		t.Fatalf("terminal shutdown restored admission: closing=%v inbound=%v", controller.closing, controller.inboundActive)
	}
	if _, err := core.GetUserManager(controller.tag); err == nil {
		t.Fatal("terminal shutdown re-added its inbound after spool failure")
	}
	if err := controller.Start(core); err == nil {
		t.Fatal("a second terminal attempt admitted a new inbound")
	}
}

func TestNodeShutdownReturnsByContextDeadline(t *testing.T) {
	controller := &Controller{}
	controller.userSyncMu.Lock()
	nodes := &Node{controllers: []*Controller{controller}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	started := time.Now()
	err := nodes.Shutdown(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("shutdown ignored context deadline for %v", elapsed)
	}
	controller.userSyncMu.Unlock()
}

func TestControllerShutdownReturnsByDeadlineWhenTrafficSpoolIsBusy(t *testing.T) {
	limiter.Init()
	core := vcore.New(conf.New())
	if err := core.Start(nil); err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	controller := &Controller{server: core, started: true}
	controller.trafficReportMu.Lock()
	defer controller.trafficReportMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	started := time.Now()
	err := controller.Shutdown(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("shutdown waited for a busy traffic spool for %v", elapsed)
	}
	if !controller.closing || !controller.terminalShutdown {
		t.Fatal("terminal shutdown did not install its irreversible fence")
	}
}

func TestControllerShutdownReturnsByDeadlineWhenTrafficSpoolWriterBlocks(t *testing.T) {
	limiter.Init()
	core := vcore.New(conf.New())
	if err := core.Start(nil); err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	blocked := make(chan struct{})
	controller := &Controller{
		server:             core,
		tag:                "blocked-writer",
		started:            true,
		trafficSpoolLoaded: true,
		trafficSpoolWriter: func(string, *trafficSpoolState) error {
			<-blocked
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	started := time.Now()
	err := controller.Shutdown(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("shutdown waited for blocked writer for %v", elapsed)
	}
	if !strings.Contains(err.Error(), `tag="blocked-writer"`) {
		t.Fatalf("shutdown error did not identify spool owner: %v", err)
	}
	close(blocked)
}

func TestShutdownFenceRejectsStartBeforeTerminalTransitionCanAcquireLifecycleLock(t *testing.T) {
	controller := &Controller{}
	controller.lifecycleMu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- controller.Shutdown(ctx) }()
	select {
	case err := <-shutdownDone:
		t.Fatalf("shutdown completed while the lifecycle gate was held: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	controller.lifecycleMu.Unlock()
	if err := <-shutdownDone; err != nil {
		t.Fatalf("shutdown error = %v", err)
	}

	if err := controller.Start(nil); err == nil {
		t.Fatal("start admitted a controller after terminal shutdown began")
	}
}

func TestRuntimeTerminalAdmissionDoesNotRaceControllerStartBackendInstall(t *testing.T) {
	for i := 0; i < 100; i++ {
		controller := &Controller{}
		controller.coreOpsMu.Lock()
		startDone := make(chan error, 1)
		go func() { startDone <- controller.Start(nil) }()
		// Start writes its raw server pointer immediately before asking for the
		// executor, which is held here. Runtime terminal admission must not read
		// that pointer outside the lifecycle gate.
		time.Sleep(time.Millisecond)
		terminalDone := make(chan struct{})
		go func() {
			(&Node{controllers: []*Controller{controller}}).BeginTerminalCoreOperations()
			close(terminalDone)
		}()
		controller.coreOpsMu.Unlock()
		<-startDone
		<-terminalDone
	}
}

func TestTerminalCoreOperationRejectsLateCallbackAccess(t *testing.T) {
	backend := &recordingControllerCore{}
	controller := &Controller{coreOps: newCoreOperationExecutor(backend)}
	controller.beginTerminalCoreOperations()

	err := controller.coreOps.requestSnapshot(context.Background())
	if err == nil {
		t.Fatal("late callback received a core lease after terminal close")
	}
	if backend.called.Load() {
		t.Fatal("late callback dereferenced the core after terminal close")
	}
}

type recordingControllerCore struct {
	controllerCore
	called atomic.Bool
}

func (c *recordingControllerCore) requestSnapshot(context.Context) error {
	c.called.Store(true)
	return nil
}

type cooperativeTrafficCore struct {
	controllerCore
	entered         chan struct{}
	operationDone   chan struct{}
	captureCalls    atomic.Int32
	closed          atomic.Bool
	postCloseAccess atomic.Bool
}

type immediateTrafficCore struct{ controllerCore }

func (*immediateTrafficCore) captureUserTraffic(context.Context, string, int) (*vcore.UserTrafficCapture, error) {
	return &vcore.UserTrafficCapture{Snapshot: map[int]int64{}}, nil
}

func (*immediateTrafficCore) quiesceNodeLinks(context.Context, string) error { return nil }

type blockingOnlineLimiter struct {
	entered chan struct{}
	release chan struct{}
}

func (*blockingOnlineLimiter) UpdateAliveList(map[int]int) {}

func (*blockingOnlineLimiter) UpdateUser(string, []panel.UserInfo, []panel.UserInfo, []panel.UserInfo) {
}

func (l *blockingOnlineLimiter) GetOnlineDevice() (*[]panel.OnlineUser, error) {
	close(l.entered)
	<-l.release
	return nil, errors.New("limiter snapshot stopped")
}

func (c *cooperativeTrafficCore) observeAccess() {
	if c.closed.Load() {
		c.postCloseAccess.Store(true)
	}
}

func (c *cooperativeTrafficCore) captureUserTraffic(ctx context.Context, _ string, _ int) (*vcore.UserTrafficCapture, error) {
	c.observeAccess()
	if c.captureCalls.Add(1) == 1 {
		close(c.entered)
		<-ctx.Done()
		c.observeAccess()
		close(c.operationDone)
		return nil, ctx.Err()
	}
	return &vcore.UserTrafficCapture{Snapshot: map[int]int64{}}, nil
}

func (c *cooperativeTrafficCore) removeNode(context.Context, string) error {
	c.observeAccess()
	return nil
}

func (c *cooperativeTrafficCore) quiesceNodeLinks(context.Context, string) error {
	c.observeAccess()
	return nil
}

func TestReportUserTrafficTaskLeavesCoreExecutorBeforeTerminalClose(t *testing.T) {
	backend := &cooperativeTrafficCore{entered: make(chan struct{}), operationDone: make(chan struct{})}
	controller := &Controller{
		server:             &vcore.V2Core{},
		tag:                "task-node",
		info:               &panel.NodeInfo{Id: 91, Tag: "task-node"},
		started:            true,
		trafficSpoolLoaded: true,
		coreOps:            newCoreOperationExecutor(backend),
	}
	controller.userReportPeriodic = &task.Task{
		Name:     "reportUserTrafficTask",
		Interval: time.Hour,
		Execute:  controller.reportUserTrafficTask,
	}
	if err := controller.userReportPeriodic.Start(true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-backend.entered:
	case <-time.After(time.Second):
		t.Fatal("reportUserTrafficTask did not enter traffic capture")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := controller.Shutdown(ctx); err != nil {
		t.Fatalf("terminal shutdown: %v", err)
	}
	if err := controller.waitForCoreOperations(ctx); err != nil {
		t.Fatalf("terminal close waited for task callback: %v", err)
	}
	select {
	case <-backend.operationDone:
	case <-time.After(time.Second):
		t.Fatal("reportUserTrafficTask retained core executor access after terminal stop")
	}

	backend.closed.Store(true)
	if _, err := controller.coreOps.captureUserTraffic(context.Background(), false, controller.tag, 0); err == nil {
		t.Fatal("late task operation was admitted after terminal close")
	}
	if backend.postCloseAccess.Load() {
		t.Fatal("a task operation accessed the core backend after close")
	}
}

func TestReportUserTrafficTaskGuardsLimiterSnapshotAgainstTerminalTeardown(t *testing.T) {
	activeLimiter := &blockingOnlineLimiter{entered: make(chan struct{}), release: make(chan struct{})}
	controller := &Controller{
		server:             &vcore.V2Core{},
		tag:                "limiter-race",
		info:               &panel.NodeInfo{Id: 92, Tag: "limiter-race"},
		trafficSpoolLoaded: true,
		limiter:            activeLimiter,
		coreOps:            newCoreOperationExecutor(&immediateTrafficCore{}),
	}
	controller.userReportPeriodic = &task.Task{
		Name:     "reportUserTrafficTask",
		Interval: time.Hour,
		Execute:  controller.reportUserTrafficTask,
	}
	if err := controller.userReportPeriodic.Start(true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-activeLimiter.entered:
	case <-time.After(time.Second):
		t.Fatal("reportUserTrafficTask did not enter limiter snapshot")
	}

	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- controller.Shutdown(context.Background()) }()
	select {
	case err := <-shutdownDone:
		t.Fatalf("shutdown tore down limiter while its snapshot was in use: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(activeLimiter.release)
	if err := <-shutdownDone; err != nil {
		t.Fatalf("shutdown after limiter snapshot: %v", err)
	}
}

type terminalOutcomeHook struct {
	mu      sync.Mutex
	entries []log.Fields
}

func (*terminalOutcomeHook) Levels() []log.Level { return log.AllLevels }

func (h *terminalOutcomeHook) Fire(entry *log.Entry) error {
	if entry.Message != "Terminal traffic spool outcome" {
		return nil
	}
	fields := make(log.Fields, len(entry.Data))
	for key, value := range entry.Data {
		fields[key] = value
	}
	h.mu.Lock()
	h.entries = append(h.entries, fields)
	h.mu.Unlock()
	return nil
}

func (h *terminalOutcomeHook) last() log.Fields {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.entries) == 0 {
		return nil
	}
	return h.entries[len(h.entries)-1]
}

func TestInactiveShutdownLogsNotAttemptedWithTagAndNodeIdentity(t *testing.T) {
	hook := &terminalOutcomeHook{}
	logger := log.StandardLogger()
	originalHooks := logger.Hooks
	logger.Hooks = make(log.LevelHooks)
	logger.AddHook(hook)
	defer func() { logger.Hooks = originalHooks }()

	controller := &Controller{
		conf: &conf.NodeConfig{NodeID: 73},
		info: &panel.NodeInfo{Id: 73, Tag: "inactive-node"},
	}
	if err := controller.Shutdown(context.Background()); err != nil {
		t.Fatalf("inactive shutdown: %v", err)
	}
	entry := hook.last()
	if entry == nil {
		t.Fatal("inactive controller silently omitted its terminal persistence outcome")
	}
	if got := entry["outcome"]; got != "not attempted" {
		t.Fatalf("terminal outcome = %v, want not attempted", got)
	}
	if got := entry["tag"]; got != "inactive-node" {
		t.Fatalf("terminal outcome tag = %v, want inactive-node", got)
	}
	if got := entry["node"]; got != 73 {
		t.Fatalf("terminal outcome node = %v, want 73", got)
	}
}

func TestTerminalSpoolSuccessLogsTagAndNodeIdentity(t *testing.T) {
	hook, restore := installTerminalOutcomeHook(t)
	defer restore()

	controller := &Controller{
		server:             &vcore.V2Core{},
		conf:               &conf.NodeConfig{NodeID: 74},
		info:               &panel.NodeInfo{Id: 74, Tag: "successful-node"},
		tag:                "successful-node",
		started:            true,
		trafficSpoolLoaded: true,
		coreOps:            newCoreOperationExecutor(&immediateTrafficCore{}),
	}
	if err := controller.Shutdown(context.Background()); err != nil {
		t.Fatalf("successful shutdown: %v", err)
	}
	assertTerminalOutcomeIdentity(t, hook.last(), "success", "successful-node", 74)
}

func TestTerminalSpoolFailureLogsTagAndNodeIdentity(t *testing.T) {
	hook, restore := installTerminalOutcomeHook(t)
	defer restore()

	spoolErr := errors.New("spool write failed")
	controller := &Controller{
		server:             &vcore.V2Core{},
		conf:               &conf.NodeConfig{NodeID: 75},
		info:               &panel.NodeInfo{Id: 75, Tag: "failed-node"},
		tag:                "failed-node",
		started:            true,
		trafficSpoolLoaded: true,
		trafficSpoolWriter: func(string, *trafficSpoolState) error { return spoolErr },
		coreOps:            newCoreOperationExecutor(&immediateTrafficCore{}),
	}
	err := controller.Shutdown(context.Background())
	if !errors.Is(err, spoolErr) {
		t.Fatalf("shutdown error = %v, want spool failure", err)
	}
	assertTerminalOutcomeIdentity(t, hook.last(), "failure", "failed-node", 75)
}

func installTerminalOutcomeHook(t *testing.T) (*terminalOutcomeHook, func()) {
	t.Helper()
	hook := &terminalOutcomeHook{}
	logger := log.StandardLogger()
	originalHooks := logger.Hooks
	logger.Hooks = make(log.LevelHooks)
	logger.AddHook(hook)
	return hook, func() { logger.Hooks = originalHooks }
}

func assertTerminalOutcomeIdentity(t *testing.T, entry log.Fields, outcome, tag string, nodeID int) {
	t.Helper()
	if entry == nil {
		t.Fatal("controller silently omitted its terminal persistence outcome")
	}
	if got := entry["outcome"]; got != outcome {
		t.Fatalf("terminal outcome = %v, want %s", got, outcome)
	}
	if got := entry["tag"]; got != tag {
		t.Fatalf("terminal outcome tag = %v, want %s", got, tag)
	}
	if got := entry["node"]; got != nodeID {
		t.Fatalf("terminal outcome node = %v, want %d", got, nodeID)
	}
}

func TestCloseControllersStartsEveryDrainConcurrently(t *testing.T) {
	controllers := []*Controller{{}, {}, {}}
	started := make(chan *Controller, len(controllers))
	release := make(chan struct{})
	done := make(chan []controllerCloseResult, 1)

	go func() {
		done <- closeControllersConcurrently(controllers, func(controller *Controller) error {
			started <- controller
			<-release
			return nil
		})
	}()

	seen := make(map[*Controller]bool, len(controllers))
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for len(seen) < len(controllers) {
		select {
		case controller := <-started:
			seen[controller] = true
		case <-deadline.C:
			t.Fatalf("only %d/%d controller drains started concurrently", len(seen), len(controllers))
		}
	}
	close(release)

	select {
	case results := <-done:
		if len(results) != len(controllers) {
			t.Fatalf("got %d close results, want %d", len(results), len(controllers))
		}
		for index, result := range results {
			if result.controller != controllers[index] || result.err != nil {
				t.Fatalf("unexpected result %d: %#v", index, result)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("parallel controller close did not finish after drains were released")
	}
}
