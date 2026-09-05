package cmd

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/Duyvj/v3node/conf"
	vcore "github.com/Duyvj/v3node/core"
	"github.com/Duyvj/v3node/limiter"
	"github.com/Duyvj/v3node/node"
)

type blockedTerminalNodes struct {
	operationStarted chan struct{}
	operationDone    chan struct{}
	admissionClosed  bool
	admissionWasOpen bool
}

func (n *blockedTerminalNodes) BeginTerminalCoreOperations() { n.admissionClosed = true }

func (n *blockedTerminalNodes) Shutdown(ctx context.Context) error {
	if !n.admissionClosed {
		n.admissionWasOpen = true
		return errors.New("core admission remained open during terminal accounting")
	}
	close(n.operationStarted)
	<-ctx.Done()
	close(n.operationDone)
	return ctx.Err()
}

func (n *blockedTerminalNodes) CloseCoreOperations(ctx context.Context) error {
	select {
	case <-n.operationDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type recordingCoreCloser struct{ closed bool }

func (c *recordingCoreCloser) Close() error {
	c.closed = true
	return nil
}

type orderedCoreCloser struct {
	operationDone <-chan struct{}
	closedEarly   bool
	err           error
}

func (c *orderedCoreCloser) Close() error {
	select {
	case <-c.operationDone:
	default:
		c.closedEarly = true
	}
	return c.err
}

func TestShutdownRuntimeAttemptsCoreCloseAfterCooperativeOperationDeadline(t *testing.T) {
	nodes := &blockedTerminalNodes{operationStarted: make(chan struct{}), operationDone: make(chan struct{})}
	closeErr := errors.New("core close failed")
	core := &orderedCoreCloser{operationDone: nodes.operationDone, err: closeErr}
	running := &runningRuntime{terminalNodes: nodes, terminalCore: core}

	started := time.Now()
	err := shutdownRuntime(running, 30*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("shutdown exceeded its bounded deadline: %v", elapsed)
	}
	if !errors.Is(err, closeErr) {
		t.Fatalf("shutdown error = %v, want joined core close failure", err)
	}
	if core.closedEarly {
		t.Fatal("shutdown closed the core before the cooperative operation returned")
	}
}

func TestShutdownRuntimeClosesCoreAdmissionBeforeBoundedAccounting(t *testing.T) {
	nodes := &blockedTerminalNodes{operationStarted: make(chan struct{}), operationDone: make(chan struct{})}
	core := &recordingCoreCloser{}
	err := shutdownRuntime(&runningRuntime{terminalNodes: nodes, terminalCore: core}, 30*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown error = %v, want context deadline exceeded after core admission closes", err)
	}
	if !core.closed {
		t.Fatal("shutdown did not attempt core close after closing admission")
	}
	if nodes.admissionWasOpen {
		t.Fatal("runtime began terminal accounting before closing core admission")
	}
}

func TestStartPreparedRuntimeWithZeroAssignedNodes(t *testing.T) {
	limiter.Init()
	nodes, err := node.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	prepared := &preparedRuntime{config: conf.New(), nodes: nodes}
	running, err := startPreparedRuntime(prepared, make(chan struct{}, 1))
	if err != nil {
		t.Fatalf("zero-node agent runtime failed to start: %v", err)
	}
	running.Close()
}

func TestShutdownRuntimeClosesCoreAfterBoundedAccountingAttempt(t *testing.T) {
	limiter.Init()
	nodes, err := node.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	running, err := startPreparedRuntime(&preparedRuntime{config: conf.New(), nodes: nodes}, make(chan struct{}, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := shutdownRuntime(running, 50*time.Millisecond); err != nil {
		t.Fatalf("shutdown runtime: %v", err)
	}
	if running.core.Server != nil {
		t.Fatal("shutdown left the core open after accounting completed")
	}
}

func TestShutdownRuntimeCancelsRealTrafficCaptureBeforeClosingProductionCore(t *testing.T) {
	var statusCalls atomic.Int32
	statusReturned := make(chan struct{})
	var statusReturnedOnce sync.Once
	panelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/api/v1/server/UniProxy/status" && statusCalls.Add(1) >= 2 {
			statusReturnedOnce.Do(func() { close(statusReturned) })
		}
		_, _ = w.Write([]byte(`{"data":true}`))
	}))
	defer panelServer.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	nodeConfig := conf.NodeConfig{APIHost: panelServer.URL, NodeID: 76, Key: "agent-token", AgentID: "agent-a"}
	info := &panel.NodeInfo{
		Id: 76, Tag: "integrated-capture", Type: "vmess",
		PushInterval: 20 * time.Millisecond, PullInterval: time.Hour,
		Common: &panel.CommonNode{
			PanelType: conf.RequiredPanelType, Protocol: "vmess",
			ListenIP: "127.0.0.1", ServerPort: port, BaseConfig: &panel.BaseConfig{},
		},
	}
	nodes, err := node.NewFromRuntimeSnapshot([]conf.NodeConfig{nodeConfig}, node.RuntimeSnapshot{
		NodeInfos: []*panel.NodeInfo{info}, Users: [][]panel.UserInfo{{}}, Alive: []map[int]int{{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	config := conf.New()
	config.NodeConfigs = []conf.NodeConfig{nodeConfig}
	limiter.Init()
	running, err := startPreparedRuntime(&preparedRuntime{config: config, nodes: nodes}, make(chan struct{}, 1))
	if err != nil {
		t.Fatal(err)
	}

	// Hold the production user-map boundary, not an executor/backend mock. The
	// real periodic report must leave this context-aware wait before the real
	// V2Core is closed by runningRuntime.Shutdown.
	userMapLock := productionUserMapLock(t, running.core)
	userMapLock.Lock()

	select {
	case <-statusReturned:
	case <-time.After(2 * time.Second):
		userMapLock.Unlock()
		_ = running.Close()
		t.Fatal("real reportUserTrafficTask did not reach its second status report")
	}
	activeDeadline := time.Now().Add(time.Second)
	for {
		probeCtx, probeCancel := context.WithTimeout(context.Background(), time.Millisecond)
		probeErr := running.nodes.CloseCoreOperations(probeCtx)
		probeCancel()
		if errors.Is(probeErr, context.DeadlineExceeded) {
			break
		}
		if time.Now().After(activeDeadline) {
			userMapLock.Unlock()
			_ = running.Close()
			t.Fatal("real reportUserTrafficTask did not enter production traffic capture")
		}
		time.Sleep(time.Millisecond)
	}

	err = shutdownRuntime(running, 30*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		userMapLock.Unlock()
		t.Fatalf("shutdown error = %v, want joined context deadline", err)
	}
	if !strings.Contains(err.Error(), `tag="integrated-capture"`) || !strings.Contains(err.Error(), "node=76") {
		userMapLock.Unlock()
		t.Fatalf("joined shutdown error omitted controller identity: %v", err)
	}
	if running.core.Server != nil {
		userMapLock.Unlock()
		t.Fatal("runtime did not attempt production core close after the deadline")
	}

	probeCtx, probeCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	drainErr := running.nodes.CloseCoreOperations(probeCtx)
	probeCancel()
	if drainErr != nil {
		// Keep the core boundary locked on failure: releasing it after V2Core.Close
		// would let the known-broken callback dereference torn-down core state.
		t.Fatalf("real report task retained production core access after close: %v", drainErr)
	}
	userMapLock.Unlock()
}

func productionUserMapLock(t *testing.T, core *vcore.V2Core) *sync.RWMutex {
	t.Helper()
	coreValue := reflect.ValueOf(core).Elem()
	usersField := coreValue.FieldByName("users")
	if !usersField.IsValid() || usersField.IsNil() {
		t.Fatal("production core user map is unavailable")
	}
	usersValue := reflect.NewAt(usersField.Type().Elem(), unsafe.Pointer(usersField.Pointer())).Elem()
	lockField := usersValue.FieldByName("mapLock")
	if !lockField.IsValid() || !lockField.CanAddr() {
		t.Fatal("production core user-map lock is unavailable")
	}
	return (*sync.RWMutex)(unsafe.Pointer(lockField.UnsafeAddr()))
}

func TestReloadRestoresPreviousRuntimeWhenReplacementControllerFails(t *testing.T) {
	limiter.Init()
	oldNodes, err := node.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	old, err := startPreparedRuntime(&preparedRuntime{config: conf.New(), nodes: oldNodes}, make(chan struct{}, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	oldCore := old.core
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	occupiedPort := occupied.Addr().(*net.TCPAddr).Port

	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/server/agent/config":
			_, _ = w.Write([]byte(`{"panel_type":"zboard","revision":"test-revision","nodes":[12],"poll_interval":15}`))
		case "/api/v2/server/config":
			_, _ = w.Write([]byte(`{"panel_type":"zboard","listen_ip":"127.0.0.1","server_port":` + strconv.Itoa(occupiedPort) + `,"protocol":"vmess","network":"tcp","tls":0,"base_config":{"push_interval":60,"pull_interval":60}}`))
		case "/api/v1/server/UniProxy/user":
			_, _ = w.Write([]byte(`{"users":[]}`))
		case "/api/v1/server/UniProxy/alivelist":
			_, _ = w.Write([]byte(`{"alive":{}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer panel.Close()

	configPath := filepath.Join(t.TempDir(), "config.json")
	configJSON := `{"type":"zboard","Agent":{"Enable":true,"ApiHost":"` + panel.URL + `","AgentID":"agent-a","AgentToken":"agent-token"}}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0600); err != nil {
		t.Fatal(err)
	}

	_, err = reloadRuntime(configPath, old, make(chan struct{}, 1))
	if err == nil || !strings.Contains(err.Error(), "previous runtime restored") {
		t.Fatalf("expected a restored-runtime error, got %v", err)
	}
	if old.core == nil || old.core == oldCore {
		t.Fatal("previous runtime core was not restored in place")
	}
}
