package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Duyvj/v3node/internal/config"
	"github.com/Duyvj/v3node/internal/engine"
	"github.com/Duyvj/v3node/internal/model"
	"github.com/Duyvj/v3node/internal/state"
)

type accountingPanel struct {
	reports   [][]model.UserTraffic
	online    []model.OnlineUsers
	onlineErr error
}

type fakeConnectionsAPI struct {
	mu       sync.Mutex
	closed   []string
	closeErr error
}

func (*fakeConnectionsAPI) Snapshot(context.Context) ([]engine.ActiveConnection, error) {
	return nil, nil
}

func (f *fakeConnectionsAPI) Close(_ context.Context, id string) error {
	f.mu.Lock()
	f.closed = append(f.closed, id)
	f.mu.Unlock()
	return f.closeErr
}

func (f *fakeConnectionsAPI) closedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := append([]string(nil), f.closed...)
	sort.Strings(result)
	return result
}

func TestRestoreTrafficAccumulatorQuarantinesInvalidCheckpoint(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "traffic.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"pending":[{"user_id":0,"upload":1}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	accumulator, err := restoreTrafficAccumulator(path, 10, log.New(&output, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if accumulator.Len() != 0 {
		t.Fatalf("new accumulator len = %d", accumulator.Len())
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid checkpoint remains active: %v", err)
	}
	matches, err := filepath.Glob(path + ".corrupt-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("quarantined checkpoints = %v, error %v", matches, err)
	}
	if !strings.Contains(output.String(), "quarantined") {
		t.Fatalf("quarantine was not logged: %q", output.String())
	}
}

type partialPanel struct {
	node     *model.NodeConfig
	nodeErr  error
	users    []model.User
	usersErr error
	alive    model.AliveUsers
	aliveErr error
}

type parallelPanel struct {
	started chan struct{}
	release chan struct{}
}

func (p *parallelPanel) wait() {
	p.started <- struct{}{}
	<-p.release
}

func (p *parallelPanel) GetNodeConfig(context.Context) (*model.NodeConfig, bool, error) {
	p.wait()
	return nil, false, nil
}

func (p *parallelPanel) GetUsers(context.Context) ([]model.User, bool, error) {
	p.wait()
	return nil, false, nil
}

func (p *parallelPanel) GetAlive(context.Context) (model.AliveUsers, error) {
	p.wait()
	return model.AliveUsers{}, nil
}

func (*parallelPanel) ReportTraffic(context.Context, []model.UserTraffic) error { return nil }
func (*parallelPanel) ReportOnline(context.Context, model.OnlineUsers) error    { return nil }

func (p *partialPanel) GetNodeConfig(context.Context) (*model.NodeConfig, bool, error) {
	return p.node, p.node != nil, p.nodeErr
}

func (p *partialPanel) GetUsers(context.Context) ([]model.User, bool, error) {
	return p.users, p.users != nil, p.usersErr
}

func (p *partialPanel) GetAlive(context.Context) (model.AliveUsers, error) {
	return p.alive, p.aliveErr
}

func TestSyncPanelDiscardsStaleAliveCountsAfterFailures(t *testing.T) {
	panel := &partialPanel{aliveErr: errors.New("alive unavailable")}
	controller := &Controller{
		panel:          panel,
		logger:         log.New(io.Discard, "", 0),
		alive:          model.AliveUsers{1: 9},
		aliveReady:     true,
		aliveUpdatedAt: time.Now().Add(-aliveStateMaxAge),
	}
	if _, err := controller.syncPanel(context.Background()); err != nil {
		t.Fatalf("alive-only failure made control-plane sync fail: %v", err)
	}
	if controller.aliveReady || len(controller.alive) != 0 {
		t.Fatalf("stale alive state retained: ready=%v alive=%#v", controller.aliveReady, controller.alive)
	}
}

func (*partialPanel) ReportTraffic(context.Context, []model.UserTraffic) error { return nil }
func (*partialPanel) ReportOnline(context.Context, model.OnlineUsers) error    { return nil }

func TestSyncPanelDoesNotReconcilePartialGeneration(t *testing.T) {
	node := &model.NodeConfig{Protocol: model.ProtocolVLESS, ServerPort: 443}
	usersFailure := errors.New("users unavailable")
	controller := &Controller{
		panel: &partialPanel{
			node:     node,
			usersErr: usersFailure,
		},
		alive: make(model.AliveUsers),
	}
	changed, err := controller.syncPanel(context.Background())
	if changed || !errors.Is(err, usersFailure) {
		t.Fatalf("partial sync = changed %v, error %v", changed, err)
	}
	if controller.desiredNode != node || !controller.desiredDirty {
		t.Fatal("successful node half was not staged for a later complete cycle")
	}
}

func TestSyncPanelFetchesIndependentEndpointsConcurrently(t *testing.T) {
	panel := &parallelPanel{started: make(chan struct{}, 3), release: make(chan struct{})}
	controller := &Controller{panel: panel, alive: make(model.AliveUsers)}
	done := make(chan error, 1)
	go func() {
		_, err := controller.syncPanel(context.Background())
		done <- err
	}()
	for index := 0; index < 3; index++ {
		select {
		case <-panel.started:
		case <-time.After(time.Second):
			t.Fatal("panel endpoints were fetched sequentially")
		}
	}
	close(panel.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("parallel panel synchronization did not finish")
	}
}

func TestPolicyOnlyUpdatePreservesUnchangedOnlineUsers(t *testing.T) {
	tracker, err := state.NewOnlineTracker(time.Minute, 10, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Observe(1, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Observe(2, "192.0.2.2"); err != nil {
		t.Fatal(err)
	}
	controller := &Controller{
		haveActive: true,
		online:     tracker,
		lastOnlineReport: map[int]map[netip.Addr]struct{}{
			1: {netip.MustParseAddr("192.0.2.1"): {}},
			2: {netip.MustParseAddr("192.0.2.2"): {}},
		},
		active: RuntimeState{Policies: map[int]UserPolicy{
			1: {DeviceLimit: 2},
			2: {DeviceLimit: 2},
		}},
	}
	next := RuntimeState{Policies: map[int]UserPolicy{
		1: {DeviceLimit: 2},
		2: {DeviceLimit: 1},
	}}
	if !controller.resetOnlinePolicyState(next, false) {
		t.Fatal("changed device policy did not request a connection reseed")
	}
	if !tracker.Has(1, "192.0.2.1") {
		t.Fatal("unchanged user's online state was cleared")
	}
	if tracker.Has(2, "192.0.2.2") {
		t.Fatal("changed user's online state was retained")
	}
	if len(controller.lastOnlineReport[1]) != 1 || controller.lastOnlineReport[2] != nil {
		t.Fatalf("report overlap was not reconciled with policy changes: %#v", controller.lastOnlineReport)
	}
}

func TestEngineReplacementClearsAllOnlineReportOverlap(t *testing.T) {
	tracker, err := state.NewOnlineTracker(time.Minute, 10, 5)
	if err != nil {
		t.Fatal(err)
	}
	controller := &Controller{
		haveActive: true,
		online:     tracker,
		lastOnlineReport: map[int]map[netip.Addr]struct{}{
			99: {netip.MustParseAddr("192.0.2.99"): {}},
		},
		lastOnlineReportAt: time.Now(),
		active:             RuntimeState{EngineUsers: map[string]int{"uid-1": 1}},
	}
	if !controller.resetOnlinePolicyState(RuntimeState{}, true) {
		t.Fatal("engine replacement did not request a reseed")
	}
	if len(controller.lastOnlineReport) != 0 || !controller.lastOnlineReportAt.IsZero() {
		t.Fatalf("engine replacement retained report overlap: %#v at %v", controller.lastOnlineReport, controller.lastOnlineReportAt)
	}
}

func (*accountingPanel) GetNodeConfig(context.Context) (*model.NodeConfig, bool, error) {
	return nil, false, nil
}

func (*accountingPanel) GetUsers(context.Context) ([]model.User, bool, error) {
	return nil, false, nil
}

func (*accountingPanel) GetAlive(context.Context) (model.AliveUsers, error) {
	return nil, nil
}

func (p *accountingPanel) ReportTraffic(_ context.Context, traffic []model.UserTraffic) error {
	p.reports = append(p.reports, append([]model.UserTraffic(nil), traffic...))
	return nil
}

func (p *accountingPanel) ReportOnline(_ context.Context, online model.OnlineUsers) error {
	clone := make(model.OnlineUsers, len(online))
	for userID, addresses := range online {
		clone[userID] = append([]string(nil), addresses...)
	}
	p.online = append(p.online, clone)
	return p.onlineErr
}

func TestForceTrafficReportDrainsInflightAndPendingGenerations(t *testing.T) {
	accumulator, err := state.NewTrafficAccumulator(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := accumulator.Add(1, 10, 20); err != nil {
		t.Fatal(err)
	}
	first := accumulator.Snapshot()
	if first.Empty() {
		t.Fatal("failed to create in-flight traffic batch")
	}
	if err := accumulator.Add(2, 30, 40); err != nil {
		t.Fatal(err)
	}
	panel := new(accountingPanel)
	controller := &Controller{
		panel:   panel,
		traffic: accumulator,
		active:  RuntimeState{NodeReportMinBytes: 1 << 30},
	}
	if err := controller.reportTraffic(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if len(panel.reports) != 2 {
		t.Fatalf("traffic reports = %d, want 2", len(panel.reports))
	}
	if len(panel.reports[0]) != 1 || panel.reports[0][0].UserID != 1 ||
		len(panel.reports[1]) != 1 || panel.reports[1][0].UserID != 2 {
		t.Fatalf("unexpected force-flush payloads: %#v", panel.reports)
	}
	if accumulator.Len() != 0 || accumulator.HasInFlight() {
		t.Fatalf("force flush retained traffic: len=%d inFlight=%v", accumulator.Len(), accumulator.HasInFlight())
	}
	if controller.lastTrafficFlush.IsZero() {
		t.Fatal("force flush time was not recorded")
	}
}

func TestTrafficForceFlushSchedule(t *testing.T) {
	controller := new(Controller)
	now := time.Unix(1_700_000_000, 0)
	if !controller.trafficForceDue(now) {
		t.Fatal("initial force flush is not due")
	}
	controller.lastTrafficFlush = now
	if controller.trafficForceDue(now.Add(trafficForceFlushInterval - time.Nanosecond)) {
		t.Fatal("force flush became due before the retention interval")
	}
	if !controller.trafficForceDue(now.Add(trafficForceFlushInterval)) {
		t.Fatal("force flush is not due at the retention interval")
	}
}

func TestSetDesiredUsersClearsRemovedCredentialBacking(t *testing.T) {
	old := []model.User{
		{ID: 1, UUID: "credential-one"},
		{ID: 2, UUID: "credential-two"},
		{ID: 3, UUID: "credential-three"},
	}
	// Expose only the first entry to reproduce a prior shorter reslice while
	// credentials remain in the backing-array tail.
	controller := &Controller{desiredUsers: old[:1]}
	controller.setDesiredUsers([]model.User{{ID: 4, UUID: "credential-four"}})
	for index, user := range old {
		if user != (model.User{}) {
			t.Fatalf("old credential backing entry %d was retained: %#v", index, user)
		}
	}
	if len(controller.desiredUsers) != 1 || controller.desiredUsers[0].UUID != "credential-four" {
		t.Fatalf("replacement users = %#v", controller.desiredUsers)
	}
}

func TestProcessConnectionsEnforcesBeforeThresholdAndAggregatesByDevice(t *testing.T) {
	tracker, err := state.NewOnlineTracker(time.Minute, 16, 4)
	if err != nil {
		t.Fatal(err)
	}
	connections := new(fakeConnectionsAPI)
	cfg := config.Defaults()
	cfg.Runtime.HTTPTimeout.Duration = time.Second
	controller := &Controller{
		cfg:         cfg,
		connections: connections,
		online:      tracker,
		alive:       make(model.AliveUsers),
		active: RuntimeState{
			Backend:              "sing-box",
			EngineUsers:          map[string]int{"uid-1": 1},
			Policies:             map[int]UserPolicy{1: {DeviceLimit: 1}},
			DeviceOnlineMinBytes: 100,
			PullIntervalNanos:    int64(30 * time.Second),
			PushIntervalNanos:    int64(30 * time.Second),
		},
		haveActive: true,
	}
	start := time.Unix(1_700_000_000, 0)
	first := netip.MustParseAddr("192.0.2.1")
	second := netip.MustParseAddr("192.0.2.2")
	snapshot := []engine.ActiveConnection{
		{ID: "accepted-a", User: "uid-1", SourceIP: first, Upload: 40, StartedAt: start},
		{ID: "accepted-b", User: "uid-1", SourceIP: first, Download: 40, StartedAt: start.Add(time.Second)},
		{ID: "rejected-a", User: "uid-1", SourceIP: second, Upload: 1_000, StartedAt: start.Add(2 * time.Second)},
		{ID: "rejected-b", User: "uid-1", SourceIP: second, StartedAt: start.Add(3 * time.Second)},
	}
	if err := controller.processConnections(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if got := connections.closedIDs(); len(got) != 2 || got[0] != "rejected-a" || got[1] != "rejected-b" {
		t.Fatalf("closed connection IDs = %#v", got)
	}
	if !tracker.Has(1, first.String()) || tracker.Has(1, second.String()) {
		t.Fatalf("unexpected enforcement state: %#v", tracker.SnapshotMap())
	}
	if got := tracker.SnapshotReportableMap(); len(got) != 0 {
		t.Fatalf("sub-threshold accepted device was reported: %#v", got)
	}

	// The threshold is evaluated over all connections from the same user/IP,
	// so neither individual connection needs to cross it alone.
	next := []engine.ActiveConnection{
		{ID: "accepted-c", User: "uid-1", SourceIP: first, Upload: 50, StartedAt: start},
		{ID: "accepted-d", User: "uid-1", SourceIP: first, Download: 50, StartedAt: start.Add(time.Second)},
	}
	if err := controller.processConnections(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	reported := tracker.SnapshotReportableMap()
	if len(reported[1]) != 1 || reported[1][0] != first.String() {
		t.Fatalf("aggregated device was not reported: %#v", reported)
	}
}

func TestProcessConnectionsAdvancesPanelAliveBaseline(t *testing.T) {
	tracker, err := state.NewOnlineTracker(time.Minute, 16, 4)
	if err != nil {
		t.Fatal(err)
	}
	connections := new(fakeConnectionsAPI)
	cfg := config.Defaults()
	cfg.Runtime.HTTPTimeout.Duration = time.Second
	controller := &Controller{
		cfg:               cfg,
		connections:       connections,
		online:            tracker,
		alive:             model.AliveUsers{1: 2},
		aliveReady:        true,
		connectionsSeeded: true,
		active: RuntimeState{
			Backend:     "sing-box",
			EngineUsers: map[string]int{"uid-1": 1},
			Policies:    map[int]UserPolicy{1: {DeviceLimit: 3}},
		},
		haveActive: true,
	}
	start := time.Unix(1_700_000_000, 0)
	accepted := netip.MustParseAddr("192.0.2.40")
	rejected := netip.MustParseAddr("192.0.2.41")
	snapshot := []engine.ActiveConnection{
		{ID: "accepted", User: "uid-1", SourceIP: accepted, StartedAt: start},
		{ID: "rejected", User: "uid-1", SourceIP: rejected, StartedAt: start.Add(time.Second)},
	}
	if err := controller.processConnections(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if !tracker.Has(1, accepted.String()) || tracker.Has(1, rejected.String()) {
		t.Fatalf("panel baseline was not enforced: %#v", tracker.SnapshotMap())
	}
	closed := connections.closedIDs()
	if len(closed) != 1 || closed[0] != "rejected" {
		t.Fatalf("closed connections = %#v", closed)
	}
}

func TestProcessConnectionsRejectsEveryNewIPWhenPanelBaselineIsFull(t *testing.T) {
	tracker, err := state.NewOnlineTracker(time.Minute, 16, 4)
	if err != nil {
		t.Fatal(err)
	}
	connections := new(fakeConnectionsAPI)
	cfg := config.Defaults()
	cfg.Runtime.HTTPTimeout.Duration = time.Second
	controller := &Controller{
		cfg:               cfg,
		connections:       connections,
		online:            tracker,
		alive:             model.AliveUsers{1: 1},
		aliveReady:        true,
		connectionsSeeded: true,
		active: RuntimeState{
			Backend:     "sing-box",
			EngineUsers: map[string]int{"uid-1": 1},
			Policies:    map[int]UserPolicy{1: {DeviceLimit: 1}},
		},
		haveActive: true,
	}
	start := time.Unix(1_700_000_000, 0)
	err = controller.processConnections(context.Background(), []engine.ActiveConnection{
		{ID: "new-a", User: "uid-1", SourceIP: netip.MustParseAddr("192.0.2.100"), StartedAt: start},
		{ID: "new-b", User: "uid-1", SourceIP: netip.MustParseAddr("192.0.2.101"), StartedAt: start.Add(time.Second)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tracker.Len() != 0 {
		t.Fatalf("new IP retained despite full panel baseline: %#v", tracker.SnapshotMap())
	}
	if got := connections.closedIDs(); len(got) != 2 || got[0] != "new-a" || got[1] != "new-b" {
		t.Fatalf("closed connections = %#v", got)
	}
}

func TestFailedOnlineReportIsNotSubtractedFromAliveBaseline(t *testing.T) {
	tracker, err := state.NewOnlineTracker(time.Minute, 16, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Observe(1, "192.0.2.110"); err != nil {
		t.Fatal(err)
	}
	panel := &accountingPanel{onlineErr: errors.New("report failed")}
	controller := &Controller{
		panel:            panel,
		online:           tracker,
		lastOnlineReport: make(map[int]map[netip.Addr]struct{}),
	}
	if err := controller.reportOnline(context.Background()); !errors.Is(err, panel.onlineErr) {
		t.Fatalf("reportOnline error = %v", err)
	}
	if len(controller.lastOnlineReport) != 0 {
		t.Fatalf("failed payload was remembered: %#v", controller.lastOnlineReport)
	}

	connections := new(fakeConnectionsAPI)
	cfg := config.Defaults()
	cfg.Runtime.HTTPTimeout.Duration = time.Second
	controller.cfg = cfg
	controller.connections = connections
	controller.alive = model.AliveUsers{1: 1}
	controller.aliveReady = true
	controller.connectionsSeeded = true
	controller.active = RuntimeState{
		Backend:     "sing-box",
		EngineUsers: map[string]int{"uid-1": 1},
		Policies:    map[int]UserPolicy{1: {DeviceLimit: 1}},
	}
	if err := controller.processConnections(context.Background(), []engine.ActiveConnection{{
		ID: "new", User: "uid-1", SourceIP: netip.MustParseAddr("192.0.2.111"), StartedAt: time.Now(),
	}}); err != nil {
		t.Fatal(err)
	}
	if tracker.Has(1, "192.0.2.111") || len(connections.closedIDs()) != 1 {
		t.Fatalf("failed report was subtracted from panel baseline: state=%#v closed=%#v", tracker.SnapshotMap(), connections.closedIDs())
	}
}

func TestProcessConnectionsDoesNotDoubleCountLocalPanelOverlap(t *testing.T) {
	tracker, err := state.NewOnlineTracker(time.Minute, 16, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Observe(1, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	connections := new(fakeConnectionsAPI)
	cfg := config.Defaults()
	cfg.Runtime.HTTPTimeout.Duration = time.Second
	controller := &Controller{
		cfg:         cfg,
		connections: connections,
		online:      tracker,
		alive:       model.AliveUsers{1: 1},
		aliveReady:  true,
		lastOnlineReport: map[int]map[netip.Addr]struct{}{
			1: {netip.MustParseAddr("192.0.2.50"): {}},
		},
		lastOnlineReportAt: time.Now().Add(-time.Second),
		aliveUpdatedAt:     time.Now(),
		connectionsSeeded:  true,
		active: RuntimeState{
			Backend:     "sing-box",
			EngineUsers: map[string]int{"uid-1": 1},
			Policies:    map[int]UserPolicy{1: {DeviceLimit: 1}},
		},
		haveActive: true,
	}
	replacement := netip.MustParseAddr("192.0.2.51")
	if err := controller.processConnections(context.Background(), []engine.ActiveConnection{{
		ID: "replacement", User: "uid-1", SourceIP: replacement, StartedAt: time.Now(),
	}}); err != nil {
		t.Fatal(err)
	}
	if !tracker.Has(1, replacement.String()) || len(connections.closedIDs()) != 0 {
		t.Fatalf("local panel overlap rejected replacement: state=%#v closed=%#v", tracker.SnapshotMap(), connections.closedIDs())
	}
}

func TestProcessConnectionsCombinesRemotePanelAndLocalDevices(t *testing.T) {
	tracker, err := state.NewOnlineTracker(time.Minute, 16, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Observe(1, "192.0.2.60"); err != nil {
		t.Fatal(err)
	}
	connections := new(fakeConnectionsAPI)
	cfg := config.Defaults()
	cfg.Runtime.HTTPTimeout.Duration = time.Second
	controller := &Controller{
		cfg:         cfg,
		connections: connections,
		online:      tracker,
		alive:       model.AliveUsers{1: 2}, // one local report + one remote IP
		aliveReady:  true,
		lastOnlineReport: map[int]map[netip.Addr]struct{}{
			1: {netip.MustParseAddr("192.0.2.60"): {}},
		},
		lastOnlineReportAt: time.Now().Add(-time.Second),
		aliveUpdatedAt:     time.Now(),
		connectionsSeeded:  true,
		active: RuntimeState{
			Backend:     "sing-box",
			EngineUsers: map[string]int{"uid-1": 1},
			Policies:    map[int]UserPolicy{1: {DeviceLimit: 2}},
		},
		haveActive: true,
	}
	newDevice := netip.MustParseAddr("192.0.2.61")
	if err := controller.processConnections(context.Background(), []engine.ActiveConnection{
		{ID: "existing-local", User: "uid-1", SourceIP: netip.MustParseAddr("192.0.2.60"), StartedAt: time.Now().Add(-time.Second)},
		{ID: "over-limit", User: "uid-1", SourceIP: newDevice, StartedAt: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}
	if tracker.Has(1, newDevice.String()) {
		t.Fatal("new device was admitted despite one active remote panel device")
	}
	if got := connections.closedIDs(); len(got) != 1 || got[0] != "over-limit" {
		t.Fatalf("closed connections = %#v", got)
	}
}

func TestProcessConnectionsDoesNotSubtractReportNewerThanAliveSnapshot(t *testing.T) {
	tracker, err := state.NewOnlineTracker(time.Minute, 16, 4)
	if err != nil {
		t.Fatal(err)
	}
	connections := new(fakeConnectionsAPI)
	cfg := config.Defaults()
	cfg.Runtime.HTTPTimeout.Duration = time.Second
	controller := &Controller{
		cfg:            cfg,
		connections:    connections,
		online:         tracker,
		alive:          model.AliveUsers{1: 1},
		aliveReady:     true,
		aliveUpdatedAt: time.Now().Add(-time.Minute),
		lastOnlineReport: map[int]map[netip.Addr]struct{}{
			1: {netip.MustParseAddr("192.0.2.120"): {}},
		},
		lastOnlineReportAt: time.Now(),
		connectionsSeeded:  true,
		active: RuntimeState{
			Backend:     "sing-box",
			EngineUsers: map[string]int{"uid-1": 1},
			Policies:    map[int]UserPolicy{1: {DeviceLimit: 1}},
		},
		haveActive: true,
	}
	if err := controller.processConnections(context.Background(), []engine.ActiveConnection{{
		ID: "new", User: "uid-1", SourceIP: netip.MustParseAddr("192.0.2.121"), StartedAt: time.Now(),
	}}); err != nil {
		t.Fatal(err)
	}
	if tracker.Has(1, "192.0.2.121") || len(connections.closedIDs()) != 1 {
		t.Fatalf("newer report was subtracted from older alive snapshot: state=%#v closed=%#v", tracker.SnapshotMap(), connections.closedIDs())
	}
}

func TestProcessConnectionsRollsBackNewSlotWhenRejectCloseFails(t *testing.T) {
	tracker, err := state.NewOnlineTracker(time.Minute, 16, 4)
	if err != nil {
		t.Fatal(err)
	}
	connections := &fakeConnectionsAPI{closeErr: errors.New("close failed")}
	cfg := config.Defaults()
	cfg.Runtime.HTTPTimeout.Duration = time.Second
	controller := &Controller{
		cfg:               cfg,
		connections:       connections,
		online:            tracker,
		alive:             model.AliveUsers{1: 1},
		aliveReady:        true,
		connectionsSeeded: true,
		active: RuntimeState{
			Backend:     "sing-box",
			EngineUsers: map[string]int{"uid-1": 1},
			Policies:    map[int]UserPolicy{1: {DeviceLimit: 2}},
		},
		haveActive: true,
	}
	older := netip.MustParseAddr("192.0.2.70")
	newer := netip.MustParseAddr("192.0.2.71")
	err = controller.processConnections(context.Background(), []engine.ActiveConnection{
		{ID: "admitted", User: "uid-1", SourceIP: older, StartedAt: time.Now().Add(-time.Second)},
		{ID: "rejected", User: "uid-1", SourceIP: newer, StartedAt: time.Now()},
	})
	if err == nil {
		t.Fatal("close failure was not returned")
	}
	if tracker.Has(1, older.String()) || tracker.Has(1, newer.String()) {
		t.Fatalf("new policy slot survived close failure: %#v", tracker.SnapshotMap())
	}
}

func TestProcessConnectionsFreesDisconnectedDeviceSlotImmediately(t *testing.T) {
	tracker, err := state.NewOnlineTracker(time.Hour, 16, 4)
	if err != nil {
		t.Fatal(err)
	}
	connections := new(fakeConnectionsAPI)
	cfg := config.Defaults()
	cfg.Runtime.HTTPTimeout.Duration = time.Second
	controller := &Controller{
		cfg:               cfg,
		connections:       connections,
		online:            tracker,
		alive:             make(model.AliveUsers),
		connectionsSeeded: true,
		active: RuntimeState{
			Backend:     "sing-box",
			EngineUsers: map[string]int{"uid-1": 1},
			Policies:    map[int]UserPolicy{1: {DeviceLimit: 1}},
		},
		haveActive: true,
	}
	if err := tracker.Reserve(1, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}

	newDevice := netip.MustParseAddr("192.0.2.11")
	snapshot := []engine.ActiveConnection{{ID: "replacement", User: "uid-1", SourceIP: newDevice, StartedAt: time.Now()}}
	if err := controller.processConnections(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if tracker.Has(1, "192.0.2.10") || !tracker.Has(1, newDevice.String()) {
		t.Fatalf("disconnected slot was not replaced: %#v", tracker.SnapshotMap())
	}
	if got := connections.closedIDs(); len(got) != 0 {
		t.Fatalf("replacement device was rejected: %#v", got)
	}
}

func TestProcessConnectionsSortsOnlyLimitedUsersAfterSeed(t *testing.T) {
	tracker, err := state.NewOnlineTracker(time.Minute, 16, 4)
	if err != nil {
		t.Fatal(err)
	}
	connections := new(fakeConnectionsAPI)
	cfg := config.Defaults()
	cfg.Runtime.HTTPTimeout.Duration = time.Second
	controller := &Controller{
		cfg:               cfg,
		connections:       connections,
		online:            tracker,
		alive:             make(model.AliveUsers),
		connectionsSeeded: true,
		active: RuntimeState{
			Backend:     "sing-box",
			EngineUsers: map[string]int{"uid-1": 1, "uid-2": 2},
			Policies:    map[int]UserPolicy{1: {DeviceLimit: 1}},
		},
		haveActive: true,
	}
	start := time.Unix(1_700_000_000, 0)
	older := netip.MustParseAddr("192.0.2.10")
	newer := netip.MustParseAddr("192.0.2.20")
	snapshot := []engine.ActiveConnection{
		{ID: "newer-limited", User: "uid-1", SourceIP: newer, Upload: 1, StartedAt: start.Add(time.Second)},
		{ID: "unlimited", User: "uid-2", SourceIP: netip.MustParseAddr("192.0.2.30"), Upload: 1, StartedAt: start.Add(2 * time.Second)},
		{ID: "older-limited", User: "uid-1", SourceIP: older, Upload: 1, StartedAt: start},
	}
	if err := controller.processConnections(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if !tracker.Has(1, older.String()) || tracker.Has(1, newer.String()) {
		t.Fatalf("limited user did not retain oldest IP: %#v", tracker.SnapshotMap())
	}
	if !tracker.Has(2, "192.0.2.30") {
		t.Fatalf("unlimited user was not processed: %#v", tracker.SnapshotMap())
	}
	closed := connections.closedIDs()
	if len(closed) != 1 || closed[0] != "newer-limited" {
		t.Fatalf("closed connections = %#v", closed)
	}
}
