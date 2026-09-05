package node

import (
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/Duyvj/v3node/conf"
)

func withTemporaryTrafficSpool(t *testing.T) string {
	t.Helper()
	previous := trafficSpoolDirectory
	trafficSpoolDirectory = filepath.Join(t.TempDir(), "traffic")
	t.Cleanup(func() { trafficSpoolDirectory = previous })
	return trafficSpoolDirectory
}

func TestTrafficSpoolRoundTripPreservesImmutablePendingBatch(t *testing.T) {
	withTemporaryTrafficSpool(t)
	first := &Controller{
		conf:                   &conf.NodeConfig{APIHost: "https://panel.example", NodeID: 42},
		pendingTrafficReportID: "0123456789abcdef0123456789abcdef",
		pendingTraffic:         []panel.UserTraffic{{UID: 7, Upload: 100, Download: 200}},
		queuedTraffic:          []panel.UserTraffic{{UID: 8, Upload: 300, Download: 400}},
	}
	if err := first.persistTrafficSpoolLocked(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(first.trafficSpoolPath())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("traffic spool mode = %o, want 600", got)
		}
	}

	restored := &Controller{conf: &conf.NodeConfig{APIHost: "https://panel.example", NodeID: 42}}
	if err := restored.restoreTrafficSpool(); err != nil {
		t.Fatal(err)
	}
	if restored.pendingTrafficReportID != first.pendingTrafficReportID {
		t.Fatalf("report ID changed across restart: %q", restored.pendingTrafficReportID)
	}
	if !reflect.DeepEqual(restored.pendingTraffic, first.pendingTraffic) {
		t.Fatalf("pending batch changed across restart: %#v", restored.pendingTraffic)
	}
	if !reflect.DeepEqual(restored.queuedTraffic, first.queuedTraffic) {
		t.Fatalf("queued batch changed across restart: %#v", restored.queuedTraffic)
	}
}

func TestTrafficSpoolRejectsCorruptionAndUnknownFields(t *testing.T) {
	directory := withTemporaryTrafficSpool(t)
	controller := &Controller{conf: &conf.NodeConfig{APIHost: "https://panel.example", NodeID: 7}}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	bad := `{"version":1,"pending_report_id":"0123456789abcdef0123456789abcdef","pending":[{"uid":1,"upload":1,"download":2}],"secret":"unexpected"}`
	if err := os.WriteFile(controller.trafficSpoolPath(), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := controller.restoreTrafficSpool(); err == nil {
		t.Fatal("corrupt traffic spool was accepted")
	}
}

func TestTrafficSpoolDirectoryCannotBeASymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	previous := trafficSpoolDirectory
	trafficSpoolDirectory = filepath.Join(root, "traffic")
	t.Cleanup(func() { trafficSpoolDirectory = previous })
	if err := os.Symlink(target, trafficSpoolDirectory); err != nil {
		t.Fatal(err)
	}
	controller := &Controller{
		conf:                   &conf.NodeConfig{APIHost: "https://panel.example", NodeID: 8},
		pendingTrafficReportID: "0123456789abcdef0123456789abcdef",
		pendingTraffic:         []panel.UserTraffic{{UID: 1, Upload: 1}},
	}
	if err := controller.persistTrafficSpoolLocked(); err == nil {
		t.Fatal("symlinked traffic spool directory was accepted")
	}
}

func TestMergeTrafficBatchesIsDeterministicAndRejectsOverflow(t *testing.T) {
	merged, err := mergeTrafficBatches(
		[]panel.UserTraffic{{UID: 9, Upload: 2, Download: 3}},
		[]panel.UserTraffic{{UID: 2, Upload: 5}, {UID: 9, Upload: 7, Download: 11}},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []panel.UserTraffic{{UID: 2, Upload: 5}, {UID: 9, Upload: 9, Download: 14}}
	if !reflect.DeepEqual(merged, want) {
		t.Fatalf("unexpected merged batch: %#v", merged)
	}
	if _, err := mergeTrafficBatches(
		[]panel.UserTraffic{{UID: 1, Upload: math.MaxInt64}},
		[]panel.UserTraffic{{UID: 1, Upload: 1}},
	); err == nil {
		t.Fatal("traffic counter overflow was accepted")
	}
}

func TestEmptyTrafficSpoolRemovesAcknowledgedBatch(t *testing.T) {
	withTemporaryTrafficSpool(t)
	controller := &Controller{
		conf:                   &conf.NodeConfig{APIHost: "https://panel.example", NodeID: 9},
		pendingTrafficReportID: "0123456789abcdef0123456789abcdef",
		pendingTraffic:         []panel.UserTraffic{{UID: 1, Upload: 1}},
	}
	if err := controller.persistTrafficSpoolLocked(); err != nil {
		t.Fatal(err)
	}
	controller.pendingTrafficReportID = ""
	controller.pendingTraffic = nil
	if err := controller.persistTrafficSpoolLocked(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(controller.trafficSpoolPath()); !os.IsNotExist(err) {
		t.Fatalf("acknowledged traffic spool still exists: %v", err)
	}
}

func TestQueuedTrafficIsSplitIntoBoundedImmutableReports(t *testing.T) {
	controller := &Controller{queuedTraffic: make([]panel.UserTraffic, maxTrafficReportUsers+1)}
	for i := range controller.queuedTraffic {
		controller.queuedTraffic[i] = panel.UserTraffic{UID: i + 1, Upload: 1}
	}
	if err := controller.promoteQueuedTrafficLocked(); err != nil {
		t.Fatal(err)
	}
	if len(controller.pendingTraffic) != maxTrafficReportUsers {
		t.Fatalf("pending report has %d users", len(controller.pendingTraffic))
	}
	if len(controller.queuedTraffic) != 1 || controller.queuedTraffic[0].UID != maxTrafficReportUsers+1 {
		t.Fatalf("unexpected queued remainder: %#v", controller.queuedTraffic)
	}
	if !validTrafficReportID(controller.pendingTrafficReportID) {
		t.Fatalf("invalid generated report ID %q", controller.pendingTrafficReportID)
	}
}

func TestQueuedTrafficIsAlsoSplitByByteLimit(t *testing.T) {
	controller := &Controller{queuedTraffic: []panel.UserTraffic{{
		UID: 7, Upload: maxTrafficReportBytes + 5, Download: 11,
	}}}
	if err := controller.promoteQueuedTrafficLocked(); err != nil {
		t.Fatal(err)
	}
	if len(controller.pendingTraffic) != 1 ||
		controller.pendingTraffic[0].Upload != maxTrafficReportBytes ||
		controller.pendingTraffic[0].Download != 0 {
		t.Fatalf("unexpected byte-bounded pending report: %#v", controller.pendingTraffic)
	}
	if len(controller.queuedTraffic) != 1 ||
		controller.queuedTraffic[0].Upload != 5 ||
		controller.queuedTraffic[0].Download != 11 {
		t.Fatalf("unexpected byte-bounded remainder: %#v", controller.queuedTraffic)
	}
}

func TestAcknowledgedTrafficKeepsDurableStateWhenSpoolAdvanceFails(t *testing.T) {
	withTemporaryTrafficSpool(t)
	pending := []panel.UserTraffic{{UID: 7, Upload: 10, Download: 20}}
	queued := []panel.UserTraffic{{UID: 8, Upload: 30, Download: 40}}
	controller := &Controller{
		conf:                   &conf.NodeConfig{APIHost: "https://panel.example", NodeID: 10},
		pendingTrafficReportID: "0123456789abcdef0123456789abcdef",
		pendingTraffic:         append([]panel.UserTraffic(nil), pending...),
		queuedTraffic:          append([]panel.UserTraffic(nil), queued...),
	}
	if err := controller.persistTrafficSpoolLocked(); err != nil {
		t.Fatal(err)
	}

	// Simulate a disk/path failure after the panel has acknowledged the current
	// report but before the next immutable report ID can be committed.
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}
	trafficSpoolDirectory = blocked

	if err := controller.advanceAcknowledgedTrafficLocked(); err == nil {
		t.Fatal("spool advance unexpectedly succeeded through a non-directory")
	}
	if !reflect.DeepEqual(controller.pendingTraffic, pending) ||
		controller.pendingTrafficReportID != "0123456789abcdef0123456789abcdef" ||
		!reflect.DeepEqual(controller.queuedTraffic, queued) {
		t.Fatalf("durable pre-ACK state changed: pending=%#v id=%q queued=%#v",
			controller.pendingTraffic, controller.pendingTrafficReportID, controller.queuedTraffic)
	}
}
