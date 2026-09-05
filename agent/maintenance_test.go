package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	panel "github.com/Duyvj/v3node/api/v2board"
)

type maintenanceReport struct {
	status string
}

type fakeMaintenanceReporter struct {
	reports []maintenanceReport
}

func (f *fakeMaintenanceReporter) ReportMaintenance(_ context.Context, _, status, _ string) error {
	f.reports = append(f.reports, maintenanceReport{status: status})
	return nil
}

func TestMaintenanceIsScheduledOnceAndFailsClosedWithoutAResultAfterRestart(t *testing.T) {
	oldPath := statePath
	oldSchedule := scheduleMaintenance
	statePath = filepath.Join(t.TempDir(), "maintenance.json")
	scheduled := 0
	scheduleMaintenance = func(panel.AgentMaintenance) error { scheduled++; return nil }
	defer func() { statePath = oldPath; scheduleMaintenance = oldSchedule }()

	reporter := &fakeMaintenanceReporter{}
	command := &panel.AgentMaintenance{ID: "0123456789abcdef0123456789abcdef", Action: "update_latest"}
	if err := reconcileMaintenance(context.Background(), reporter, command); err != nil {
		t.Fatal(err)
	}
	if scheduled != 1 || len(reporter.reports) != 1 || reporter.reports[0].status != "scheduled" {
		t.Fatalf("unexpected first reconciliation: scheduled=%d reports=%+v", scheduled, reporter.reports)
	}
	if err := reconcileMaintenance(context.Background(), reporter, command); err != nil {
		t.Fatal(err)
	}
	if scheduled != 1 || len(reporter.reports) != 1 {
		t.Fatal("same process must not execute or report the command twice")
	}

	state, err := readMaintenanceState()
	if err != nil {
		t.Fatal(err)
	}
	state.OriginPID = os.Getpid() + 1
	state.UpdatedAt = 1
	if err := writeMaintenanceState(state); err != nil {
		t.Fatal(err)
	}
	if err := reconcileMaintenance(context.Background(), reporter, command); err != nil {
		t.Fatal(err)
	}
	if len(reporter.reports) != 2 || reporter.reports[1].status != "failed" {
		t.Fatalf("missing result must not be reported as successful after restart: %+v", reporter.reports)
	}
}

func TestCorruptMaintenanceStatePreventsDuplicateScheduling(t *testing.T) {
	oldPath := statePath
	oldSchedule := scheduleMaintenance
	statePath = filepath.Join(t.TempDir(), "maintenance.json")
	scheduled := 0
	scheduleMaintenance = func(panel.AgentMaintenance) error { scheduled++; return nil }
	defer func() { statePath = oldPath; scheduleMaintenance = oldSchedule }()
	if err := os.WriteFile(statePath, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}

	reporter := &fakeMaintenanceReporter{}
	command := &panel.AgentMaintenance{ID: "0123456789abcdef0123456789abcdef", Action: "update_latest"}
	if err := reconcileMaintenance(context.Background(), reporter, command); err == nil {
		t.Fatal("corrupt idempotency state was ignored")
	}
	if scheduled != 0 {
		t.Fatal("maintenance was scheduled again without trustworthy state")
	}
}
