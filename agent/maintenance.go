package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	panel "github.com/Duyvj/v3node/api/v2board"
)

const maintenanceStatePath = "/var/lib/znode/maintenance.json"

type maintenanceReporter interface {
	ReportMaintenance(context.Context, string, string, string) error
}

type maintenanceState struct {
	ID        string `json:"id"`
	Action    string `json:"action"`
	Status    string `json:"status"`
	OriginPID int    `json:"origin_pid"`
	UpdatedAt int64  `json:"updated_at"`
}

var scheduleMaintenance = scheduleMaintenanceCommand
var statePath = maintenanceStatePath
var maintenanceMu sync.Mutex

const maxMaintenanceStateBytes int64 = 64 << 10

func validMaintenanceID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func reconcileMaintenance(ctx context.Context, reporter maintenanceReporter, command *panel.AgentMaintenance) error {
	if reporter == nil || command == nil {
		return nil
	}
	if !validMaintenanceID(command.ID) {
		return fmt.Errorf("invalid maintenance command ID")
	}
	if command.Action != "update_latest" && command.Action != "rollback" {
		return fmt.Errorf("invalid maintenance action")
	}
	maintenanceMu.Lock()
	defer maintenanceMu.Unlock()
	state, stateErr := readMaintenanceState()
	if stateErr != nil && !os.IsNotExist(stateErr) {
		return fmt.Errorf("read maintenance state: %w", stateErr)
	}
	if state.ID == command.ID {
		if result, err := readMaintenanceResult(command.ID); err == nil {
			status := "completed"
			message := "VPS completed the maintenance command."
			if string(result) != "0\n" {
				status = "failed"
				message = "The VPS maintenance command returned a non-zero exit status. Check /var/log/znode-maintenance.log."
			}
			if err := reporter.ReportMaintenance(ctx, command.ID, status, message); err != nil {
				return err
			}
			state.Status = status
			state.OriginPID = os.Getpid()
			state.UpdatedAt = time.Now().Unix()
			_ = os.Remove(maintenanceResultPath(command.ID))
			return writeMaintenanceState(state)
		}
		if (state.Status == "scheduled" || state.Status == "preparing") && state.OriginPID != os.Getpid() {
			// The update helper restarts znode before it has finished its final
			// checks and written the result file. Give that detached helper time
			// to report the real exit status instead of declaring success as soon
			// as the new Agent process starts.
			if time.Since(time.Unix(state.UpdatedAt, 0)) < 2*time.Minute {
				return nil
			}
			if err := reporter.ReportMaintenance(ctx, command.ID, "failed", "The Agent restarted but no authenticated maintenance result was recorded. Verify the VPS before retrying with a new command ID."); err != nil {
				return err
			}
			state.Status = "failed"
			state.OriginPID = os.Getpid()
			state.UpdatedAt = time.Now().Unix()
			return writeMaintenanceState(state)
		}
		return nil
	}

	state = maintenanceState{ID: command.ID, Action: command.Action, Status: "preparing", OriginPID: os.Getpid(), UpdatedAt: time.Now().Unix()}
	if err := writeMaintenanceState(state); err != nil {
		_ = reporter.ReportMaintenance(ctx, command.ID, "failed", err.Error())
		return err
	}
	if err := scheduleMaintenance(*command); err != nil {
		state.Status = "failed"
		state.UpdatedAt = time.Now().Unix()
		_ = writeMaintenanceState(state)
		_ = reporter.ReportMaintenance(ctx, command.ID, "failed", err.Error())
		return err
	}
	state.Status = "scheduled"
	state.UpdatedAt = time.Now().Unix()
	if err := writeMaintenanceState(state); err != nil {
		_ = reporter.ReportMaintenance(ctx, command.ID, "failed", "Maintenance was launched but its durable state could not be committed; inspect the VPS before retrying.")
		return err
	}
	return reporter.ReportMaintenance(ctx, command.ID, "scheduled", "VPS accepted the maintenance command and will restart ZNode.")
}

func scheduleMaintenanceCommand(command panel.AgentMaintenance) error {
	if !validMaintenanceID(command.ID) {
		return fmt.Errorf("invalid maintenance command ID")
	}
	var action string
	switch command.Action {
	case "update_latest":
		action = "update"
	case "rollback":
		action = "rollback"
	default:
		return fmt.Errorf("invalid maintenance action")
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("automatic maintenance is only supported on Linux")
	}
	resultPath := maintenanceResultPath(command.ID)
	commandLine := "sleep 2; /usr/bin/znode " + action + " >>/var/log/znode-maintenance.log 2>&1; code=$?; (set -C; printf '%s\\n' \"$code\" > " + resultPath + "); exit $code"
	if _, err := os.Stat("/usr/bin/systemd-run"); err == nil {
		unit := "znode-maintenance-" + command.ID[:12]
		cmd := exec.Command("/usr/bin/systemd-run", "--unit="+unit, "--collect", "--property=Type=oneshot", "/bin/sh", "-c", commandLine)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("schedule systemd maintenance: %w: %s", err, string(output))
		}
		return nil
	}
	nohupPath := "/usr/bin/nohup"
	if _, err := os.Stat(nohupPath); err != nil {
		nohupPath = "/bin/nohup"
		if _, fallbackErr := os.Stat(nohupPath); fallbackErr != nil {
			return fmt.Errorf("schedule maintenance: trusted nohup binary is unavailable")
		}
	}
	cmd := exec.Command(nohupPath, "/bin/sh", "-c", commandLine)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("schedule maintenance: %w", err)
	}
	return cmd.Process.Release()
}

func maintenanceResultPath(commandID string) string {
	return "/var/lib/znode/maintenance-result-" + commandID
}

func readMaintenanceResult(commandID string) ([]byte, error) {
	if !validMaintenanceID(commandID) {
		return nil, fmt.Errorf("invalid maintenance command ID")
	}
	path := maintenanceResultPath(commandID)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 32 {
		return nil, fmt.Errorf("maintenance result is not a regular bounded file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || openedInfo.Size() < 1 || openedInfo.Size() > 32 {
		return nil, fmt.Errorf("maintenance result changed during inspection")
	}
	result, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil {
		return nil, err
	}
	if len(result) > 32 {
		return nil, fmt.Errorf("maintenance result exceeds the size limit")
	}
	return result, nil
}

func readMaintenanceState() (maintenanceState, error) {
	var state maintenanceState
	info, err := os.Lstat(statePath)
	if os.IsNotExist(err) {
		return state, err
	}
	if err != nil {
		return state, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxMaintenanceStateBytes {
		return state, fmt.Errorf("maintenance state is not a regular bounded file")
	}
	file, err := os.Open(statePath)
	if err != nil {
		return state, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || openedInfo.Size() < 0 || openedInfo.Size() > maxMaintenanceStateBytes {
		return state, fmt.Errorf("maintenance state changed during inspection")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxMaintenanceStateBytes+1))
	if err != nil {
		return state, err
	}
	if int64(len(data)) > maxMaintenanceStateBytes {
		return state, fmt.Errorf("maintenance state exceeds the size limit")
	}
	return state, json.Unmarshal(data, &state)
}
func writeMaintenanceState(state maintenanceState) error {
	directory := filepath.Dir(statePath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create maintenance state directory: %w", err)
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("maintenance state directory is not a private directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("protect maintenance state directory: %w", err)
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".maintenance-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, statePath); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}
