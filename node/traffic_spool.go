package node

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	panel "github.com/Duyvj/v3node/api/v2board"
)

const (
	trafficSpoolVersion   = 1
	maxTrafficSpoolBytes  = 64 << 20
	maxTrafficReportUsers = 10000
	maxTrafficQueuedUsers = 400000
	maxTrafficSpoolUsers  = maxTrafficQueuedUsers + maxTrafficReportUsers
	maxTrafficReportBytes = int64(1125899906842624) // 1 PiB
)

// Kept as a variable so package tests can use an isolated directory. The
// production directory is root-owned and is created with mode 0700.
var trafficSpoolDirectory = "/var/lib/znode/traffic"

type trafficSpoolEntry struct {
	UID      int   `json:"uid"`
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
}

type trafficSpoolState struct {
	Version         int                 `json:"version"`
	PendingReportID string              `json:"pending_report_id,omitempty"`
	Pending         []trafficSpoolEntry `json:"pending,omitempty"`
	Queued          []trafficSpoolEntry `json:"queued,omitempty"`
}

func (c *Controller) restoreTrafficSpool() error {
	c.trafficReportMu.Lock()
	defer c.trafficReportMu.Unlock()
	return c.restoreTrafficSpoolLocked()
}

func (c *Controller) restoreTrafficSpoolLocked() error {
	if c.trafficSpoolLoaded {
		return nil
	}

	state, err := readTrafficSpool(c.trafficSpoolPath())
	if err != nil {
		return err
	}
	if state != nil {
		c.pendingTrafficReportID = state.PendingReportID
		c.pendingTraffic = spoolEntriesToTraffic(state.Pending)
		c.queuedTraffic = spoolEntriesToTraffic(state.Queued)
	}
	c.trafficSpoolLoaded = true
	return nil
}

func (c *Controller) persistTrafficSpoolLocked() error {
	state, err := c.trafficSpoolSnapshotLocked()
	if err != nil {
		return err
	}
	return c.writeTrafficSpool(c.trafficSpoolPath(), state)
}

// trafficSpoolSnapshotLocked copies all controller-owned traffic state before
// terminal persistence. The writer receives only this immutable snapshot and
// never owns a controller lock, core lease, or mutable controller state.
func (c *Controller) trafficSpoolSnapshotLocked() (*trafficSpoolState, error) {
	state := &trafficSpoolState{
		Version:         trafficSpoolVersion,
		PendingReportID: c.pendingTrafficReportID,
		Pending:         trafficToSpoolEntries(c.pendingTraffic),
		Queued:          trafficToSpoolEntries(c.queuedTraffic),
	}
	if err := validateTrafficSpoolState(state); err != nil {
		return nil, fmt.Errorf("validate traffic spool: %w", err)
	}
	return state, nil
}

func (c *Controller) writeTrafficSpool(path string, state *trafficSpoolState) error {
	if c.trafficSpoolWriter != nil {
		return c.trafficSpoolWriter(path, state)
	}
	return writeTrafficSpool(path, state)
}

func (c *Controller) trafficSpoolPath() string {
	apiHost := ""
	nodeID := 0
	if c.conf != nil {
		apiHost = strings.TrimRight(strings.TrimSpace(c.conf.APIHost), "/")
		nodeID = c.conf.NodeID
	}
	identity := fmt.Sprintf("%s\n%d", apiHost, nodeID)
	digest := sha256.Sum256([]byte(identity))
	return filepath.Join(trafficSpoolDirectory, hex.EncodeToString(digest[:])+".json")
}

func readTrafficSpool(path string) (*trafficSpoolState, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect traffic spool: %w", err)
	}
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("traffic spool is not a regular file")
	}
	if info.Size() < 0 || info.Size() > maxTrafficSpoolBytes {
		return nil, fmt.Errorf("traffic spool exceeds the size limit")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open traffic spool: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxTrafficSpoolBytes+1))
	decoder.DisallowUnknownFields()
	var state trafficSpoolState
	if err := decoder.Decode(&state); err != nil {
		return nil, fmt.Errorf("decode traffic spool: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("decode traffic spool: trailing JSON value")
		}
		return nil, fmt.Errorf("decode traffic spool: %w", err)
	}
	if err := validateTrafficSpoolState(&state); err != nil {
		return nil, fmt.Errorf("invalid traffic spool: %w", err)
	}
	// Old installations sometimes inherit a permissive umask. Tighten an
	// otherwise valid spool before it is used again.
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("protect traffic spool: %w", err)
	}
	return &state, nil
}

func writeTrafficSpool(path string, state *trafficSpoolState) error {
	if state == nil {
		return fmt.Errorf("traffic spool state is nil")
	}
	if err := validateTrafficSpoolState(state); err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if dirInfo, err := os.Lstat(directory); err == nil && !dirInfo.IsDir() {
		return fmt.Errorf("traffic spool directory is not a real directory")
	}
	if len(state.Pending) == 0 && len(state.Queued) == 0 {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return fmt.Errorf("inspect empty traffic spool: %w", err)
		}
		if err := ensurePrivateDirectory(directory); err != nil {
			return err
		}
		if err := removeTrafficSpool(path); err != nil {
			return err
		}
		return syncDirectory(directory)
	}
	if err := ensurePrivateDirectory(directory); err != nil {
		return err
	}

	temporary, err := os.CreateTemp(directory, ".traffic-*.tmp")
	if err != nil {
		return fmt.Errorf("create traffic spool temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("protect traffic spool temporary file: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(state); err != nil {
		return fmt.Errorf("encode traffic spool: %w", err)
	}
	if info, err := temporary.Stat(); err != nil {
		return fmt.Errorf("inspect traffic spool temporary file: %w", err)
	} else if info.Size() > maxTrafficSpoolBytes {
		return fmt.Errorf("traffic spool exceeds the size limit")
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync traffic spool temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close traffic spool temporary file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("commit traffic spool: %w", err)
	}
	committed = true
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("protect traffic spool: %w", err)
	}
	return syncDirectory(directory)
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create traffic spool directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect traffic spool directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("traffic spool directory is not a real directory")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("protect traffic spool directory: %w", err)
	}
	return nil
}

func removeTrafficSpool(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect traffic spool before removal: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to remove a non-regular traffic spool")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove traffic spool: %w", err)
	}
	return nil
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open traffic spool directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync traffic spool directory: %w", err)
	}
	return nil
}

func validateTrafficSpoolState(state *trafficSpoolState) error {
	if state.Version != trafficSpoolVersion {
		return fmt.Errorf("unsupported version %d", state.Version)
	}
	if len(state.Pending)+len(state.Queued) > maxTrafficSpoolUsers {
		return fmt.Errorf("too many users")
	}
	if len(state.Pending) == 0 {
		if state.PendingReportID != "" {
			return fmt.Errorf("report ID exists without a pending batch")
		}
	} else if !validTrafficReportID(state.PendingReportID) {
		return fmt.Errorf("pending report ID is invalid")
	}
	if err := validateTrafficSpoolEntries(state.Pending); err != nil {
		return fmt.Errorf("pending batch: %w", err)
	}
	if len(state.Pending) > maxTrafficReportUsers {
		return fmt.Errorf("pending batch has too many users")
	}
	remaining := maxTrafficReportBytes
	for _, entry := range state.Pending {
		if entry.Upload > remaining {
			return fmt.Errorf("pending batch exceeds the byte limit")
		}
		remaining -= entry.Upload
		if entry.Download > remaining {
			return fmt.Errorf("pending batch exceeds the byte limit")
		}
		remaining -= entry.Download
	}
	if err := validateTrafficSpoolEntries(state.Queued); err != nil {
		return fmt.Errorf("queued batch: %w", err)
	}
	return nil
}

func validateTrafficSpoolEntries(entries []trafficSpoolEntry) error {
	seen := make(map[int]struct{}, len(entries))
	for _, entry := range entries {
		if entry.UID <= 0 || entry.Upload < 0 || entry.Download < 0 {
			return fmt.Errorf("invalid traffic entry")
		}
		if _, exists := seen[entry.UID]; exists {
			return fmt.Errorf("duplicate user %d", entry.UID)
		}
		seen[entry.UID] = struct{}{}
	}
	return nil
}

func validTrafficReportID(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func trafficToSpoolEntries(items []panel.UserTraffic) []trafficSpoolEntry {
	entries := make([]trafficSpoolEntry, len(items))
	for i, item := range items {
		entries[i] = trafficSpoolEntry{UID: item.UID, Upload: item.Upload, Download: item.Download}
	}
	return entries
}

func spoolEntriesToTraffic(entries []trafficSpoolEntry) []panel.UserTraffic {
	items := make([]panel.UserTraffic, len(entries))
	for i, entry := range entries {
		items[i] = panel.UserTraffic{UID: entry.UID, Upload: entry.Upload, Download: entry.Download}
	}
	return items
}

func mergeTrafficBatches(existing, additions []panel.UserTraffic) ([]panel.UserTraffic, error) {
	merged := make(map[int]panel.UserTraffic, len(existing)+len(additions))
	for _, source := range [][]panel.UserTraffic{existing, additions} {
		for _, item := range source {
			if item.UID <= 0 || item.Upload < 0 || item.Download < 0 {
				return nil, fmt.Errorf("invalid traffic batch entry")
			}
			current := merged[item.UID]
			current.UID = item.UID
			if current.Upload > math.MaxInt64-item.Upload || current.Download > math.MaxInt64-item.Download {
				return nil, fmt.Errorf("traffic counter overflow for user %d", item.UID)
			}
			current.Upload += item.Upload
			current.Download += item.Download
			merged[item.UID] = current
		}
	}
	ids := make([]int, 0, len(merged))
	for uid, item := range merged {
		if item.Upload == 0 && item.Download == 0 {
			continue
		}
		ids = append(ids, uid)
	}
	if len(ids) > maxTrafficQueuedUsers {
		return nil, fmt.Errorf("traffic batch has too many users")
	}
	sort.Ints(ids)
	result := make([]panel.UserTraffic, 0, len(ids))
	for _, uid := range ids {
		result = append(result, merged[uid])
	}
	return result, nil
}
