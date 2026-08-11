package state

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

const (
	trafficCheckpointVersion = 1
	maxCheckpointBytes       = 256 << 20
)

type trafficCheckpoint struct {
	Version  int           `json:"version"`
	Sequence uint64        `json:"sequence"`
	Active   *TrafficBatch `json:"active,omitempty"`
	Pending  []UserTraffic `json:"pending,omitempty"`
}

// SaveCheckpoint atomically writes the complete accumulator state as JSON.
// The temporary file is created beside path and renamed only after its content
// has been flushed. Existing files are replaced atomically on supported local
// filesystems.
func (a *TrafficAccumulator) SaveCheckpoint(path string) error {
	if path == "" {
		return errors.New("state: checkpoint path is empty")
	}

	checkpoint, revision := a.checkpoint()
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create traffic checkpoint: %w", err)
	}
	temporaryName := temporary.Name()
	keepTemporary := true
	defer func() {
		if keepTemporary {
			_ = os.Remove(temporaryName)
		}
	}()

	writer := bufio.NewWriterSize(temporary, 32<<10)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(checkpoint); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("encode traffic checkpoint: %w", err)
	}
	if err := writer.Flush(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("flush traffic checkpoint: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync traffic checkpoint: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close traffic checkpoint: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace traffic checkpoint: %w", err)
	}
	keepTemporary = false
	if err := syncCheckpointDirectory(directory); err != nil {
		return fmt.Errorf("sync traffic checkpoint directory: %w", err)
	}
	a.mu.Lock()
	if revision == a.revision {
		a.saved = revision
	}
	a.mu.Unlock()
	return nil
}

// LoadTrafficAccumulator restores a checkpoint while applying a fresh memory
// bound. Unknown fields, duplicate users, zero counters, and oversized input
// are rejected.
func LoadTrafficAccumulator(path string, maxUsers int) (*TrafficAccumulator, error) {
	accumulator, err := NewTrafficAccumulator(maxUsers)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, errors.New("state: checkpoint path is empty")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open traffic checkpoint: %w", err)
	}
	defer file.Close()

	limit := checkpointLimit(maxUsers)
	limited := io.LimitReader(file, limit+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read traffic checkpoint: %w", err)
	}
	if int64(len(payload)) > limit {
		return nil, errors.New("state: traffic checkpoint exceeds size limit")
	}

	var checkpoint trafficCheckpoint
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&checkpoint); err != nil {
		return nil, fmt.Errorf("decode traffic checkpoint: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	if err := accumulator.restore(checkpoint); err != nil {
		return nil, err
	}
	return accumulator, nil
}

func (a *TrafficAccumulator) checkpoint() (trafficCheckpoint, uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()

	pending := make([]UserTraffic, 0, len(a.entries))
	for userID, entry := range a.entries {
		if entry.pending.empty() {
			continue
		}
		pending = append(pending, UserTraffic{
			UserID:   userID,
			Upload:   entry.pending.Upload,
			Download: entry.pending.Download,
		})
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].UserID < pending[j].UserID })

	checkpoint := trafficCheckpoint{
		Version:  trafficCheckpointVersion,
		Sequence: a.sequence,
		Pending:  pending,
	}
	if a.active != nil {
		active := cloneTrafficBatch(*a.active)
		checkpoint.Active = &active
	}
	return checkpoint, a.revision
}

func (a *TrafficAccumulator) restore(checkpoint trafficCheckpoint) error {
	if checkpoint.Version != trafficCheckpointVersion {
		return fmt.Errorf("state: unsupported traffic checkpoint version %d", checkpoint.Version)
	}

	seenPending := make(map[int]struct{}, len(checkpoint.Pending))
	for _, user := range checkpoint.Pending {
		if err := validateCheckpointUser(user); err != nil {
			return err
		}
		if _, duplicate := seenPending[user.UserID]; duplicate {
			return fmt.Errorf("state: duplicate pending user %d in traffic checkpoint", user.UserID)
		}
		seenPending[user.UserID] = struct{}{}
		entry := a.entries[user.UserID]
		if entry == nil {
			entry = &trafficEntry{}
			a.entries[user.UserID] = entry
		}
		entry.pending = Traffic{Upload: user.Upload, Download: user.Download}
	}

	if checkpoint.Active != nil {
		if checkpoint.Active.ID == 0 || len(checkpoint.Active.Users) == 0 {
			return errors.New("state: invalid active traffic batch in checkpoint")
		}
		seenActive := make(map[int]struct{}, len(checkpoint.Active.Users))
		for _, user := range checkpoint.Active.Users {
			if err := validateCheckpointUser(user); err != nil {
				return err
			}
			if _, duplicate := seenActive[user.UserID]; duplicate {
				return fmt.Errorf("state: duplicate active user %d in traffic checkpoint", user.UserID)
			}
			seenActive[user.UserID] = struct{}{}
			if a.entries[user.UserID] == nil {
				a.entries[user.UserID] = &trafficEntry{}
			}
		}
		active := cloneTrafficBatch(*checkpoint.Active)
		sort.Slice(active.Users, func(i, j int) bool { return active.Users[i].UserID < active.Users[j].UserID })
		a.active = &active
	}
	if len(a.entries) > a.maxUsers {
		return fmt.Errorf("%w: checkpoint has %d users, limit is %d", ErrTrafficCapacity, len(a.entries), a.maxUsers)
	}
	a.sequence = checkpoint.Sequence
	a.revision = 1
	a.saved = 1
	return nil
}

func validateCheckpointUser(user UserTraffic) error {
	if user.UserID <= 0 {
		return ErrInvalidUserID
	}
	if user.Upload < 0 || user.Download < 0 {
		return ErrInvalidTraffic
	}
	if user.Upload == 0 && user.Download == 0 {
		return fmt.Errorf("state: zero traffic for user %d in checkpoint", user.UserID)
	}
	return nil
}

func checkpointLimit(maxUsers int) int64 {
	const bytesPerUser = 256
	limit := int64(maxUsers)*bytesPerUser + 4096
	if limit > maxCheckpointBytes {
		return maxCheckpointBytes
	}
	return limit
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("state: traffic checkpoint contains trailing JSON")
		}
		return fmt.Errorf("decode trailing traffic checkpoint data: %w", err)
	}
	return nil
}
