// Package state contains bounded, concurrency-safe runtime state used by the
// controller. Types in this package do not start background goroutines.
package state

import (
	"errors"
	"math"
	"sort"
	"sync"
)

const (
	// MaxTrafficUsers is a defensive upper bound for configured accumulator
	// capacity. The normal configured value should be substantially smaller.
	MaxTrafficUsers = 1_000_000
)

var (
	ErrInvalidCapacity = errors.New("state: capacity must be positive and within the supported limit")
	ErrInvalidUserID   = errors.New("state: user ID must be positive")
	ErrInvalidTraffic  = errors.New("state: traffic deltas must not be negative")
	ErrTrafficCapacity = errors.New("state: traffic accumulator is at capacity")
)

// Traffic contains byte counters for one user.
type Traffic struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
}

func (t Traffic) empty() bool {
	return t.Upload == 0 && t.Download == 0
}

// UserTraffic associates byte counters with a panel user ID.
type UserTraffic struct {
	UserID   int   `json:"user_id"`
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
}

// TrafficBatch is an immutable-by-contract reporting snapshot. Users are
// always ordered by UserID. Snapshot returns a defensive copy, so a caller may
// safely transform the returned value for a panel request.
type TrafficBatch struct {
	ID    uint64        `json:"id"`
	Users []UserTraffic `json:"users"`
}

// Empty reports whether the batch contains no traffic to send.
func (b TrafficBatch) Empty() bool {
	return len(b.Users) == 0
}

type trafficEntry struct {
	pending Traffic
}

// TrafficAccumulator collects per-user traffic with a fixed user bound.
//
// At most one reporting batch is in flight. Snapshot returns that same batch
// until it is acknowledged. Adds made after Snapshot go into separate pending
// counters and therefore cannot be lost when the earlier batch is acknowledged.
type TrafficAccumulator struct {
	mu       sync.Mutex
	maxUsers int
	entries  map[int]*trafficEntry
	active   *TrafficBatch
	sequence uint64
	revision uint64
	saved    uint64
}

// NewTrafficAccumulator creates an accumulator that retains at most maxUsers
// distinct user IDs, including users in the in-flight batch.
func NewTrafficAccumulator(maxUsers int) (*TrafficAccumulator, error) {
	if maxUsers <= 0 || maxUsers > MaxTrafficUsers {
		return nil, ErrInvalidCapacity
	}

	return &TrafficAccumulator{
		maxUsers: maxUsers,
		entries:  make(map[int]*trafficEntry, min(maxUsers, 1024)),
	}, nil
}

// Add records byte deltas for userID. Arithmetic saturates at MaxInt64, which
// is also the largest counter accepted by the panel API.
// Adding a zero delta is a no-op and does not consume capacity.
func (a *TrafficAccumulator) Add(userID int, upload, download int64) error {
	if userID <= 0 {
		return ErrInvalidUserID
	}
	if upload < 0 || download < 0 {
		return ErrInvalidTraffic
	}
	if upload == 0 && download == 0 {
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	entry := a.entries[userID]
	if entry == nil {
		if len(a.entries) >= a.maxUsers {
			return ErrTrafficCapacity
		}
		entry = &trafficEntry{}
		a.entries[userID] = entry
	}
	entry.pending.Upload = saturatingAdd(entry.pending.Upload, upload)
	entry.pending.Download = saturatingAdd(entry.pending.Download, download)
	a.markChangedLocked()
	return nil
}

// AddBatch atomically records traffic for every supplied user. The complete
// batch is validated and its distinct-user capacity is preflighted before any
// counter is changed. Duplicate user IDs are combined with saturating
// arithmetic. If AddBatch returns an error, the accumulator is unchanged.
func (a *TrafficAccumulator) AddBatch(users []UserTraffic) error {
	if len(users) == 0 {
		return nil
	}
	for _, user := range users {
		if user.UserID <= 0 {
			return ErrInvalidUserID
		}
		if user.Upload < 0 || user.Download < 0 {
			return ErrInvalidTraffic
		}
	}
	normalized := make(map[int]Traffic, min(len(users), min(a.maxUsers, 1024)))
	for _, user := range users {
		if user.Upload == 0 && user.Download == 0 {
			continue
		}
		traffic := normalized[user.UserID]
		traffic.Upload = saturatingAdd(traffic.Upload, user.Upload)
		traffic.Download = saturatingAdd(traffic.Download, user.Download)
		normalized[user.UserID] = traffic
		if len(normalized) > a.maxUsers {
			return ErrTrafficCapacity
		}
	}
	if len(normalized) == 0 {
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	newUsers := 0
	for userID := range normalized {
		if _, exists := a.entries[userID]; !exists {
			newUsers++
		}
	}
	if newUsers > a.maxUsers-len(a.entries) {
		return ErrTrafficCapacity
	}
	for userID, traffic := range normalized {
		entry := a.entries[userID]
		if entry == nil {
			entry = &trafficEntry{}
			a.entries[userID] = entry
		}
		entry.pending.Upload = saturatingAdd(entry.pending.Upload, traffic.Upload)
		entry.pending.Download = saturatingAdd(entry.pending.Download, traffic.Download)
	}
	a.markChangedLocked()
	return nil
}

// Snapshot returns the current in-flight batch, or atomically moves all
// pending counters into a new batch. An empty accumulator returns a zero batch.
func (a *TrafficAccumulator) Snapshot() TrafficBatch {
	return a.SnapshotAbove(0)
}

// SnapshotAbove starts a batch only for users whose combined pending bytes
// exceed minimumBytes. Smaller counters remain pending and are considered in
// a later reporting interval. An existing in-flight batch is returned as-is.
func (a *TrafficAccumulator) SnapshotAbove(minimumBytes int64) TrafficBatch {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.active != nil {
		return cloneTrafficBatch(*a.active)
	}

	users := make([]UserTraffic, 0, len(a.entries))
	for userID, entry := range a.entries {
		if entry.pending.empty() {
			continue
		}
		combined := saturatingAdd(entry.pending.Upload, entry.pending.Download)
		if combined <= minimumBytes {
			continue
		}
		users = append(users, UserTraffic{
			UserID:   userID,
			Upload:   entry.pending.Upload,
			Download: entry.pending.Download,
		})
		entry.pending = Traffic{}
	}
	if len(users) == 0 {
		return TrafficBatch{}
	}

	sort.Slice(users, func(i, j int) bool { return users[i].UserID < users[j].UserID })
	a.sequence++
	if a.sequence == 0 {
		// Batch ID zero is reserved for an empty batch.
		a.sequence = 1
	}
	a.active = &TrafficBatch{ID: a.sequence, Users: users}
	a.markChangedLocked()
	return cloneTrafficBatch(*a.active)
}

// Ack acknowledges the currently in-flight batch. It returns false for an
// empty, stale, or unknown batch ID. Pending increments made after Snapshot are
// preserved.
func (a *TrafficAccumulator) Ack(batchID uint64) bool {
	if batchID == 0 {
		return false
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.active == nil || a.active.ID != batchID {
		return false
	}
	for _, user := range a.active.Users {
		entry := a.entries[user.UserID]
		if entry != nil && entry.pending.empty() {
			delete(a.entries, user.UserID)
		}
	}
	a.active = nil
	a.markChangedLocked()
	return true
}

// CheckpointDirty reports whether the logical accumulator state changed since
// the most recent successful checkpoint write (or restore).
func (a *TrafficAccumulator) CheckpointDirty() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.revision != a.saved
}

// Len returns the number of retained user IDs. It includes users represented
// only by the in-flight batch.
func (a *TrafficAccumulator) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.entries)
}

// HasInFlight reports whether a non-empty batch is waiting for acknowledgement.
func (a *TrafficAccumulator) HasInFlight() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.active != nil
}

// Capacity returns the configured distinct-user limit.
func (a *TrafficAccumulator) Capacity() int {
	return a.maxUsers
}

func (a *TrafficAccumulator) markChangedLocked() {
	a.revision++
	if a.revision == 0 {
		a.revision = 1
	}
}

func saturatingAdd(left, right int64) int64 {
	if math.MaxInt64-left < right {
		return math.MaxInt64
	}
	return left + right
}

func cloneTrafficBatch(batch TrafficBatch) TrafficBatch {
	clone := TrafficBatch{ID: batch.ID}
	clone.Users = append([]UserTraffic(nil), batch.Users...)
	return clone
}
