package state

import (
	"container/list"
	"errors"
	"net/netip"
	"sort"
	"sync"
	"time"
)

const MaxOnlineEntries = 1_000_000

var (
	ErrInvalidTTL = errors.New("state: online TTL must be positive")
	ErrInvalidIP  = errors.New("state: invalid online IP address")
)

// OnlineUser is a deterministic snapshot row. Rows are sorted by UserID and
// IPs are sorted by address value.
type OnlineUser struct {
	UserID int      `json:"user_id"`
	IPs    []string `json:"ips"`
}

type onlineRecord struct {
	userID     int
	address    netip.Addr
	expiresAt  time.Time
	reportable bool
	globalElem *list.Element
	userElem   *list.Element
}

type onlineUserState struct {
	records map[netip.Addr]*onlineRecord
	lru     list.List
}

// OnlineTracker retains recently observed user/IP pairs. Both the total pair
// count and each user's pair count have hard bounds. Least-recently-observed
// entries are evicted when either bound is reached.
//
// Expiry is opportunistic: calls to Observe, Snapshot, Len, or Purge remove
// expired entries. The tracker deliberately starts no cleanup goroutine.
type OnlineTracker struct {
	mu            sync.Mutex
	ttl           time.Duration
	maxEntries    int
	maxIPsPerUser int
	users         map[int]*onlineUserState
	globalLRU     list.List
	watermark     time.Time
}

// NewOnlineTracker constructs a bounded online-IP tracker.
func NewOnlineTracker(ttl time.Duration, maxEntries, maxIPsPerUser int) (*OnlineTracker, error) {
	if ttl <= 0 {
		return nil, ErrInvalidTTL
	}
	if maxEntries <= 0 || maxEntries > MaxOnlineEntries || maxIPsPerUser <= 0 || maxIPsPerUser > maxEntries {
		return nil, ErrInvalidCapacity
	}

	return &OnlineTracker{
		ttl:           ttl,
		maxEntries:    maxEntries,
		maxIPsPerUser: maxIPsPerUser,
		users:         make(map[int]*onlineUserState, min(maxEntries, 1024)),
	}, nil
}

// Observe records an IP at the current time.
func (t *OnlineTracker) Observe(userID int, rawAddress string) error {
	return t.ObserveAt(userID, rawAddress, time.Now())
}

// ObserveAt records an IP at a supplied time. IPv4-mapped IPv6 addresses are
// canonicalized to IPv4, preventing duplicate accounting for the same peer.
func (t *OnlineTracker) ObserveAt(userID int, rawAddress string, now time.Time) error {
	// A valid zone-free textual IP is at most 45 bytes. Keep a little room for
	// unusual but parser-supported forms while bounding hostile input work.
	if len(rawAddress) == 0 || len(rawAddress) > 64 {
		return ErrInvalidIP
	}
	address, err := netip.ParseAddr(rawAddress)
	if err != nil || address.Zone() != "" {
		return ErrInvalidIP
	}
	return t.observeAddrAt(userID, address, now, true)
}

// ObserveAddrAt is the parsed-address variant of ObserveAt.
func (t *OnlineTracker) ObserveAddrAt(userID int, address netip.Addr, now time.Time) error {
	return t.observeAddrAt(userID, address, now, true)
}

// Reserve records an accepted user/IP pair for device-limit enforcement
// without making it eligible for the panel online report. A later Observe of
// the same pair promotes it to reportable once the traffic threshold is met.
func (t *OnlineTracker) Reserve(userID int, rawAddress string) error {
	if len(rawAddress) == 0 || len(rawAddress) > 64 {
		return ErrInvalidIP
	}
	address, err := netip.ParseAddr(rawAddress)
	if err != nil || address.Zone() != "" {
		return ErrInvalidIP
	}
	return t.observeAddrAt(userID, address, time.Now(), false)
}

func (t *OnlineTracker) observeAddrAt(userID int, address netip.Addr, now time.Time, reportable bool) error {
	if userID <= 0 {
		return ErrInvalidUserID
	}
	if !address.IsValid() || address.Zone() != "" {
		return ErrInvalidIP
	}
	address = address.Unmap()

	t.mu.Lock()
	defer t.mu.Unlock()

	now = t.effectiveNow(now)
	t.purgeExpiredLocked(now)
	if user := t.users[userID]; user != nil {
		if record := user.records[address]; record != nil {
			record.expiresAt = now.Add(t.ttl)
			record.reportable = record.reportable || reportable
			t.globalLRU.MoveToBack(record.globalElem)
			user.lru.MoveToBack(record.userElem)
			return nil
		}
	}

	// Enforce the per-user bound first. Global eviction can delete that user's
	// state entirely, so the user map is looked up again before insertion.
	if user := t.users[userID]; user != nil && len(user.records) >= t.maxIPsPerUser {
		t.removeRecordLocked(user.lru.Front().Value.(*onlineRecord))
	}
	for t.globalLRU.Len() >= t.maxEntries {
		t.removeRecordLocked(t.globalLRU.Front().Value.(*onlineRecord))
	}

	user := t.users[userID]
	if user == nil {
		user = &onlineUserState{records: make(map[netip.Addr]*onlineRecord, min(t.maxIPsPerUser, 16))}
		t.users[userID] = user
	}
	record := &onlineRecord{
		userID:     userID,
		address:    address,
		expiresAt:  now.Add(t.ttl),
		reportable: reportable,
	}
	record.globalElem = t.globalLRU.PushBack(record)
	record.userElem = user.lru.PushBack(record)
	user.records[address] = record
	return nil
}

// Snapshot returns a deterministic copy at the current time.
func (t *OnlineTracker) Snapshot() []OnlineUser {
	return t.SnapshotAt(time.Now())
}

// SnapshotAt returns a deterministic copy after expiring old entries.
func (t *OnlineTracker) SnapshotAt(now time.Time) []OnlineUser {
	t.mu.Lock()
	defer t.mu.Unlock()

	now = t.effectiveNow(now)
	t.purgeExpiredLocked(now)
	result := make([]OnlineUser, 0, len(t.users))
	for userID, user := range t.users {
		addresses := make([]netip.Addr, 0, len(user.records))
		for address := range user.records {
			addresses = append(addresses, address)
		}
		sort.Slice(addresses, func(i, j int) bool { return addresses[i].Compare(addresses[j]) < 0 })
		ips := make([]string, len(addresses))
		for index, address := range addresses {
			ips[index] = address.String()
		}
		result = append(result, OnlineUser{UserID: userID, IPs: ips})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UserID < result[j].UserID })
	return result
}

// SnapshotMap converts the deterministic rows to the panel's online report
// shape. Each returned IP slice is owned by the caller.
func (t *OnlineTracker) SnapshotMap() map[int][]string {
	rows := t.Snapshot()
	result := make(map[int][]string, len(rows))
	for _, row := range rows {
		result[row.UserID] = append([]string(nil), row.IPs...)
	}
	return result
}

// SnapshotReportableMap returns only pairs promoted by Observe. Reserved
// low-traffic pairs continue to protect device limits without being reported
// to the panel before DeviceOnlineMinTraffic is reached.
func (t *OnlineTracker) SnapshotReportableMap() map[int][]string {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.effectiveNow(time.Now())
	t.purgeExpiredLocked(now)
	addressesByUser := make(map[int][]netip.Addr)
	for userID, user := range t.users {
		for address, record := range user.records {
			if record.reportable {
				addressesByUser[userID] = append(addressesByUser[userID], address)
			}
		}
	}
	result := make(map[int][]string, len(addressesByUser))
	for userID, addresses := range addressesByUser {
		sort.Slice(addresses, func(i, j int) bool { return addresses[i].Compare(addresses[j]) < 0 })
		values := make([]string, len(addresses))
		for index, address := range addresses {
			values[index] = address.String()
		}
		result[userID] = values
	}
	return result
}

// Purge removes entries expired at the current time and returns their count.
func (t *OnlineTracker) Purge() int {
	return t.PurgeAt(time.Now())
}

// PurgeAt removes entries expired at now and returns their count.
func (t *OnlineTracker) PurgeAt(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	now = t.effectiveNow(now)
	return t.purgeExpiredLocked(now)
}

// Len returns the number of live user/IP pairs at the current time.
func (t *OnlineTracker) Len() int {
	return t.LenAt(time.Now())
}

// LenAt returns the number of live user/IP pairs after expiring entries at now.
func (t *OnlineTracker) LenAt(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	now = t.effectiveNow(now)
	t.purgeExpiredLocked(now)
	return t.globalLRU.Len()
}

// Has reports whether a live user/IP pair is already known. It is useful for
// conservative device-limit enforcement: reconnects from an accepted IP do
// not consume another device slot.
func (t *OnlineTracker) Has(userID int, rawAddress string) bool {
	address, err := netip.ParseAddr(rawAddress)
	if err != nil || address.Zone() != "" {
		return false
	}
	address = address.Unmap()
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.effectiveNow(time.Now())
	t.purgeExpiredLocked(now)
	user := t.users[userID]
	return user != nil && user.records[address] != nil
}

// UserLen returns the number of live IPs retained for one user.
func (t *OnlineTracker) UserLen(userID int) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.effectiveNow(time.Now())
	t.purgeExpiredLocked(now)
	if user := t.users[userID]; user != nil {
		return len(user.records)
	}
	return 0
}

// ForgetUser immediately removes all online-IP entries for userID.
func (t *OnlineTracker) ForgetUser(userID int) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	user := t.users[userID]
	if user == nil {
		return 0
	}
	removed := len(user.records)
	for user.lru.Len() != 0 {
		t.removeRecordLocked(user.lru.Front().Value.(*onlineRecord))
	}
	return removed
}

// Capacity returns the global and per-user pair limits.
func (t *OnlineTracker) Capacity() (global, perUser int) {
	return t.maxEntries, t.maxIPsPerUser
}

func (t *OnlineTracker) effectiveNow(now time.Time) time.Time {
	// Wall-clock corrections must not make the LRU cease to be expiration
	// ordered. Clamp regressions to the most recently observed time.
	if !t.watermark.IsZero() && now.Before(t.watermark) {
		return t.watermark
	}
	t.watermark = now
	return now
}

func (t *OnlineTracker) purgeExpiredLocked(now time.Time) int {
	removed := 0
	for t.globalLRU.Len() != 0 {
		record := t.globalLRU.Front().Value.(*onlineRecord)
		if record.expiresAt.After(now) {
			break
		}
		t.removeRecordLocked(record)
		removed++
	}
	return removed
}

func (t *OnlineTracker) removeRecordLocked(record *onlineRecord) {
	t.globalLRU.Remove(record.globalElem)
	user := t.users[record.userID]
	if user == nil {
		return
	}
	user.lru.Remove(record.userElem)
	delete(user.records, record.address)
	if len(user.records) == 0 {
		delete(t.users, record.userID)
	}
}
