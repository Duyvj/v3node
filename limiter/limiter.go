package limiter

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/Duyvj/v3node/common/format"
	"github.com/Duyvj/v3node/common/rate"
	"github.com/Duyvj/v3node/conf"
	log "github.com/sirupsen/logrus"
)

var limitLock sync.RWMutex
var limiter map[string]*Limiter

func Init() {
	limitLock.Lock()
	limiter = map[string]*Limiter{}
	limitLock.Unlock()
}

type Limiter struct {
	Nodetype      string
	SpeedLimit    int
	UserLimitInfo *sync.Map // key: tag|uuid, value: UserLimitInfo
	SpeedLimiter  *sync.Map // key: tag|uuid, value: *DynamicBucket
	devices       *deviceTracker
	remote        *redisDeviceStore
	remoteEnabled bool
	failClosed    bool
	lastRemoteErr atomic.Int64
}

type UserLimitInfo struct {
	UID               int
	SpeedLimit        int
	DeviceLimit       int
	DynamicSpeedLimit int
	ExpireTime        int64
}

func AddLimiter(nodetype string, tag string, users []panel.UserInfo, alive map[int]int, deviceConfig *conf.GlobalDeviceLimitConfig, namespace string) *Limiter {
	if deviceConfig != nil {
		copyConfig := *deviceConfig
		// The config type lives in conf so it can be decoded without an import cycle.
		// Keep the same safe defaults when callers construct it directly in tests.
		applyDeviceDefaults(&copyConfig)
		deviceConfig = &copyConfig
	}

	l := &Limiter{
		Nodetype:      nodetype,
		UserLimitInfo: new(sync.Map),
		SpeedLimiter:  new(sync.Map),
		devices:       newDeviceTracker(deviceConfig),
	}
	l.devices.SetAliveList(alive)
	if deviceConfig != nil && deviceConfig.Enable {
		l.remoteEnabled = true
		l.failClosed = deviceConfig.FailClosed
		remote, err := newRedisDeviceStore(deviceConfig, namespace)
		if err != nil {
			if l.failClosed {
				log.WithError(err).Error("Redis device limiter unavailable; device-limited users fail closed")
			} else {
				log.WithError(err).Warn("Redis device limiter disabled; using bounded local device tracking")
			}
		} else {
			l.remote = remote
			if !l.failClosed {
				l.devices.startRemoteRefresh(2)
			}
		}
	}
	for i := range users {
		l.UserLimitInfo.Store(format.UserTag(tag, users[i].Uuid), UserLimitInfo{
			UID:         users[i].Id,
			SpeedLimit:  users[i].SpeedLimit,
			DeviceLimit: users[i].DeviceLimit,
		})
	}
	limitLock.Lock()
	limiter[tag] = l
	limitLock.Unlock()
	return l
}

func GetLimiter(tag string) (info *Limiter, err error) {
	limitLock.RLock()
	info, ok := limiter[tag]
	limitLock.RUnlock()
	if !ok {
		return nil, errors.New("not found")
	}
	return info, nil
}

func DeleteLimiter(tag string) {
	limitLock.Lock()
	l := limiter[tag]
	delete(limiter, tag)
	limitLock.Unlock()
	if l != nil {
		l.Close()
	}
}

func (l *Limiter) Close() {
	l.devices.Close()
	if l.remote != nil {
		_ = l.remote.Close()
	}
}

func (l *Limiter) UpdateAliveList(alive map[int]int) {
	// Keep the panel's last global count as a conservative fallback when Redis
	// is disabled. The tracker still owns current local IPs and never reads this
	// map without copying it under a lock.
	l.devices.SetAliveList(alive)
}

func (l *Limiter) UpdateUser(tag string, added []panel.UserInfo, deleted []panel.UserInfo, modified []panel.UserInfo) {
	for i := range deleted {
		key := format.UserTag(tag, deleted[i].Uuid)
		l.UserLimitInfo.Delete(key)
		l.SpeedLimiter.Delete(key)
		l.devices.Delete(key)
		if l.remote != nil {
			_ = l.remote.Delete(context.Background(), key)
		}
	}
	for i := range modified {
		key := format.UserTag(tag, modified[i].Uuid)
		l.UserLimitInfo.Store(key, UserLimitInfo{
			UID:         modified[i].Id,
			SpeedLimit:  modified[i].SpeedLimit,
			DeviceLimit: modified[i].DeviceLimit,
		})
		limit := int64(determineSpeedLimit(l.SpeedLimit, modified[i].SpeedLimit)) * 1000000 / 8
		if limit > 0 {
			if v, ok := l.SpeedLimiter.Load(key); ok {
				v.(*rate.DynamicBucket).Update(limit)
			} else {
				l.SpeedLimiter.Store(key, rate.NewDynamicBucket(limit))
			}
		} else {
			l.SpeedLimiter.Delete(key)
		}
	}
	for i := range added {
		key := format.UserTag(tag, added[i].Uuid)
		l.UserLimitInfo.Store(key, UserLimitInfo{
			UID:         added[i].Id,
			SpeedLimit:  added[i].SpeedLimit,
			DeviceLimit: added[i].DeviceLimit,
		})
	}
}

func (l *Limiter) UpdateDynamicSpeedLimit(tag, uuid string, limit int, expire time.Time) error {
	key := format.UserTag(tag, uuid)
	for {
		v, ok := l.UserLimitInfo.Load(key)
		if !ok {
			return errors.New("not found")
		}
		old := v.(UserLimitInfo)
		updated := old
		updated.DynamicSpeedLimit = limit
		updated.ExpireTime = expire.Unix()
		if l.UserLimitInfo.CompareAndSwap(key, old, updated) {
			return nil
		}
	}
}

// CheckLimit applies the per-user speed limit and the device/IP limit. It is
// called for both TCP and UDP sessions; the old implementation skipped most
// UDP sources and therefore never enforced the configured limit for them.
func (l *Limiter) CheckLimit(ctx context.Context, taguuid string, ip string) (*rate.DynamicBucket, bool) {
	infoValue, ok := l.UserLimitInfo.Load(taguuid)
	if !ok {
		return nil, true
	}
	info := infoValue.(UserLimitInfo)
	now := time.Now()
	if info.ExpireTime != 0 && info.ExpireTime <= now.Unix() {
		if info.SpeedLimit != 0 {
			updated := info
			updated.DynamicSpeedLimit = 0
			updated.ExpireTime = 0
			l.UserLimitInfo.CompareAndSwap(taguuid, info, updated)
			info = updated
		} else {
			l.UserLimitInfo.Delete(taguuid)
			return nil, true
		}
	}

	if normalizedIP := normalizeIP(ip); normalizedIP != "" {
		// FailClosed must also cover configuration/initialization failures. The
		// previous implementation enforced it only after a Redis client had been
		// created, so an unsupported network value silently bypassed the global
		// device limit even though the administrator explicitly requested denial.
		if info.DeviceLimit > 0 && l.remoteEnabled && l.failClosed && l.remote == nil {
			return nil, true
		}
		allowed, err := l.devices.Observe(ctx, l.remote, l.failClosed, taguuid, normalizedIP, info.UID, info.DeviceLimit, now)
		if err != nil && l.shouldLogRemoteError(now) {
			log.WithError(err).Warn("Redis device limiter request failed; local bounded tracker is used")
		}
		if !allowed {
			return nil, true
		}
	}

	limit := int64(determineSpeedLimit(l.SpeedLimit, determineSpeedLimit(info.SpeedLimit, info.DynamicSpeedLimit))) * 1000000 / 8
	if limit <= 0 {
		return nil, false
	}
	if v, ok := l.SpeedLimiter.Load(taguuid); ok {
		bucket := v.(*rate.DynamicBucket)
		return bucket, false
	}
	bucket := rate.NewDynamicBucket(limit)
	actual, loaded := l.SpeedLimiter.LoadOrStore(taguuid, bucket)
	if loaded {
		return actual.(*rate.DynamicBucket), false
	}
	return bucket, false
}

// TouchDevice refreshes the bounded local entry and, when due, the Redis TTL.
// It is safe to call from the data path because same-IP touches are allocation
// free. Fail-open Redis refreshes are queued in bounded background workers;
// FailClosed keeps its synchronous enforcement semantics.
func (l *Limiter) TouchDevice(taguuid, ip string) {
	value, ok := l.UserLimitInfo.Load(taguuid)
	if !ok {
		return
	}
	if ip == "" {
		return
	}
	_, _ = l.devices.Observe(context.Background(), l.remote, l.failClosed, taguuid, ip, value.(UserLimitInfo).UID, value.(UserLimitInfo).DeviceLimit, time.Now())
}

func (l *Limiter) shouldLogRemoteError(now time.Time) bool {
	last := time.Unix(0, l.lastRemoteErr.Load())
	if now.Sub(last) < 30*time.Second {
		return false
	}
	return l.lastRemoteErr.CompareAndSwap(last.UnixNano(), now.UnixNano())
}

func (l *Limiter) GetOnlineDevice() (*[]panel.OnlineUser, error) {
	online, active := l.devices.Snapshot(time.Now())
	// Buckets for users that did not appear in the current TTL window are no
	// longer useful and are a common source of slow memory growth on long-lived
	// nodes.
	l.SpeedLimiter.Range(func(key, _ interface{}) bool {
		if _, ok := active[key.(string)]; !ok {
			l.SpeedLimiter.Delete(key)
		}
		return true
	})
	return &online, nil
}

func normalizeIP(raw string) string {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "::ffff:"))
	if raw == "" {
		return ""
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return ""
	}
	return addr.Unmap().String()
}

// NormalizeIP is exported for data-path wrappers so the address is parsed once
// per session instead of once per UDP packet.
func NormalizeIP(raw string) string {
	return normalizeIP(raw)
}

// deviceGracePtr returns a fresh pointer. applyDeviceDefaults is handed a
// shallow copy of the caller's config, so a default must replace the pointer
// rather than write through it, or it would mutate the original.
func deviceGracePtr(v int) *int {
	return &v
}

func applyDeviceDefaults(c *conf.GlobalDeviceLimitConfig) {
	if c.RedisNetwork == "" {
		c.RedisNetwork = "tcp"
	}
	if c.RedisAddr == "" {
		c.RedisAddr = "127.0.0.1:6379"
	}
	if c.Timeout <= 0 {
		c.Timeout = 1
	}
	if c.Expiry <= 0 {
		c.Expiry = 60
	}
	if c.Expiry < 10 {
		c.Expiry = 10
	}
	if c.RefreshInterval <= 0 || c.RefreshInterval >= c.Expiry {
		c.RefreshInterval = c.Expiry / 3
		if c.RefreshInterval < 5 {
			c.RefreshInterval = 5
		}
	}
	if c.RefreshInterval < 5 {
		c.RefreshInterval = 5
	}
	// Kept byte-for-byte in step with conf.GlobalDeviceLimitConfig.applyDefaults:
	// a file-loaded config and an agent hot-swapped one must admit identically.
	if c.HandoverGrace == nil {
		c.HandoverGrace = deviceGracePtr(15)
	}
	if *c.HandoverGrace < 0 {
		c.HandoverGrace = deviceGracePtr(0)
	}
	if *c.HandoverGrace > c.Expiry {
		c.HandoverGrace = deviceGracePtr(c.Expiry)
	}
	// An address that is still transmitting only refreshes its score once per
	// RefreshInterval, so it must get at least two chances to do so inside the
	// grace window. Otherwise a second client that is genuinely active looks
	// silent and gets evicted, which is the sharing case we must still refuse.
	if grace := *c.HandoverGrace; grace > 0 {
		if c.RefreshInterval > grace/2 {
			c.RefreshInterval = grace / 2
			if c.RefreshInterval < 5 {
				c.RefreshInterval = 5
			}
		}
		if c.RefreshInterval*2 > grace {
			c.HandoverGrace = deviceGracePtr(c.RefreshInterval * 2)
		}
	}
	if c.MaxIPsPerUser <= 0 {
		c.MaxIPsPerUser = 256
	}
	if c.KeyPrefix == "" {
		c.KeyPrefix = "znode:device"
	}
	if c.SyncChannel == "" {
		c.SyncChannel = "v2board:device-sync"
	}
	if c.SyncEnabled == nil {
		enabled := true
		c.SyncEnabled = &enabled
	}
}

type UserIpList struct {
	Uid    int      `json:"Uid"`
	IpList []string `json:"Ips"`
}
