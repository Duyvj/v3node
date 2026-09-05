package limiter

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/Duyvj/v3node/common/format"
	"github.com/Duyvj/v3node/conf"
)

type fakeDeviceStore struct {
	calls atomic.Int32
	allow func(context.Context, string, string, int) (bool, error)
}

func (s *fakeDeviceStore) Allow(ctx context.Context, userKey, ip string, limit int) (bool, error) {
	s.calls.Add(1)
	return s.allow(ctx, userKey, ip, limit)
}

func waitForDeviceStoreCalls(t *testing.T, store *fakeDeviceStore, want int32) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if store.calls.Load() >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("remote calls = %d, want at least %d", store.calls.Load(), want)
}

func TestNormalizeIP(t *testing.T) {
	if got := normalizeIP("::ffff:192.0.2.10"); got != "192.0.2.10" {
		t.Fatalf("mapped IPv4 normalized to %q", got)
	}
	if got := normalizeIP("2001:db8::1"); got != "2001:db8::1" {
		t.Fatalf("IPv6 normalized to %q", got)
	}
	if got := normalizeIP("not-an-ip"); got != "" {
		t.Fatalf("invalid IP normalized to %q", got)
	}
}

func TestRedisDeviceKeyUsesUUIDAndNamespaceHash(t *testing.T) {
	store := &redisDeviceStore{prefix: "znode:device", namespace: "https://panel.example/"}
	first := store.key("[node-a]|uuid-123")
	second := store.key("[node-b]|uuid-123")
	other := (&redisDeviceStore{prefix: "znode:device", namespace: "https://other.example"}).key("[node-a]|uuid-123")
	if first != second {
		t.Fatalf("same UUID on two nodes must share a Redis key: %q != %q", first, second)
	}
	if first == other || len(first) > 100 || containsRaw(first, "uuid-123") {
		t.Fatalf("Redis key should be namespaced and opaque: %q", first)
	}
}

func TestRedisDeviceKeyIsStableAcrossHashedUserTagUpgrade(t *testing.T) {
	store := &redisDeviceStore{prefix: "znode:device", namespace: "https://panel.example"}
	legacy := store.key("[node-a]|uuid-123")
	hardened := store.key(format.UserTag("[node-a]", "uuid-123"))
	if legacy != hardened {
		t.Fatalf("rolling upgrade split the device-limit identity: legacy=%q hardened=%q", legacy, hardened)
	}
}

func TestRedisDeviceStoresShareOneClientPerAgentConfig(t *testing.T) {
	config := &conf.GlobalDeviceLimitConfig{
		Enable:       true,
		RedisNetwork: "tcp",
		RedisAddr:    "127.0.0.1:6379",
		RedisDB:      7,
		Timeout:      2,
	}
	first, err := newRedisDeviceStore(config, "https://panel.example")
	if err != nil {
		t.Fatalf("create first store: %v", err)
	}
	second, err := newRedisDeviceStore(config, "https://panel.example")
	if err != nil {
		_ = first.Close()
		t.Fatalf("create second store: %v", err)
	}
	if first.client != second.client {
		t.Fatal("logical nodes with identical Redis settings did not share a client pool")
	}
	redisClientRegistry.Lock()
	shared := redisClientRegistry.clients[first.clientKey]
	refs := 0
	if shared != nil {
		refs = shared.refs
	}
	redisClientRegistry.Unlock()
	if refs != 2 {
		t.Fatalf("shared Redis client refs = %d, want 2", refs)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first store: %v", err)
	}
	if second.client == nil {
		t.Fatal("closing one logical node closed the shared client for the other node")
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close second store: %v", err)
	}
	redisClientRegistry.Lock()
	remaining := len(redisClientRegistry.clients)
	redisClientRegistry.Unlock()
	if remaining != 0 {
		t.Fatalf("shared Redis registry retained %d clients after final close", remaining)
	}
}

func containsRaw(value, raw string) bool {
	for i := 0; i+len(raw) <= len(value); i++ {
		if value[i:i+len(raw)] == raw {
			return true
		}
	}
	return false
}

func TestDeviceTrackerEnforcesAndExpires(t *testing.T) {
	tracker := newDeviceTracker(nil)
	tracker.ttl = 20 * time.Millisecond
	now := time.Now()
	if allowed, err := tracker.Observe(context.Background(), nil, false, "user", "192.0.2.1", 1, 1, now); !allowed || err != nil {
		t.Fatalf("first device: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := tracker.Observe(context.Background(), nil, false, "user", "192.0.2.2", 1, 1, now); allowed || err != nil {
		t.Fatalf("second device should be rejected: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := tracker.Observe(context.Background(), nil, false, "user", "192.0.2.1", 1, 1, now); !allowed || err != nil {
		t.Fatalf("same device: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := tracker.Observe(context.Background(), nil, false, "user", "192.0.2.2", 1, 1, now.Add(25*time.Millisecond)); !allowed || err != nil {
		t.Fatalf("expired device should free a slot: allowed=%v err=%v", allowed, err)
	}
}

func TestDeviceTrackerBoundsUnlimitedUser(t *testing.T) {
	tracker := newDeviceTracker(nil)
	tracker.maxIPsPerUser = 2
	now := time.Now()
	for i, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		if allowed, err := tracker.Observe(context.Background(), nil, false, "user", ip, 1, 0, now); !allowed || err != nil {
			t.Fatalf("unlimited device %d: allowed=%v err=%v", i, allowed, err)
		}
	}
	online, _ := tracker.Snapshot(now)
	if len(online) != 2 {
		t.Fatalf("bounded tracker stored %d IPs, want 2", len(online))
	}
}

func TestDeviceTrackerDoesNotRejectReconnectFromStalePanelAliveCount(t *testing.T) {
	tracker := newDeviceTracker(nil)
	tracker.SetAliveList(map[int]int{42: 1})
	now := time.Now()
	if allowed, err := tracker.Observe(context.Background(), nil, false, "user", "192.0.2.9", 42, 1, now); !allowed || err != nil {
		t.Fatalf("stale panel alive count blocked the first reconnect: allowed=%v err=%v", allowed, err)
	}
}

func TestFailOpenDeviceAdmissionStillHonorsHealthyRedisDenial(t *testing.T) {
	tracker := newDeviceTracker(nil)
	store := &fakeDeviceStore{allow: func(context.Context, string, string, int) (bool, error) {
		return false, nil
	}}
	tracker.startRemoteRefresh(1)
	defer tracker.Close()

	for attempt := 0; attempt < 2; attempt++ {
		if allowed, err := tracker.Observe(context.Background(), store, false, "user", "192.0.2.1", 1, 1, time.Now()); allowed || err != nil {
			t.Fatalf("healthy Redis denial attempt %d: allowed=%v err=%v", attempt, allowed, err)
		}
	}
	if got := store.calls.Load(); got != 2 {
		t.Fatalf("Redis admission calls = %d, want 2", got)
	}
}

func TestFailOpenConcurrentSameIPCannotBypassHealthyRedisDenial(t *testing.T) {
	tracker := newDeviceTracker(nil)
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	store := &fakeDeviceStore{allow: func(context.Context, string, string, int) (bool, error) {
		started <- struct{}{}
		<-release
		return false, nil
	}}
	tracker.startRemoteRefresh(1)
	defer tracker.Close()

	type result struct {
		allowed bool
		err     error
	}
	results := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			allowed, err := tracker.Observe(context.Background(), store, false, "user", "192.0.2.1", 1, 1, time.Now())
			results <- result{allowed: allowed, err: err}
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("concurrent admission did not wait for Redis")
		}
	}
	close(release)
	for i := 0; i < 2; i++ {
		result := <-results
		if result.allowed || result.err != nil {
			t.Fatalf("concurrent denial result %d: allowed=%v err=%v", i, result.allowed, result.err)
		}
	}
}

func TestFailOpenApprovedDeviceRefreshIsNonblockingAndSingleFlightPerIP(t *testing.T) {
	tracker := newDeviceTracker(nil)
	started := make(chan struct{}, 1)
	var block atomic.Bool
	store := &fakeDeviceStore{allow: func(ctx context.Context, _, _ string, _ int) (bool, error) {
		if !block.Load() {
			return true, nil
		}
		started <- struct{}{}
		<-ctx.Done()
		return true, ctx.Err()
	}}
	tracker.startRemoteRefresh(1)
	defer tracker.Close()
	now := time.Now()
	if allowed, err := tracker.Observe(context.Background(), store, false, "user", "192.0.2.1", 1, 1, now); !allowed || err != nil {
		t.Fatalf("initial Redis admission: allowed=%v err=%v", allowed, err)
	}
	block.Store(true)
	now = time.Now().Add(tracker.refresh + time.Second)
	start := time.Now()
	for i := 0; i < 20; i++ {
		if allowed, err := tracker.Observe(context.Background(), store, false, "user", "192.0.2.1", 1, 1, now); !allowed || err != nil {
			t.Fatalf("fail-open observe %d: allowed=%v err=%v", i, allowed, err)
		}
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("fail-open path blocked for %s", elapsed)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("background refresh did not start")
	}
	if got := store.calls.Load(); got != 2 {
		t.Fatalf("same IP created %d total Redis calls, want admission + one refresh", got)
	}
}

func TestFailOpenDeviceRefreshOpensCircuitAfterRedisError(t *testing.T) {
	tracker := newDeviceTracker(nil)
	store := &fakeDeviceStore{allow: func(context.Context, string, string, int) (bool, error) {
		return false, errors.New("redis unavailable")
	}}
	tracker.startRemoteRefresh(1)
	defer tracker.Close()
	now := time.Now()
	if allowed, err := tracker.Observe(context.Background(), store, false, "user", "192.0.2.1", 1, 2, now); !allowed || err == nil {
		t.Fatalf("initial Redis failure should fail open and report the error: allowed=%v err=%v", allowed, err)
	}
	waitForDeviceStoreCalls(t, store, 1)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		tracker.mu.Lock()
		open := time.Now().Before(tracker.circuitUntil)
		tracker.mu.Unlock()
		if open {
			break
		}
		time.Sleep(time.Millisecond)
	}
	tracker.mu.Lock()
	open := time.Now().Before(tracker.circuitUntil)
	tracker.mu.Unlock()
	if !open {
		t.Fatal("Redis error did not open cooldown circuit")
	}
	if allowed, err := tracker.Observe(context.Background(), store, false, "user", "192.0.2.2", 1, 2, time.Now()); !allowed || err != nil {
		t.Fatalf("circuit fail-open observe: allowed=%v err=%v", allowed, err)
	}
	time.Sleep(20 * time.Millisecond)
	if got := store.calls.Load(); got != 1 {
		t.Fatalf("cooldown made %d remote calls, want 1", got)
	}

	tracker.mu.Lock()
	tracker.circuitUntil = time.Now().Add(-time.Millisecond)
	tracker.mu.Unlock()
	store.allow = func(context.Context, string, string, int) (bool, error) { return false, nil }
	if allowed, err := tracker.Observe(context.Background(), store, false, "user", "192.0.2.2", 1, 2, time.Now()); allowed || err != nil {
		t.Fatalf("unapproved fail-open entry bypassed Redis after recovery: allowed=%v err=%v", allowed, err)
	}
}

func TestDeviceLimiterHonorsFailClosedWhenRedisCannotInitialize(t *testing.T) {
	Init()
	config := &conf.GlobalDeviceLimitConfig{
		Enable:       true,
		RedisNetwork: "unsupported",
		FailClosed:   true,
	}
	limiter := AddLimiter("vless", "node-a", []panel.UserInfo{{
		Id: 1, Uuid: "uuid-a", DeviceLimit: 1,
	}}, nil, config, "https://panel.example")
	defer DeleteLimiter("node-a")

	if _, rejected := limiter.CheckLimit(
		context.Background(), format.UserTag("node-a", "uuid-a"), "192.0.2.10",
	); !rejected {
		t.Fatal("FailClosed=true allowed a device-limited session without Redis")
	}
}

func BenchmarkDeviceTrackerSameIP(b *testing.B) {
	tracker := newDeviceTracker(nil)
	now := time.Now()
	if allowed, err := tracker.Observe(context.Background(), nil, false, "user", "192.0.2.1", 1, 1, now); !allowed || err != nil {
		b.Fatalf("seed device: allowed=%v err=%v", allowed, err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if allowed, err := tracker.Observe(context.Background(), nil, false, "user", "192.0.2.1", 1, 1, now); !allowed || err != nil {
			b.Fatal("same device was rejected")
		}
	}
}

func TestDeviceTrackerHandsOverSlotAfterGraceOfSilence(t *testing.T) {
	tracker := newDeviceTracker(nil)
	tracker.ttl = 10 * time.Second
	tracker.grace = 20 * time.Millisecond
	now := time.Now()
	ctx := context.Background()
	if allowed, err := tracker.Observe(ctx, nil, false, "user", "192.0.2.1", 1, 1, now); !allowed || err != nil {
		t.Fatalf("first address: allowed=%v err=%v", allowed, err)
	}
	// Still transmitting, so the slot is genuinely taken.
	if allowed, err := tracker.Observe(ctx, nil, false, "user", "192.0.2.2", 1, 1, now); allowed || err != nil {
		t.Fatalf("second address while the first is active: allowed=%v err=%v", allowed, err)
	}
	// WiFi went down: the old address stops refreshing and the new one takes over
	// well before the TTL would have released it.
	if allowed, err := tracker.Observe(ctx, nil, false, "user", "192.0.2.2", 1, 1, now.Add(30*time.Millisecond)); !allowed || err != nil {
		t.Fatalf("handover after the grace: allowed=%v err=%v", allowed, err)
	}
	online, _ := tracker.Snapshot(now.Add(30 * time.Millisecond))
	if len(online) != 1 || online[0].IP != "192.0.2.2" {
		t.Fatalf("the silent address was not released: %+v", online)
	}
}

func TestDeviceTrackerStillDeniesAConcurrentlyActiveSecondAddress(t *testing.T) {
	tracker := newDeviceTracker(nil)
	tracker.ttl = 10 * time.Second
	tracker.grace = 20 * time.Millisecond
	now := time.Now()
	ctx := context.Background()
	if allowed, err := tracker.Observe(ctx, nil, false, "user", "192.0.2.1", 1, 1, now); !allowed || err != nil {
		t.Fatalf("first address: allowed=%v err=%v", allowed, err)
	}
	// The incumbent keeps moving traffic, which restamps lastSeen past the grace.
	if allowed, err := tracker.Observe(ctx, nil, false, "user", "192.0.2.1", 1, 1, now.Add(25*time.Millisecond)); !allowed || err != nil {
		t.Fatalf("incumbent refresh: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := tracker.Observe(ctx, nil, false, "user", "192.0.2.2", 1, 1, now.Add(30*time.Millisecond)); allowed || err != nil {
		t.Fatalf("sharing must still be refused: allowed=%v err=%v", allowed, err)
	}
}

func TestDeviceTrackerHandoverFreesOnlyTheSilentSlotWhenLimitIsTwo(t *testing.T) {
	tracker := newDeviceTracker(nil)
	tracker.ttl = 10 * time.Second
	tracker.grace = 20 * time.Millisecond
	now := time.Now()
	ctx := context.Background()
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		if allowed, err := tracker.Observe(ctx, nil, false, "user", ip, 1, 2, now); !allowed || err != nil {
			t.Fatalf("address %s: allowed=%v err=%v", ip, allowed, err)
		}
	}
	// .1 keeps transmitting while .2 goes quiet. A third address may take the
	// quiet slot: two addresses are still the most that run at once, which is
	// what the limit of two allows.
	if allowed, err := tracker.Observe(ctx, nil, false, "user", "192.0.2.1", 1, 2, now.Add(25*time.Millisecond)); !allowed || err != nil {
		t.Fatalf("incumbent refresh: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := tracker.Observe(ctx, nil, false, "user", "192.0.2.3", 1, 2, now.Add(30*time.Millisecond)); !allowed || err != nil {
		t.Fatalf("the quiet slot should have been handed over: allowed=%v err=%v", allowed, err)
	}
	online, _ := tracker.Snapshot(now.Add(30 * time.Millisecond))
	if len(online) != 2 {
		t.Fatalf("handover freed the wrong number of slots: %+v", online)
	}
	// The address that was still transmitting kept its slot; the quiet one lost it.
	held := map[string]bool{}
	for _, entry := range online {
		held[entry.IP] = true
	}
	if !held["192.0.2.1"] || !held["192.0.2.3"] || held["192.0.2.2"] {
		t.Fatalf("the wrong address was evicted: %+v", online)
	}
}

func TestDeviceTrackerRefusesAThirdAddressWhileBothSlotsAreActive(t *testing.T) {
	tracker := newDeviceTracker(nil)
	tracker.ttl = 10 * time.Second
	tracker.grace = 20 * time.Millisecond
	now := time.Now()
	ctx := context.Background()
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		if allowed, err := tracker.Observe(ctx, nil, false, "user", ip, 1, 2, now); !allowed || err != nil {
			t.Fatalf("address %s: allowed=%v err=%v", ip, allowed, err)
		}
	}
	// Both keep moving traffic, so neither slot is available and genuine sharing
	// by a third client is still refused.
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		if allowed, err := tracker.Observe(ctx, nil, false, "user", ip, 1, 2, now.Add(25*time.Millisecond)); !allowed || err != nil {
			t.Fatalf("refresh of %s: allowed=%v err=%v", ip, allowed, err)
		}
	}
	if allowed, err := tracker.Observe(ctx, nil, false, "user", "192.0.2.3", 1, 2, now.Add(30*time.Millisecond)); allowed || err != nil {
		t.Fatalf("sharing must still be refused: allowed=%v err=%v", allowed, err)
	}
}

func TestDeviceTrackerHandoverIsDisabledByAZeroGrace(t *testing.T) {
	tracker := newDeviceTracker(nil)
	tracker.ttl = 10 * time.Second
	tracker.grace = 0
	now := time.Now()
	ctx := context.Background()
	if allowed, err := tracker.Observe(ctx, nil, false, "user", "192.0.2.1", 1, 1, now); !allowed || err != nil {
		t.Fatalf("first address: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := tracker.Observe(ctx, nil, false, "user", "192.0.2.2", 1, 1, now.Add(5*time.Second)); allowed || err != nil {
		t.Fatalf("a zero grace must keep the previous refusal: allowed=%v err=%v", allowed, err)
	}
}
