package node

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Duyvj/v3node/conf"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

type deviceSyncEvent struct {
	Version int    `json:"version"`
	APIHost string `json:"api_host"`
	Action  string `json:"action"`
}

// One agent can host many logical nodes. All nodes with identical Redis
// settings share one Pub/Sub connection; each subscriber only keeps a tiny,
// coalescing notification channel. This prevents Redis clients and reconnect
// goroutines from growing linearly with the logical-node count.
type deviceSyncHubKey struct {
	network          string
	addr             string
	username         string
	password         string
	db               int
	timeout          int
	channel          string
	tls              bool
	tlsName          string
	tlsCA            string
	tlsCACertHash    string
	sentinelMaster   string
	sentinelAddrs    string
	sentinelUsername string
	sentinelPassword string
}

type deviceSyncHubEntry struct {
	hub  *deviceSyncHub
	refs int
}

var deviceSyncHubRegistry = struct {
	sync.Mutex
	hubs map[deviceSyncHubKey]*deviceSyncHubEntry
}{hubs: make(map[deviceSyncHubKey]*deviceSyncHubEntry)}

var deviceSyncSubscriberSequence atomic.Uint64

type deviceSyncHub struct {
	client      *redis.Client
	channel     string
	mu          sync.RWMutex
	subscribers map[uint64]*deviceSyncSubscriber
	stop        chan struct{}
	done        chan struct{}
	startOnce   sync.Once
	closeOnce   sync.Once
}

type deviceSyncSubscriber struct {
	apiHost string
	refresh func()
	notify  chan struct{}
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
}

type deviceSyncWatcher struct {
	config    conf.GlobalDeviceLimitConfig
	apiHost   string
	mu        sync.Mutex
	hubKey    deviceSyncHubKey
	id        uint64
	started   bool
	closed    bool
	closeOnce sync.Once
}

func newDeviceSyncWatcher(config *conf.GlobalDeviceLimitConfig, apiHost string) *deviceSyncWatcher {
	if config == nil || !config.Enable || (config.SyncEnabled != nil && !*config.SyncEnabled) {
		return nil
	}
	cloned := *config
	applyDeviceSyncDefaults(&cloned)
	return &deviceSyncWatcher{
		config:  cloned,
		apiHost: normalizeDeviceSyncAPIHost(apiHost),
	}
}

func applyDeviceSyncDefaults(config *conf.GlobalDeviceLimitConfig) {
	if config.RedisNetwork == "" {
		config.RedisNetwork = "tcp"
	}
	if config.RedisAddr == "" {
		config.RedisAddr = "127.0.0.1:6379"
	}
	if config.Timeout <= 0 {
		config.Timeout = 2
	}
	if config.SyncChannel == "" {
		config.SyncChannel = "v2board:device-sync"
	}
}

func deviceSyncKey(config *conf.GlobalDeviceLimitConfig) deviceSyncHubKey {
	return deviceSyncHubKey{
		network:          config.RedisNetwork,
		addr:             config.RedisAddr,
		username:         config.RedisUsername,
		password:         config.RedisPassword,
		db:               config.RedisDB,
		timeout:          config.Timeout,
		channel:          config.SyncChannel,
		tls:              config.RedisTLS,
		tlsName:          config.RedisTLSServerName,
		tlsCA:            config.RedisTLSCAFile,
		tlsCACertHash:    fmt.Sprintf("%x", sha256.Sum256([]byte(config.RedisTLSCACert))),
		sentinelMaster:   config.RedisSentinelMaster,
		sentinelAddrs:    strings.Join(config.RedisSentinelAddrs, ","),
		sentinelUsername: config.RedisSentinelUsername,
		sentinelPassword: config.RedisSentinelPassword,
	}
}

func newDeviceSyncHub(config *conf.GlobalDeviceLimitConfig) (*deviceSyncHub, error) {
	tlsConfig, err := conf.RedisTLSConfig(config)
	if err != nil {
		return nil, err
	}
	var client *redis.Client
	if strings.TrimSpace(config.RedisSentinelMaster) != "" && len(config.RedisSentinelAddrs) > 0 {
		client = redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:       config.RedisSentinelMaster,
			SentinelAddrs:    append([]string(nil), config.RedisSentinelAddrs...),
			SentinelUsername: config.RedisSentinelUsername,
			SentinelPassword: config.RedisSentinelPassword,
			Username:         config.RedisUsername,
			Password:         config.RedisPassword,
			DB:               config.RedisDB,
			PoolSize:         1,
			DialTimeout:      time.Duration(config.Timeout) * time.Second,
			ReadTimeout:      time.Duration(config.Timeout) * time.Second,
			WriteTimeout:     time.Duration(config.Timeout) * time.Second,
			TLSConfig:        tlsConfig,
		})
	} else {
		client = redis.NewClient(&redis.Options{
			Network:      config.RedisNetwork,
			Addr:         config.RedisAddr,
			Username:     config.RedisUsername,
			Password:     config.RedisPassword,
			DB:           config.RedisDB,
			PoolSize:     1,
			DialTimeout:  time.Duration(config.Timeout) * time.Second,
			ReadTimeout:  time.Duration(config.Timeout) * time.Second,
			WriteTimeout: time.Duration(config.Timeout) * time.Second,
			TLSConfig:    tlsConfig,
		})
	}
	return &deviceSyncHub{
		client:      client,
		channel:     config.SyncChannel,
		subscribers: make(map[uint64]*deviceSyncSubscriber),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
	}, nil
}

func acquireDeviceSyncHub(config *conf.GlobalDeviceLimitConfig) (*deviceSyncHub, deviceSyncHubKey, error) {
	key := deviceSyncKey(config)
	deviceSyncHubRegistry.Lock()
	if entry := deviceSyncHubRegistry.hubs[key]; entry != nil {
		entry.refs++
		deviceSyncHubRegistry.Unlock()
		return entry.hub, key, nil
	}
	hub, err := newDeviceSyncHub(config)
	if err != nil {
		deviceSyncHubRegistry.Unlock()
		return nil, deviceSyncHubKey{}, err
	}
	deviceSyncHubRegistry.hubs[key] = &deviceSyncHubEntry{hub: hub, refs: 1}
	deviceSyncHubRegistry.Unlock()
	return hub, key, nil
}

func releaseDeviceSyncHub(key deviceSyncHubKey) {
	deviceSyncHubRegistry.Lock()
	entry := deviceSyncHubRegistry.hubs[key]
	if entry == nil {
		deviceSyncHubRegistry.Unlock()
		return
	}
	entry.refs--
	if entry.refs > 0 {
		deviceSyncHubRegistry.Unlock()
		return
	}
	delete(deviceSyncHubRegistry.hubs, key)
	deviceSyncHubRegistry.Unlock()
	entry.hub.Close()
}

func (w *deviceSyncWatcher) Start(apiHost string, refresh func()) error {
	if w == nil || refresh == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started || w.closed {
		return nil
	}
	host := normalizeDeviceSyncAPIHost(apiHost)
	if host == "" {
		host = w.apiHost
	}
	hub, key, err := acquireDeviceSyncHub(&w.config)
	if err != nil {
		return err
	}
	w.hubKey = key
	w.id = hub.addSubscriber(host, refresh)
	hub.Start()
	w.started = true
	return nil
}

func (h *deviceSyncHub) Start() {
	h.startOnce.Do(func() { go h.run() })
}

func (w *deviceSyncWatcher) Close() {
	if w == nil {
		return
	}
	w.closeOnce.Do(func() {
		w.mu.Lock()
		w.closed = true
		started := w.started
		key := w.hubKey
		id := w.id
		w.mu.Unlock()
		if !started {
			return
		}
		deviceSyncHubRegistry.Lock()
		entry := deviceSyncHubRegistry.hubs[key]
		deviceSyncHubRegistry.Unlock()
		if entry != nil {
			entry.hub.removeSubscriber(id)
		}
		releaseDeviceSyncHub(key)
	})
}

func (h *deviceSyncHub) addSubscriber(apiHost string, refresh func()) uint64 {
	id := deviceSyncSubscriberSequence.Add(1)
	subscriber := &deviceSyncSubscriber{
		apiHost: normalizeDeviceSyncAPIHost(apiHost),
		refresh: refresh,
		notify:  make(chan struct{}, 1),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	h.mu.Lock()
	h.subscribers[id] = subscriber
	h.mu.Unlock()
	go subscriber.run()
	return id
}

func (h *deviceSyncHub) removeSubscriber(id uint64) {
	h.mu.Lock()
	subscriber := h.subscribers[id]
	delete(h.subscribers, id)
	h.mu.Unlock()
	if subscriber != nil {
		subscriber.Close()
	}
}

func (s *deviceSyncSubscriber) run() {
	defer close(s.done)
	for {
		select {
		case <-s.notify:
			select {
			case <-s.stop:
				return
			default:
			}
			s.refresh()
		case <-s.stop:
			return
		}
	}
}

func (s *deviceSyncSubscriber) signal() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

func (s *deviceSyncSubscriber) Close() {
	s.once.Do(func() {
		close(s.stop)
		select {
		case <-s.done:
		case <-time.After(5 * time.Second):
			log.Warn("device sync subscriber did not stop before timeout")
		}
	})
}

func (h *deviceSyncHub) run() {
	defer close(h.done)
	backoff := time.Second
	for {
		select {
		case <-h.stop:
			return
		default:
		}

		ctx, cancel := context.WithCancel(context.Background())
		pubsub := h.client.Subscribe(ctx, h.channel)
		_, err := pubsub.Receive(ctx)
		if err != nil {
			_ = pubsub.Close()
			cancel()
			if !h.wait(backoff) {
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		messages := pubsub.Channel(redis.WithChannelSize(16))
		connected := true
		for connected {
			select {
			case <-h.stop:
				connected = false
			case message, ok := <-messages:
				if !ok {
					connected = false
					continue
				}
				h.dispatch(message.Payload)
			}
		}
		_ = pubsub.Close()
		cancel()
		if !h.wait(backoff) {
			return
		}
	}
}

func (h *deviceSyncHub) dispatch(payload string) {
	var event deviceSyncEvent
	if json.Unmarshal([]byte(payload), &event) != nil {
		return
	}
	eventHost := normalizeDeviceSyncAPIHost(event.APIHost)
	h.mu.RLock()
	subscribers := make([]*deviceSyncSubscriber, 0, len(h.subscribers))
	for _, subscriber := range h.subscribers {
		if eventHost == "" || subscriber.apiHost == eventHost {
			subscribers = append(subscribers, subscriber)
		}
	}
	h.mu.RUnlock()
	for _, subscriber := range subscribers {
		subscriber.signal()
	}
}

func normalizeDeviceSyncAPIHost(value string) string {
	return strings.TrimRight(strings.TrimSpace(value), "/")
}

func (h *deviceSyncHub) wait(duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-h.stop:
		return false
	}
}

func (h *deviceSyncHub) Close() {
	if h == nil {
		return
	}
	h.closeOnce.Do(func() {
		close(h.stop)
		_ = h.client.Close()
		h.startOnce.Do(func() { close(h.done) })
		select {
		case <-h.done:
		case <-time.After(5 * time.Second):
			log.Warn("shared device sync hub did not stop before timeout")
		}
	})
}
