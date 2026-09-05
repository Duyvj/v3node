package limiter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Duyvj/v3node/common/format"
	"github.com/Duyvj/v3node/conf"
	"github.com/redis/go-redis/v9"
)

// The Lua script makes remove-expired, capacity-check, touch and TTL refresh
// one atomic Redis operation. A plain GET/SET pair is subject to a race when
// two znode instances accept a new IP at the same time.
const deviceLimitScript = `
local key = KEYS[1]
local member = ARGV[1]
local limit = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local expiry = tonumber(ARGV[4])
local grace = tonumber(ARGV[5])
local cutoff = now - (expiry * 1000)
redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
if redis.call('ZSCORE', key, member) then
  redis.call('ZADD', key, now, member)
  redis.call('EXPIRE', key, expiry)
  return {1, redis.call('ZCARD', key), 0}
end
local count = redis.call('ZCARD', key)
local handover = 0
if limit > 0 and count >= limit then
  if grace <= 0 then
    return {0, count, 0}
  end
  -- Free exactly as many slots as this admission needs, least recently seen
  -- first. ZRANGE is ascending by score, so these are the oldest touches and
  -- no others are considered. An address still inside the grace window is
  -- transmitting, so a set that is only partly idle refuses the newcomer.
  local needed = count - limit + 1
  local silent = now - (grace * 1000)
  local candidates = redis.call('ZRANGE', key, 0, needed - 1, 'WITHSCORES')
  local evict = {}
  for i = 1, #candidates, 2 do
    if tonumber(candidates[i + 1]) <= silent then
      evict[#evict + 1] = candidates[i]
    end
  end
  if #evict < needed then
    return {0, count, 0}
  end
  redis.call('ZREM', key, unpack(evict))
  handover = #evict
end
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, expiry)
return {1, redis.call('ZCARD', key), handover}
`

type redisDeviceStore struct {
	client    *redis.Client
	clientKey redisClientKey
	script    *redis.Script
	prefix    string
	namespace string
	timeout   time.Duration
	expiry    time.Duration
	grace     time.Duration
	closeOnce sync.Once
}

type redisClientKey struct {
	network          string
	addr             string
	username         string
	password         string
	db               int
	timeout          int
	tls              bool
	tlsName          string
	tlsCA            string
	tlsCACertHash    string
	sentinelMaster   string
	sentinelAddrs    string
	sentinelUsername string
	sentinelPassword string
}

type sharedRedisClient struct {
	client *redis.Client
	refs   int
}

var redisClientRegistry = struct {
	sync.Mutex
	clients map[redisClientKey]*sharedRedisClient
}{clients: make(map[redisClientKey]*sharedRedisClient)}

func acquireRedisClient(c *conf.GlobalDeviceLimitConfig) (*redis.Client, redisClientKey, error) {
	tlsConfig, err := conf.RedisTLSConfig(c)
	if err != nil {
		return nil, redisClientKey{}, err
	}
	key := redisClientKey{
		network:          c.RedisNetwork,
		addr:             c.RedisAddr,
		username:         c.RedisUsername,
		password:         c.RedisPassword,
		db:               c.RedisDB,
		timeout:          c.Timeout,
		tls:              c.RedisTLS,
		tlsName:          c.RedisTLSServerName,
		tlsCA:            c.RedisTLSCAFile,
		tlsCACertHash:    fmt.Sprintf("%x", sha256.Sum256([]byte(c.RedisTLSCACert))),
		sentinelMaster:   c.RedisSentinelMaster,
		sentinelAddrs:    strings.Join(c.RedisSentinelAddrs, ","),
		sentinelUsername: c.RedisSentinelUsername,
		sentinelPassword: c.RedisSentinelPassword,
	}
	redisClientRegistry.Lock()
	defer redisClientRegistry.Unlock()
	if shared := redisClientRegistry.clients[key]; shared != nil {
		shared.refs++
		return shared.client, key, nil
	}
	var client *redis.Client
	if strings.TrimSpace(c.RedisSentinelMaster) != "" && len(c.RedisSentinelAddrs) > 0 {
		client = redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:       c.RedisSentinelMaster,
			SentinelAddrs:    append([]string(nil), c.RedisSentinelAddrs...),
			SentinelUsername: c.RedisSentinelUsername,
			SentinelPassword: c.RedisSentinelPassword,
			Username:         c.RedisUsername,
			Password:         c.RedisPassword,
			DB:               c.RedisDB,
			PoolSize:         4,
			MinIdleConns:     0,
			DialTimeout:      time.Duration(c.Timeout) * time.Second,
			ReadTimeout:      time.Duration(c.Timeout) * time.Second,
			WriteTimeout:     time.Duration(c.Timeout) * time.Second,
			TLSConfig:        tlsConfig,
		})
	} else {
		client = redis.NewClient(&redis.Options{
			Network:      c.RedisNetwork,
			Addr:         c.RedisAddr,
			Username:     c.RedisUsername,
			Password:     c.RedisPassword,
			DB:           c.RedisDB,
			PoolSize:     4,
			MinIdleConns: 0,
			DialTimeout:  time.Duration(c.Timeout) * time.Second,
			ReadTimeout:  time.Duration(c.Timeout) * time.Second,
			WriteTimeout: time.Duration(c.Timeout) * time.Second,
			TLSConfig:    tlsConfig,
		})
	}
	redisClientRegistry.clients[key] = &sharedRedisClient{client: client, refs: 1}
	return client, key, nil
}

func releaseRedisClient(key redisClientKey) error {
	redisClientRegistry.Lock()
	shared := redisClientRegistry.clients[key]
	if shared == nil {
		redisClientRegistry.Unlock()
		return nil
	}
	shared.refs--
	if shared.refs > 0 {
		redisClientRegistry.Unlock()
		return nil
	}
	delete(redisClientRegistry.clients, key)
	redisClientRegistry.Unlock()
	return shared.client.Close()
}

func newRedisDeviceStore(c *conf.GlobalDeviceLimitConfig, namespace string) (*redisDeviceStore, error) {
	if c == nil || !c.Enable {
		return nil, nil
	}
	applyDeviceDefaults(c)
	if c.RedisNetwork != "tcp" && c.RedisNetwork != "unix" {
		return nil, fmt.Errorf("unsupported Redis network %q", c.RedisNetwork)
	}
	client, clientKey, err := acquireRedisClient(c)
	if err != nil {
		return nil, err
	}
	return &redisDeviceStore{
		client:    client,
		clientKey: clientKey,
		script:    redis.NewScript(deviceLimitScript),
		prefix:    strings.TrimRight(c.KeyPrefix, ":"),
		namespace: strings.TrimRight(namespace, "/"),
		timeout:   time.Duration(c.Timeout) * time.Second,
		expiry:    time.Duration(c.Expiry) * time.Second,
		// applyDeviceDefaults ran above, so the pointer is set.
		grace:     time.Duration(*c.HandoverGrace) * time.Second,
	}, nil
}

func (r *redisDeviceStore) key(userKey string) string {
	nsHash := sha256.Sum256([]byte(r.namespace))
	userHash := format.UserCredentialDigest(userKey)
	return fmt.Sprintf("%s:%s:%s", r.prefix, hex.EncodeToString(nsHash[:8]), hex.EncodeToString(userHash[:16]))
}

func (r *redisDeviceStore) Allow(ctx context.Context, userKey, ip string, limit int) (bool, error) {
	if r == nil || limit <= 0 {
		return true, nil
	}
	requestCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	now := time.Now().UnixMilli()
	result, err := r.script.Run(requestCtx, r.client, []string{r.key(userKey)}, ip, strconv.Itoa(limit), strconv.FormatInt(now, 10), strconv.FormatInt(int64(r.expiry/time.Second), 10), strconv.FormatInt(int64(r.grace/time.Second), 10)).Int64Slice()
	if err != nil {
		return false, err
	}
	return len(result) > 0 && result[0] == 1, nil
}

func (r *redisDeviceStore) Delete(ctx context.Context, userKey string) error {
	if r == nil {
		return nil
	}
	requestCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	return r.client.Del(requestCtx, r.key(userKey)).Err()
}

func (r *redisDeviceStore) Close() error {
	if r == nil || r.client == nil {
		return nil
	}
	var err error
	r.closeOnce.Do(func() {
		err = releaseRedisClient(r.clientKey)
	})
	return err
}
