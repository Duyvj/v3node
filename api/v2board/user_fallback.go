package panel

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"encoding/json/v2"

	"github.com/Duyvj/v3node/conf"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

const maxFallbackEnvelopeBytes = 96 << 20

type signedUserSnapshotEnvelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type fallbackUserSnapshot struct {
	Version     int        `json:"version"`
	PanelHash   string     `json:"panel_hash"`
	NodeIDs     []int      `json:"node_ids"`
	GeneratedAt int64      `json:"generated_at"`
	Users       []UserInfo `json:"users"`
}

func (c *Client) getFallbackUserList(ctx context.Context) ([]UserInfo, error) {
	c.fallbackMu.Lock()
	defer c.fallbackMu.Unlock()
	config := cloneGlobalDeviceLimitConfig(c.fallbackConfig)
	if config == nil || !config.UserFallbackEnabled {
		return nil, fmt.Errorf("user fallback is disabled")
	}
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
	defer client.Close()

	requestCtx, cancel := context.WithTimeout(ctx, time.Duration(max(config.Timeout, 1))*time.Second)
	defer cancel()
	panelDigest := sha256.Sum256([]byte(c.APIHost))
	panelHash := hex.EncodeToString(panelDigest[:16])
	prefix := strings.TrimRight(strings.TrimSpace(config.UserSnapshotPrefix), ":")
	if prefix == "" || strings.ContainsAny(prefix, " \t\r\n") {
		return nil, fmt.Errorf("snapshot key prefix is invalid")
	}
	key := prefix + ":" + panelHash + ":" + strconv.Itoa(c.NodeId)
	raw, err := client.Get(requestCtx, key).Bytes()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", key, err)
	}
	users, age, err := decodeFallbackUserSnapshot(raw, c.Token, panelHash, c.NodeId, config.UserSnapshotMaxAge, time.Now())
	if err != nil {
		return nil, err
	}
	log.WithFields(log.Fields{
		"node_id": c.NodeId,
		"age":     age,
	}).Warn("Panel unavailable; using authenticated Redis user snapshot")
	return users, nil
}

func decodeFallbackUserSnapshot(raw []byte, token, panelHash string, nodeID, maxAge int, now time.Time) ([]UserInfo, int64, error) {
	if len(raw) == 0 || len(raw) > maxFallbackEnvelopeBytes {
		return nil, 0, fmt.Errorf("snapshot envelope size is invalid")
	}
	var envelope signedUserSnapshotEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, 0, fmt.Errorf("decode snapshot envelope: %w", err)
	}
	providedSignature, err := hex.DecodeString(envelope.Signature)
	if err != nil || len(providedSignature) != sha256.Size {
		return nil, 0, fmt.Errorf("snapshot signature is invalid")
	}
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write([]byte(envelope.Payload))
	if !hmac.Equal(providedSignature, mac.Sum(nil)) {
		return nil, 0, fmt.Errorf("snapshot authentication failed")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || len(payload) == 0 || int64(len(payload)) > maxPanelUserResponseBytes {
		return nil, 0, fmt.Errorf("snapshot payload is invalid")
	}
	var snapshot fallbackUserSnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return nil, 0, fmt.Errorf("decode snapshot payload: %w", err)
	}
	if snapshot.Version != 1 || snapshot.PanelHash != panelHash || !containsNodeID(snapshot.NodeIDs, nodeID) {
		return nil, 0, fmt.Errorf("snapshot identity does not match this panel node")
	}
	nowUnix := now.Unix()
	if snapshot.GeneratedAt <= 0 || snapshot.GeneratedAt > nowUnix+300 || nowUnix-snapshot.GeneratedAt > int64(maxAge) {
		return nil, 0, fmt.Errorf("snapshot is stale")
	}
	if err := validateUserList(snapshot.Users); err != nil {
		return nil, 0, err
	}
	return cloneUserList(snapshot.Users), nowUnix - snapshot.GeneratedAt, nil
}

func containsNodeID(ids []int, expected int) bool {
	if len(ids) == 0 || len(ids) > 10000 {
		return false
	}
	for _, id := range ids {
		if id == expected {
			return true
		}
	}
	return false
}
