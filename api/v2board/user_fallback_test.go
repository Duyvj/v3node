package panel

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"encoding/json/v2"

	"github.com/Duyvj/v3node/conf"
)

func TestSignedRedisUserSnapshotValidation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	payload, err := json.Marshal(fallbackUserSnapshot{
		Version: 1, PanelHash: "0123456789abcdef0123456789abcdef",
		NodeIDs: []int{7, 9}, GeneratedAt: now.Unix() - 15,
		Users: []UserInfo{{Id: 1, Uuid: "uuid-a", DeviceLimit: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte("agent-secret"))
	_, _ = mac.Write([]byte(encoded))
	raw, err := json.Marshal(signedUserSnapshotEnvelope{
		Payload: encoded, Signature: hex.EncodeToString(mac.Sum(nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	users, age, err := decodeFallbackUserSnapshot(raw, "agent-secret", "0123456789abcdef0123456789abcdef", 7, 3600, now)
	if err != nil || len(users) != 1 || users[0].Uuid != "uuid-a" || age != 15 {
		t.Fatalf("valid snapshot rejected: users=%+v age=%d err=%v", users, age, err)
	}
	if _, _, err := decodeFallbackUserSnapshot(raw, "wrong-secret", "0123456789abcdef0123456789abcdef", 7, 3600, now); err == nil {
		t.Fatal("snapshot with the wrong Agent token was accepted")
	}
	if _, _, err := decodeFallbackUserSnapshot(raw, "agent-secret", "different-panel", 7, 3600, now); err == nil {
		t.Fatal("snapshot from another panel was accepted")
	}
	if _, _, err := decodeFallbackUserSnapshot(raw, "agent-secret", "0123456789abcdef0123456789abcdef", 8, 3600, now); err == nil {
		t.Fatal("snapshot for another node was accepted")
	}
	if _, _, err := decodeFallbackUserSnapshot(raw, "agent-secret", "0123456789abcdef0123456789abcdef", 7, 10, now); err == nil {
		t.Fatal("stale snapshot was accepted")
	}
}

func TestWebUserListAlwaysWinsOverRedisFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"web-user","device_limit":1}]}`))
	}))
	defer server.Close()
	client, err := New(&conf.NodeConfig{
		APIHost: server.URL, NodeID: 7, Key: "agent-secret", AgentID: "agent-1",
		GlobalDeviceLimitConfig: &conf.GlobalDeviceLimitConfig{
			RedisNetwork: "unsupported", UserFallbackEnabled: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	users, err := client.GetUserList(context.Background())
	if err != nil || len(users) != 1 || users[0].Uuid != "web-user" {
		t.Fatalf("web source did not remain authoritative: users=%+v err=%v", users, err)
	}
}

func TestRedisPrimaryFallsBackToLiveWebWhenSnapshotIsUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"web-fallback","device_limit":1}]}`))
	}))
	defer server.Close()
	client, err := New(&conf.NodeConfig{
		APIHost: server.URL, NodeID: 7, Key: "agent-secret", AgentID: "agent-1",
		GlobalDeviceLimitConfig: &conf.GlobalDeviceLimitConfig{
			RedisNetwork: "unsupported", UserFallbackEnabled: true, UserSourceMode: "redis_primary",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	users, err := client.GetUserList(context.Background())
	if err != nil || len(users) != 1 || users[0].Uuid != "web-fallback" {
		t.Fatalf("live Web fallback failed in Redis-primary mode: users=%+v err=%v", users, err)
	}
}

func TestAuthorizationFailureNeverFallsBackToRedis(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "revoked", http.StatusUnauthorized)
	}))
	defer server.Close()
	client, err := New(&conf.NodeConfig{
		APIHost: server.URL, NodeID: 7, Key: "agent-secret", AgentID: "agent-1",
		GlobalDeviceLimitConfig: &conf.GlobalDeviceLimitConfig{
			RedisNetwork: "unsupported", UserFallbackEnabled: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetUserList(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") || strings.Contains(err.Error(), "fallback") {
		t.Fatalf("authorization failure used Redis fallback: %v", err)
	}
}

func TestHealthyZBoardControlPlaneSuppressesRedisFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case agentManifestPath:
			_, _ = w.Write([]byte(`{"panel_type":"zboard","revision":"manifest-1","nodes":[7],"poll_interval":15}`))
		case "/api/v1/server/UniProxy/user":
			http.Error(w, "temporary node API failure", http.StatusInternalServerError)
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	agentConfig := conf.AgentConfig{
		Enable: true, APIHost: server.URL, AgentID: "agent-healthy", AgentToken: "agent-secret",
	}
	agentClient, err := NewAgentClient(agentConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agentClient.GetManifest(context.Background()); err != nil {
		t.Fatal(err)
	}
	client, err := New(&conf.NodeConfig{
		APIHost: server.URL, NodeID: 7, Key: "agent-secret", AgentID: "agent-healthy",
		GlobalDeviceLimitConfig: &conf.GlobalDeviceLimitConfig{
			RedisNetwork: "unsupported", UserFallbackEnabled: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetUserList(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Redis fallback suppressed") || strings.Contains(err.Error(), "signed Redis fallback unavailable") {
		t.Fatalf("healthy ZBoard unexpectedly used Redis fallback: %v", err)
	}
}

func TestUnavailableZBoardStillAttemptsRedisFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "panel unavailable", http.StatusBadGateway)
	}))
	defer server.Close()
	client, err := New(&conf.NodeConfig{
		APIHost: server.URL, NodeID: 8, Key: "agent-secret", AgentID: "agent-offline",
		GlobalDeviceLimitConfig: &conf.GlobalDeviceLimitConfig{
			RedisNetwork: "unsupported", UserFallbackEnabled: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetUserList(context.Background())
	if err == nil || !strings.Contains(err.Error(), "signed Redis fallback unavailable") {
		t.Fatalf("offline ZBoard did not attempt Redis fallback: %v", err)
	}
}
