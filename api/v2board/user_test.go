package panel

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Duyvj/v3node/conf"
	"github.com/vmihailenco/msgpack/v5"
)

func TestAggregateUserTrafficWithMultipleUUIDsSharingUID(t *testing.T) {
	got := aggregateUserTraffic([]UserTraffic{
		{UID: 7, Upload: 100, Download: 200},
		{UID: 7, Upload: 30, Download: 40},
		{UID: 8, Upload: 5, Download: 6},
	})

	if got[7][0] != 130 || got[7][1] != 240 {
		t.Fatalf("shared UID traffic was overwritten instead of aggregated: %#v", got[7])
	}
	if got[8][0] != 5 || got[8][1] != 6 {
		t.Fatalf("independent UID traffic changed unexpectedly: %#v", got[8])
	}
}

func TestUserListValidationRejectsDuplicateCredentialsAndInvalidLimits(t *testing.T) {
	if err := validateUserList([]UserInfo{
		{Id: 1, Uuid: "same", DeviceLimit: 1},
		{Id: 2, Uuid: "same", DeviceLimit: 1},
	}); err == nil {
		t.Fatal("duplicate node credential was accepted")
	}
	if err := validateUserList([]UserInfo{{Id: 1, Uuid: "valid", DeviceLimit: -1}}); err == nil {
		t.Fatal("negative device limit was accepted")
	}
	if err := validateUserList([]UserInfo{{Id: 1, Uuid: "valid", DeviceLimit: 1}}); err != nil {
		t.Fatalf("valid user rejected: %v", err)
	}
}

func TestUserRevisionAcceptsOnlyTheAuthenticatedHexMarker(t *testing.T) {
	const revision = "0123456789abcdef0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != userRevisionPath {
			t.Errorf("unexpected revision path %q", request.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"revision":"` + revision + `"}`))
	}))
	defer server.Close()

	client, err := New(&conf.NodeConfig{
		APIHost: server.URL, NodeID: 2, Key: "agent-token", AgentID: "agent-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.GetUserRevision(context.Background())
	if err != nil || got != revision {
		t.Fatalf("revision=%q err=%v, want %q", got, err, revision)
	}
}

func TestRedisPrimaryStillChecksPanelRevisionForAuthorization(t *testing.T) {
	const revision = "0123456789abcdef0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != userRevisionPath {
			t.Fatalf("unexpected revision path %q", request.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"revision":"` + revision + `"}`))
	}))
	defer server.Close()
	client, err := New(&conf.NodeConfig{
		APIHost: server.URL, NodeID: 2, Key: "agent-token", AgentID: "agent-a",
		GlobalDeviceLimitConfig: &conf.GlobalDeviceLimitConfig{UserSourceMode: "redis_primary"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := client.GetUserRevision(context.Background()); err != nil || got != revision {
		t.Fatalf("redis-primary revision=%q err=%v, want authenticated marker", got, err)
	}
}

func TestRedisPrimaryDoesNotBypassPanelAuthorizationFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == userRevisionPath {
			http.Error(w, "revoked", http.StatusUnauthorized)
			return
		}
		http.NotFound(w, request)
	}))
	defer server.Close()
	client, err := New(&conf.NodeConfig{
		APIHost: server.URL, NodeID: 2, Key: "agent-token", AgentID: "agent-a",
		GlobalDeviceLimitConfig: &conf.GlobalDeviceLimitConfig{UserSourceMode: "redis_primary"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetUserList(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("Redis-primary bypassed revoked panel credentials: %v", err)
	}
}

func TestUserRevisionRejectsMalformedSuccessfulResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"revision":"not-a-revision"}`))
	}))
	defer server.Close()

	client, err := New(&conf.NodeConfig{
		APIHost: server.URL, NodeID: 2, Key: "agent-token", AgentID: "agent-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetUserRevision(context.Background()); err == nil {
		t.Fatal("malformed revision response was accepted")
	}
}

func TestUserListNotModifiedReplaysLastCompleteDesiredState(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", `"users-v2"`)
			_, _ = w.Write([]byte(`{"users":[{"id":7,"uuid":"credential","speed_limit":0,"device_limit":1}]}`))
			return
		}
		if got := request.Header.Get("If-None-Match"); got != `"users-v2"` {
			t.Errorf("If-None-Match = %q, want committed validator", got)
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	client, err := New(&conf.NodeConfig{
		APIHost: server.URL, NodeID: 2, Key: "agent-token", AgentID: "agent-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.GetUserList(context.Background())
	if err != nil || len(first) != 1 {
		t.Fatalf("initial user snapshot failed: users=%#v err=%v", first, err)
	}
	// Simulate a controller failure after the successful fetch. The next 304
	// must replay the desired snapshot so reconciliation can be retried.
	second, err := client.GetUserList(context.Background())
	if err != nil || len(second) != 1 || second[0].Uuid != "credential" {
		t.Fatalf("304 lost the pending desired snapshot: users=%#v err=%v", second, err)
	}
}

func TestMsgpackUserListRejectsDeclaredOversizedArrayBeforeAllocation(t *testing.T) {
	// map(1), "users", array32(max uint32). The decoder must inspect and
	// reject the declared count before allocating the slice.
	payload := []byte{0x81, 0xa5, 'u', 's', 'e', 'r', 's', 0xdd, 0xff, 0xff, 0xff, 0xff}
	if _, err := decodeMsgpackUserList(msgpack.NewDecoder(bytes.NewReader(payload))); err == nil {
		t.Fatal("oversized msgpack user array was accepted")
	}
}

func TestStreamingUserListDecodersRejectNestedDuplicateAndTrailingData(t *testing.T) {
	valid := `{"meta":{"version":2},"users":[{"id":1,"uuid":"credential","speed_limit":0,"device_limit":1}]}`
	users, err := decodeJSONUserList(jsontext.NewDecoder(strings.NewReader(valid)))
	if err != nil || len(users) != 1 || users[0].Id != 1 {
		t.Fatalf("valid streaming JSON user list failed: users=%#v err=%v", users, err)
	}
	for name, payload := range map[string]string{
		"nested":    `{"outer":{"users":[]}}`,
		"duplicate": `{"users":[],"users":[]}`,
		"trailing":  `{"users":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeJSONUserList(jsontext.NewDecoder(strings.NewReader(payload))); err == nil {
				t.Fatal("malformed JSON user list was accepted")
			}
		})
	}

	msgpackPayload, err := msgpack.Marshal(map[string]any{"users": []UserInfo{}})
	if err != nil {
		t.Fatal(err)
	}
	msgpackPayload = append(msgpackPayload, 0x80)
	if _, err := decodeMsgpackUserList(msgpack.NewDecoder(bytes.NewReader(msgpackPayload))); err == nil {
		t.Fatal("trailing msgpack object was accepted")
	}
}

func TestTrafficReportUsesStableIdempotencyHeaderAndRejectsHTTPFailure(t *testing.T) {
	const reportID = "0123456789abcdef0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if advertiseTrafficProtocol2(w, request) {
			return
		}
		if got := request.Header.Get("X-ZNode-Traffic-Report-ID"); got != reportID {
			t.Errorf("traffic report id = %q, want %q", got, reportID)
		}
		if got := request.Header.Get("X-ZNode-Traffic-Protocol"); got != "2" {
			t.Errorf("traffic protocol = %q, want 2", got)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client, err := New(&conf.NodeConfig{
		APIHost: server.URL, NodeID: 2, Key: "agent-token", AgentID: "agent-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ReportUserTraffic(context.Background(), reportID, []UserTraffic{{UID: 7, Upload: 1}}); err == nil {
		t.Fatal("expected a panel HTTP failure to keep the traffic batch pending")
	}
}

func TestTrafficReportAcceptsLegacyPanel(t *testing.T) {
	const reportID = "0123456789abcdef0123456789abcdef"
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == trafficCapabilityPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if request.Method == http.MethodPost && request.URL.Path == "/api/v1/server/UniProxy/push" {
			posts++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, err := New(&conf.NodeConfig{APIHost: server.URL, NodeID: 2, Key: "agent-token", AgentID: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ReportUserTraffic(context.Background(), reportID, []UserTraffic{{UID: 7, Upload: 1}}); err != nil {
		t.Fatalf("legacy panel should be accepted, got: %v", err)
	}
	if posts != 1 {
		t.Fatalf("got %d traffic posts, want 1", posts)
	}
}

func TestTrafficReportPostsOnlyAfterProtocol2CapabilityAndExactAck(t *testing.T) {
	const reportID = "0123456789abcdef0123456789abcdef"
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if advertiseTrafficProtocol2(w, request) {
			return
		}
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/server/UniProxy/push" {
			t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		posts++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-ZBoard-Traffic-Protocol", "2")
		_, _ = w.Write([]byte(`{"data":true,"report_id":"` + reportID + `"}`))
	}))
	defer server.Close()

	client, err := New(&conf.NodeConfig{APIHost: server.URL, NodeID: 2, Key: "agent-token", AgentID: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ReportUserTraffic(context.Background(), reportID, []UserTraffic{{UID: 7, Upload: 1}}); err != nil {
		t.Fatalf("protocol-2 report failed: %v", err)
	}
	if posts != 1 {
		t.Fatalf("got %d traffic posts, want 1", posts)
	}
}

func TestTrafficReportRejectsMissingIDEchoFromProtocolAwarePanel(t *testing.T) {
	const reportID = "0123456789abcdef0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if advertiseTrafficProtocol2(w, request) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-ZBoard-Traffic-Protocol", "2")
		_, _ = w.Write([]byte("{\"data\":true}"))
	}))
	defer server.Close()

	client, err := New(&conf.NodeConfig{APIHost: server.URL, NodeID: 2, Key: "agent-token", AgentID: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ReportUserTraffic(context.Background(), reportID, []UserTraffic{{UID: 7, Upload: 1}}); err == nil {
		t.Fatal("a protocol-aware panel omitted the immutable report ID")
	}
}

func TestTrafficReportRejectsAnUnrelatedSuccessfulResponse(t *testing.T) {
	const reportID = "0123456789abcdef0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if advertiseTrafficProtocol2(w, request) {
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	client, err := New(&conf.NodeConfig{APIHost: server.URL, NodeID: 2, Key: "agent-token", AgentID: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ReportUserTraffic(context.Background(), reportID, []UserTraffic{{UID: 7, Upload: 1}}); err == nil {
		t.Fatal("a proxy HTML 200 response must not acknowledge traffic")
	}
}

func TestTrafficReportRequiresTheExactReportAcknowledgement(t *testing.T) {
	const reportID = "0123456789abcdef0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if advertiseTrafficProtocol2(w, request) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":true,"report_id":"wrong"}`))
	}))
	defer server.Close()

	client, err := New(&conf.NodeConfig{APIHost: server.URL, NodeID: 2, Key: "agent-token", AgentID: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ReportUserTraffic(context.Background(), reportID, []UserTraffic{{UID: 7, Upload: 1}}); err == nil {
		t.Fatal("an acknowledgement for another report must be rejected")
	}
}

func advertiseTrafficProtocol2(w http.ResponseWriter, request *http.Request) bool {
	if request.Method != http.MethodGet || request.URL.Path != trafficCapabilityPath {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-ZBoard-Traffic-Protocol", "2")
	_, _ = w.Write([]byte(`{"data":{"traffic_protocol":2}}`))
	return true
}

func TestOnlineReportRejectsHTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client, err := New(&conf.NodeConfig{
		APIHost: server.URL, NodeID: 2, Key: "agent-token", AgentID: "agent-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	data := map[int][]string{7: {"203.0.113.7"}}
	if err := client.ReportNodeOnlineUsers(context.Background(), &data); err == nil {
		t.Fatal("expected a panel HTTP failure")
	}
}

func TestAliveListFailureDoesNotPublishAnEmptyFallback(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"http failure": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		},
		"malformed body": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"alive":`))
		},
		"invalid count": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"alive":{"7":-1}}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			client, err := New(&conf.NodeConfig{
				APIHost: server.URL, NodeID: 2, Key: "agent-token", AgentID: "agent-a",
			})
			if err != nil {
				t.Fatal(err)
			}
			previous := map[int]int{7: 2}
			client.AliveMap = &AliveMap{Alive: previous}
			if _, err := client.GetUserAlive(context.Background()); err == nil {
				t.Fatal("unsafe alive-list response was accepted")
			}
			if client.AliveMap.Alive[7] != 2 {
				t.Fatalf("last known fallback was erased: %#v", client.AliveMap.Alive)
			}
		})
	}
}
