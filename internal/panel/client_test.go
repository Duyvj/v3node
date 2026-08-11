package panel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Duyvj/v3node/internal/model"
)

const validNodeJSON = `{"protocol":"vless","listen_ip":"0.0.0.0","server_port":443,"tls":1,"base_config":{"push_interval":30,"pull_interval":"60"}}`

func TestNewRequiresHTTPSAndConfiguresTLS12(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{BaseURL: "http://panel.example", Token: "token", NodeID: 1}); err == nil {
		t.Fatal("New() accepted HTTP without AllowHTTP")
	}
	client, err := New(Config{BaseURL: "https://panel.example", Token: "token", NodeID: 1})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	transport, ok := client.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T", client.http.Transport)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("TLS minimum is below 1.2")
	}
}

func TestGetNodeConfigContractAndETagCommit(t *testing.T) {
	t.Parallel()
	const secret = "node-secret-token"
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assertPanelQuery(t, request, secret, 17)
		if request.URL.Path != ConfigEndpoint || request.Method != http.MethodGet {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		switch requests.Add(1) {
		case 1:
			if got := request.Header.Get("If-None-Match"); got != "" {
				t.Errorf("first If-None-Match = %q", got)
			}
			writer.Header().Set("ETag", `"invalid-generation"`)
			fmt.Fprintf(writer, `{"protocol":%q,"server_port":443,"tls":0}`, secret)
		case 2:
			if got := request.Header.Get("If-None-Match"); got != "" {
				t.Errorf("invalid response ETag was committed: %q", got)
			}
			writer.Header().Set("ETag", `"valid-generation"`)
			io.WriteString(writer, validNodeJSON)
		case 3:
			if got := request.Header.Get("If-None-Match"); got != `"valid-generation"` {
				t.Errorf("third If-None-Match = %q", got)
			}
			writer.WriteHeader(http.StatusNotModified)
		default:
			t.Error("unexpected extra request")
		}
	}))
	defer server.Close()

	client := mustTestClient(t, server.URL, secret, 17, nil)
	defer client.Close()
	if _, _, err := client.GetNodeConfig(context.Background()); err == nil {
		t.Fatal("invalid node response unexpectedly succeeded")
	} else if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), url.QueryEscape(secret)) {
		t.Fatalf("error exposed token: %q", err)
	}
	node, changed, err := client.GetNodeConfig(context.Background())
	if err != nil || !changed {
		t.Fatalf("second GetNodeConfig() = changed %v, error %v", changed, err)
	}
	if node.Protocol != model.ProtocolVLESS || node.ServerPort != 443 {
		t.Fatalf("node = %+v", node)
	}
	node, changed, err = client.GetNodeConfig(context.Background())
	if err != nil || changed || node != nil {
		t.Fatalf("304 GetNodeConfig() = node %+v, changed %v, error %v", node, changed, err)
	}
}

func TestNotModifiedWithoutCachedETagIsRejected(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()
	client := mustTestClient(t, server.URL, "token", 1, nil)
	if _, _, err := client.GetNodeConfig(context.Background()); err == nil {
		t.Fatal("node HTTP 304 without ETag unexpectedly succeeded")
	}
	if _, _, err := client.GetUsers(context.Background()); err == nil {
		t.Fatal("user HTTP 304 without ETag unexpectedly succeeded")
	}
}

func TestValidatedHTTP200SemanticHashSuppressesUnchangedState(t *testing.T) {
	t.Parallel()
	var nodeRequests atomic.Int32
	var userRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case ConfigEndpoint:
			if nodeRequests.Add(1) == 1 {
				writer.Header().Set("ETag", `"node-a"`)
				io.WriteString(writer, validNodeJSON)
				return
			}
			writer.Header().Set("ETag", `"node-b"`)
			io.WriteString(writer, `{
				"base_config":{"pull_interval":60,"push_interval":"30"},
				"tls":1,"server_port":443,"listen_ip":"0.0.0.0","protocol":"vless"
			}`)
		case UsersEndpoint:
			writer.Header().Set("Content-Type", "application/json")
			if userRequests.Add(1) == 1 {
				writer.Header().Set("ETag", `"users-a"`)
				io.WriteString(writer, `{"users":[{"id":2,"uuid":"b"},{"id":1,"uuid":"a"}]}`)
				return
			}
			writer.Header().Set("ETag", `"users-b"`)
			io.WriteString(writer, `{"metadata":{"ignored":true},"users":[{"uuid":"a","id":1},{"uuid":"b","id":2}]}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := mustTestClient(t, server.URL, "token", 1, nil)
	defer client.Close()

	if _, changed, err := client.GetNodeConfig(context.Background()); err != nil || !changed {
		t.Fatalf("first node fetch = changed %v, error %v", changed, err)
	}
	if node, changed, err := client.GetNodeConfig(context.Background()); err != nil || changed || node != nil {
		t.Fatalf("semantic node repeat = node %+v, changed %v, error %v", node, changed, err)
	}
	if _, changed, err := client.GetUsers(context.Background()); err != nil || !changed {
		t.Fatalf("first user fetch = changed %v, error %v", changed, err)
	}
	if users, changed, err := client.GetUsers(context.Background()); err != nil || changed || users != nil {
		t.Fatalf("semantic user repeat = users %+v, changed %v, error %v", users, changed, err)
	}
}

func TestGetUsersJSONAndMessagePack(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		contentType string
		body        []byte
	}{
		{
			name:        "json",
			contentType: "application/json; charset=utf-8",
			body:        []byte(`{"metadata":{"generation":1},"users":[{"id":1,"uuid":"credential","speed_limit":10,"device_limit":2}]}`),
		},
		{
			name:        "messagepack",
			contentType: "application/x-msgpack",
			body: messagePackUserEnvelope(model.User{
				ID: 1, UUID: "credential", SpeedLimit: 10, DeviceLimit: 2,
			}),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path != UsersEndpoint {
					t.Errorf("path = %q", request.URL.Path)
				}
				if got := request.Header.Get("X-Response-Format"); got != "msgpack" {
					t.Errorf("X-Response-Format = %q", got)
				}
				writer.Header().Set("Content-Type", test.contentType)
				writer.Header().Set("ETag", `"users-1"`)
				writer.Write(test.body)
			}))
			defer server.Close()
			client := mustTestClient(t, server.URL, "token", 1, nil)
			users, changed, err := client.GetUsers(context.Background())
			if err != nil || !changed {
				t.Fatalf("GetUsers() = changed %v, error %v", changed, err)
			}
			if len(users) != 1 || users[0].UUID != "credential" || users[0].DeviceLimit != 2 {
				t.Fatalf("users = %+v", users)
			}
		})
	}
}

func TestGetUsersDetectsDeviceLimitChange(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != UsersEndpoint {
			http.NotFound(writer, request)
			return
		}
		limit := 1
		if requests.Add(1) > 1 {
			limit = 2
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("ETag", fmt.Sprintf(`"users-%d"`, limit))
		fmt.Fprintf(writer, `{"users":[{"id":1,"uuid":"credential","device_limit":%d}]}`, limit)
	}))
	defer server.Close()
	client := mustTestClient(t, server.URL, "token", 1, nil)
	defer client.Close()

	users, changed, err := client.GetUsers(context.Background())
	if err != nil || !changed || len(users) != 1 || users[0].DeviceLimit != 1 {
		t.Fatalf("initial users = %#v, changed %v, error %v", users, changed, err)
	}
	users, changed, err = client.GetUsers(context.Background())
	if err != nil || !changed || len(users) != 1 || users[0].DeviceLimit != 2 {
		t.Fatalf("updated users = %#v, changed %v, error %v", users, changed, err)
	}
}

func TestGetUsersBoundsAndValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		contentType string
		body        []byte
		maxUsers    int
	}{
		{"json count", "application/json", []byte(`{"users":[{"id":1,"uuid":"a"},{"id":2,"uuid":"b"}]}`), 1},
		{"messagepack count", "application/msgpack", messagePackUserEnvelope(
			model.User{ID: 1, UUID: "a"}, model.User{ID: 2, UUID: "b"}), 1},
		{"duplicate id", "application/json", []byte(`{"users":[{"id":1,"uuid":"a"},{"id":1,"uuid":"b"}]}`), 10},
		{"missing users", "application/json", []byte(`{"data":[]}`), 10},
		{"trailing json", "application/json", []byte(`{"users":[]} {}`), 10},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", test.contentType)
				writer.Write(test.body)
			}))
			defer server.Close()
			client := mustTestClient(t, server.URL, "token", 1, func(config *Config) {
				config.MaxUsers = test.maxUsers
			})
			if _, _, err := client.GetUsers(context.Background()); err == nil {
				t.Fatal("GetUsers() unexpectedly succeeded")
			}
		})
	}
}

func FuzzDecodeUsersJSON(f *testing.F) {
	f.Add([]byte(`{"users":[]}`))
	f.Add([]byte(`{"users":[{"id":1,"uuid":"credential"}]}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeUsersJSON(data, 16)
	})
}

func TestGetAlive(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != AliveListEndpoint {
			t.Errorf("path = %q", request.URL.Path)
		}
		io.WriteString(writer, `{"alive":{"1":2,"20":0},"ignored":true}`)
	}))
	defer server.Close()
	client := mustTestClient(t, server.URL, "token", 1, nil)
	alive, err := client.GetAlive(context.Background())
	if err != nil {
		t.Fatalf("GetAlive() error = %v", err)
	}
	if len(alive) != 2 || alive[1] != 2 || alive[20] != 0 {
		t.Fatalf("alive = %#v", alive)
	}
}

func TestReportsUseWirePayloadAndStrictStatus(t *testing.T) {
	t.Parallel()
	var trafficSeen, onlineSeen atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assertPanelQuery(t, request, "token", 9)
		if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("request = %s, content type %q", request.Method, request.Header.Get("Content-Type"))
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		switch request.URL.Path {
		case TrafficEndpoint:
			trafficSeen.Store(true)
			if got := string(body["3"]); got != `[11,22]` {
				t.Errorf("traffic payload = %s", got)
			}
			writer.WriteHeader(http.StatusNoContent)
		case OnlineEndpoint:
			onlineSeen.Store(true)
			if got := string(body["3"]); got != `["192.0.2.1","2001:db8::1"]` {
				t.Errorf("online payload = %s", got)
			}
			writer.WriteHeader(http.StatusBadGateway)
		default:
			t.Errorf("unexpected path %q", request.URL.Path)
		}
	}))
	defer server.Close()
	client := mustTestClient(t, server.URL, "token", 9, nil)
	if err := client.ReportTraffic(context.Background(), []model.UserTraffic{{UserID: 3, Upload: 11, Download: 22}}); err != nil {
		t.Fatalf("ReportTraffic() error = %v", err)
	}
	err := client.ReportOnline(context.Background(), model.OnlineUsers{3: {"192.0.2.1", "2001:db8::1"}})
	var statusError *HTTPStatusError
	if !errors.As(err, &statusError) || statusError.StatusCode != http.StatusBadGateway {
		t.Fatalf("ReportOnline() error = %v", err)
	}
	if !trafficSeen.Load() || !onlineSeen.Load() {
		t.Fatal("one or more report endpoints were not called")
	}
}

func TestReportDoesNotRetryAfterSuccessfulStatusWithTruncatedBody(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Length", "100")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("short"))
	}))
	defer server.Close()
	client := mustTestClient(t, server.URL, "token", 9, nil)
	if err := client.ReportTraffic(context.Background(), []model.UserTraffic{{UserID: 3, Upload: 11, Download: 22}}); err != nil {
		t.Fatalf("2xx report with truncated body was retried/rejected: %v", err)
	}
}

func TestResponseBodyLimit(t *testing.T) {
	t.Parallel()
	for _, declaredLength := range []bool{true, false} {
		declaredLength := declaredLength
		t.Run(fmt.Sprintf("declared=%v", declaredLength), func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				if declaredLength {
					writer.Header().Set("Content-Length", "1024")
				} else {
					writer.(http.Flusher).Flush()
				}
				io.WriteString(writer, strings.Repeat("x", 1024))
			}))
			defer server.Close()
			client := mustTestClient(t, server.URL, "token", 1, func(config *Config) {
				config.MaxResponseBytes = 64
			})
			if _, _, err := client.GetNodeConfig(context.Background()); err == nil || !strings.Contains(err.Error(), "limit of 64 bytes") {
				t.Fatalf("GetNodeConfig() error = %v", err)
			}
		})
	}
}

func TestCrossOriginRedirectIsRefusedAndTokenRedacted(t *testing.T) {
	t.Parallel()
	const secret = "s3cr3t value&percent%"
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetRequests.Add(1)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Redirect(writer, &http.Request{}, target.URL+ConfigEndpoint, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client := mustTestClient(t, source.URL, secret, 1, nil)
	_, _, err := client.GetNodeConfig(context.Background())
	if err == nil {
		t.Fatal("cross-origin redirect unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), url.QueryEscape(secret)) {
		t.Fatalf("redirect error exposed token: %q", err)
	}
	if targetRequests.Load() != 0 {
		t.Fatalf("redirect target received %d requests", targetRequests.Load())
	}
}

func TestCanceledContextIsPreserved(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		io.WriteString(writer, validNodeJSON)
	}))
	defer server.Close()
	client := mustTestClient(t, server.URL, "token", 1, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := client.GetNodeConfig(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("GetNodeConfig() error = %v", err)
	}
}

func TestStrictGETStatusDoesNotExposeBody(t *testing.T) {
	t.Parallel()
	const secret = "body-and-token-secret"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(writer, "invalid token %s", secret)
	}))
	defer server.Close()
	client := mustTestClient(t, server.URL, secret, 1, nil)
	_, _, err := client.GetUsers(context.Background())
	var statusError *HTTPStatusError
	if !errors.As(err, &statusError) || statusError.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GetUsers() error = %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("status error exposed body/token: %q", err)
	}
}

func mustTestClient(t *testing.T, baseURL, token string, nodeID int, mutate func(*Config)) *Client {
	t.Helper()
	config := Config{
		BaseURL:   baseURL,
		Token:     token,
		NodeID:    nodeID,
		AllowHTTP: true,
		Timeout:   2 * time.Second,
	}
	if mutate != nil {
		mutate(&config)
	}
	client, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return client
}

func assertPanelQuery(t *testing.T, request *http.Request, token string, nodeID int) {
	t.Helper()
	query := request.URL.Query()
	if query.Get("node_type") != "v2node" || query.Get("node_id") != strconv.Itoa(nodeID) || query.Get("token") != token {
		t.Errorf("query = %q", request.URL.RawQuery)
	}
}

func messagePackUserEnvelope(users ...model.User) []byte {
	result := []byte{0x81}
	result = appendMessagePackString(result, "users")
	if len(users) > 15 {
		panic("test helper only supports fixarray")
	}
	result = append(result, byte(0x90+len(users)))
	for _, user := range users {
		result = append(result, 0x85)
		result = appendMessagePackString(result, "id")
		result = appendMessagePackPositiveInt(result, user.ID)
		result = appendMessagePackString(result, "uuid")
		result = appendMessagePackString(result, user.UUID)
		result = appendMessagePackString(result, "speed_limit")
		result = appendMessagePackPositiveInt(result, user.SpeedLimit)
		result = appendMessagePackString(result, "device_limit")
		result = appendMessagePackPositiveInt(result, user.DeviceLimit)
		result = appendMessagePackString(result, "ignored")
		result = append(result, 0x91, 0x81)
		result = appendMessagePackString(result, "nested")
		result = append(result, 0xc3)
	}
	return result
}

func appendMessagePackString(destination []byte, value string) []byte {
	if len(value) > 31 {
		panic("test helper only supports fixstr")
	}
	destination = append(destination, byte(0xa0+len(value)))
	return append(destination, value...)
}

func appendMessagePackPositiveInt(destination []byte, value int) []byte {
	if value >= 0 && value <= 127 {
		return append(destination, byte(value))
	}
	panic("test helper only supports positive fixint")
}
