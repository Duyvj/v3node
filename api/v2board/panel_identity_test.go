package panel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Duyvj/v3node/conf"
)

func configureInstanceSecret(t *testing.T) string {
	t.Helper()
	secret := strings.Repeat("a", 64)
	path := filepath.Join(t.TempDir(), "instance-secret")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ZNODE_INSTANCE_SECRET_FILE", path)
	return secret
}

func TestInstanceSecretRequiresPrivateRegularFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not enforced on Windows")
	}
	secret := configureInstanceSecret(t)
	if got := loadInstanceSecret(); got != secret {
		t.Fatalf("instance secret = %q", got)
	}
	path := os.Getenv("ZNODE_INSTANCE_SECRET_FILE")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := loadInstanceSecret(); got != "" {
		t.Fatal("world-readable instance secret was accepted")
	}
}

func TestNodeConfigRequiresZBoardPanelIdentity(t *testing.T) {
	for name, panelType := range map[string]string{
		"wrong": "incompatible_panel",
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.Header.Get("X-V2Node-Type") != conf.RequiredPanelType || request.URL.Query().Get("type") != conf.RequiredPanelType {
					t.Error("client did not identify itself as v2node")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"panel_type":"` + panelType + `","protocol":"vmess","listen_ip":"127.0.0.1","server_port":443,"network":"tcp","tls":0}`))
			}))
			defer server.Close()

			client, err := New(&conf.NodeConfig{APIHost: server.URL, NodeID: 1, Key: "token", AgentID: "agent-a"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.GetNodeInfo(context.Background()); err == nil || !strings.Contains(err.Error(), "panel_type") {
				t.Fatalf("expected incompatible panel identity to be rejected, got %v", err)
			}
		})
	}
}

func TestNodeClientRejectsLegacyManualTokenBeforeAnyRequest(t *testing.T) {
	if _, err := New(&conf.NodeConfig{
		APIHost: "https://panel.example",
		NodeID:  1,
		Key:     "legacy-global-token",
	}); err == nil || !strings.Contains(err.Error(), "legacy manual/global tokens are disabled") {
		t.Fatalf("expected legacy credentials to be rejected, got %v", err)
	}
}

func TestNodeConfigWithoutBaseConfigUsesSafeIntervals(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"panel_type":"zboard","protocol":"vmess","listen_ip":"127.0.0.1","server_port":443,"network":"tcp","tls":0}`))
	}))
	defer server.Close()

	client, err := New(&conf.NodeConfig{APIHost: server.URL, NodeID: 1, Key: "token", AgentID: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	node, err := client.GetNodeInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if node.PushInterval != time.Minute || node.PullInterval != time.Minute {
		t.Fatalf("unsafe default intervals: push=%s pull=%s", node.PushInterval, node.PullInterval)
	}
}

func TestNodeConfigRejectsExecutableDNSProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"panel_type":"zboard","protocol":"trojan","listen_ip":"127.0.0.1",
			"server_port":443,"network":"tcp","tls":1,
			"tls_settings":{"cert_mode":"dns","provider":"exec","dns_env":"EXEC_PATH=/tmp/payload"}
		}`))
	}))
	defer server.Close()

	client, err := New(&conf.NodeConfig{APIHost: server.URL, NodeID: 1, Key: "token", AgentID: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetNodeInfo(context.Background()); err == nil || !strings.Contains(err.Error(), "unsupported DNS provider") {
		t.Fatalf("expected executable DNS provider to be rejected, got %v", err)
	}
}

func TestNodeConfigRejectsUnknownOrCertificateLessTLS(t *testing.T) {
	for name, security := range map[string]string{
		"unknown security":     `"tls":99`,
		"certificate-less TLS": `"tls":1,"tls_settings":{"cert_mode":"none"}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"panel_type":"zboard","protocol":"vmess","listen_ip":"127.0.0.1","server_port":443,"network":"tcp",` + security + `}`))
			}))
			defer server.Close()
			client, err := New(&conf.NodeConfig{APIHost: server.URL, NodeID: 1, Key: "token", AgentID: "agent-a"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.GetNodeInfo(context.Background()); err == nil {
				t.Fatal("unsafe transport security configuration was accepted")
			}
		})
	}
}
