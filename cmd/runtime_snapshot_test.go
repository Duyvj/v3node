package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Duyvj/v3node/agent"
	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/Duyvj/v3node/conf"
	"github.com/Duyvj/v3node/limiter"
	"github.com/Duyvj/v3node/node"
)

func TestOfflineRuntimeSnapshotStartsWithoutPanel(t *testing.T) {
	stateDirectory := t.TempDir()
	t.Setenv("ZNODE_STATE_DIR", stateDirectory)
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverPort := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	agentConfig := conf.AgentConfig{
		Enable:          true,
		APIHost:         "http://127.0.0.1:9",
		AgentID:         "agent-offline",
		AgentInstanceID: "instance-a",
		AgentToken:      "snapshot-secret",
		PollInterval:    15,
	}
	manifest := panel.AgentManifest{PanelType: conf.RequiredPanelType, Nodes: []int{7}}
	configuration := conf.New()
	configuration.Type = conf.RequiredPanelType
	configuration.AgentConfig = agentConfig
	configuration.NodeConfigs = manifest.NodeConfigs(agentConfig)
	runtimeState := node.RuntimeSnapshot{
		NodeInfos: []*panel.NodeInfo{{
			Id: 7, Type: "vmess", Security: panel.None, PushInterval: time.Minute,
			PullInterval: time.Minute, Tag: "[offline]-vmess:7",
			Common: &panel.CommonNode{
				PanelType: conf.RequiredPanelType, Protocol: "vmess", ListenIP: "127.0.0.1",
				ServerPort: serverPort, Network: "tcp", NetworkSettings: json.RawMessage(`{}`),
				BaseConfig: &panel.BaseConfig{PushInterval: 60, PullInterval: 60},
				CertInfo:   &panel.CertInfo{CertMode: "none"},
			},
		}},
		Users: [][]panel.UserInfo{{{Id: 11, UserId: 11, Uuid: "11111111-1111-4111-8111-111111111111", DeviceLimit: 2}}},
		Alive: []map[int]int{{11: 1}},
		DeviceConfigs: []*conf.GlobalDeviceLimitConfig{{
			Enable: false, RedisNetwork: "tcp", RedisAddr: "127.0.0.1:6379",
			UserFallbackEnabled: true, UserSnapshotPrefix: "zboard:user-snapshot",
			UserSnapshotMaxAge: 604800,
		}},
	}
	nodes, err := node.NewFromRuntimeSnapshot(configuration.NodeConfigs, runtimeState)
	if err != nil {
		t.Fatal(err)
	}
	prepared := &preparedRuntime{
		config: configuration,
		nodes:  nodes,
		assignment: agent.Assignment{
			Revision: "revision-online", NodeRevision: "nodes-online",
			FallbackRevision: "fallback-online", PollInterval: 15 * time.Second,
		},
	}
	if err := persistRuntimeSnapshot(prepared); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(t.TempDir(), "config.json")
	configJSON := `{"type":"zboard","Agent":{"Enable":true,"ApiHost":"http://127.0.0.1:9","AgentID":"agent-offline","AgentInstanceID":"instance-a","AgentToken":"snapshot-secret","PollInterval":15}}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	restored, err := prepareInitialRuntime(configPath)
	if err != nil {
		t.Fatalf("offline snapshot did not restore: %v", err)
	}
	if !restored.offline || restored.offlineCause == nil {
		t.Fatal("initial runtime did not mark the panel outage as offline mode")
	}
	if restored.assignment.Revision != "revision-online" || len(restored.config.NodeConfigs) != 1 || restored.config.NodeConfigs[0].NodeID != 7 {
		t.Fatalf("unexpected restored runtime: assignment=%+v nodes=%+v", restored.assignment, restored.config.NodeConfigs)
	}
	if restored.assignment.NodeRevision != "nodes-online" || restored.assignment.FallbackRevision != "fallback-online" {
		t.Fatalf("component revisions were not restored: %+v", restored.assignment)
	}
	if fallback := restored.config.NodeConfigs[0].GlobalDeviceLimitConfig; fallback == nil || !fallback.UserFallbackEnabled || fallback.UserSnapshotMaxAge != 604800 {
		t.Fatalf("Redis fallback config was not restored: %+v", fallback)
	}
	limiter.Init()
	running, err := startPreparedRuntime(restored, make(chan struct{}, 1))
	if err != nil {
		t.Fatalf("offline Xray runtime did not start: %v", err)
	}
	defer running.Close()
	connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)), time.Second)
	if err != nil {
		t.Fatalf("offline runtime did not listen on the cached VPN port: %v", err)
	}
	_ = connection.Close()
}

func TestOfflineRuntimeSnapshotRejectsTampering(t *testing.T) {
	t.Setenv("ZNODE_STATE_DIR", t.TempDir())
	agentConfig := conf.AgentConfig{Enable: true, APIHost: "https://panel.example", AgentID: "agent", AgentToken: "secret", PollInterval: 15}
	payload := runtimeSnapshotPayload{
		Version: runtimeSnapshotVersion, SavedAt: time.Now().Unix(), APIHost: agentConfig.APIHost,
		AgentID: agentConfig.AgentID, Revision: "safe", PollIntervalSeconds: 15,
		Runtime: node.RuntimeSnapshot{NodeInfos: []*panel.NodeInfo{}, Users: [][]panel.UserInfo{}, Alive: []map[int]int{}},
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope := signedRuntimeSnapshot{Payload: payloadJSON, HMAC: runtimeSnapshotMAC(agentConfig.AgentToken, payloadJSON)}
	envelope.Payload = bytes.Replace(envelope.Payload, []byte(`"revision":"safe"`), []byte(`"revision":"evil"`), 1)
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteRuntimeSnapshot(encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRuntimeSnapshot(agentConfig); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("tampered snapshot was accepted: %v", err)
	}
}
