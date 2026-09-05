package cmd

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Duyvj/v3node/agent"
	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/Duyvj/v3node/conf"
	"github.com/Duyvj/v3node/node"
)

const (
	runtimeSnapshotVersion = 1
	runtimeSnapshotFile    = "runtime.snapshot"
	maxRuntimeSnapshotSize = 128 << 20
)

type runtimeSnapshotPayload struct {
	Version              int                  `json:"version"`
	SavedAt              int64                `json:"saved_at"`
	APIHost              string               `json:"api_host"`
	AgentID              string               `json:"agent_id"`
	AgentInstanceID      string               `json:"agent_instance_id,omitempty"`
	Revision             string               `json:"revision"`
	NodeRevision         string               `json:"node_revision,omitempty"`
	FallbackRevision     string               `json:"fallback_revision,omitempty"`
	PollIntervalSeconds  int64                `json:"poll_interval_seconds"`
	AuthorizationRevoked bool                 `json:"authorization_revoked,omitempty"`
	Runtime              node.RuntimeSnapshot `json:"runtime"`
}

type signedRuntimeSnapshot struct {
	Payload json.RawMessage `json:"payload"`
	HMAC    string          `json:"hmac_sha256"`
}

func prepareInitialRuntime(configPath string) (*preparedRuntime, error) {
	prepared, onlineErr := prepareRuntime(configPath)
	if onlineErr == nil {
		return prepared, nil
	}
	prepared, snapshotErr := prepareRuntimeFromSnapshot(configPath)
	if snapshotErr != nil {
		return nil, fmt.Errorf("online preparation failed: %w; offline snapshot unavailable: %v", onlineErr, snapshotErr)
	}
	prepared.offline = true
	prepared.offlineCause = onlineErr
	return prepared, nil
}

func prepareRuntimeFromSnapshot(configPath string) (*preparedRuntime, error) {
	configuration := conf.New()
	if err := configuration.LoadFromPath(configPath); err != nil {
		return nil, err
	}
	if !configuration.AgentConfig.Enable {
		return nil, fmt.Errorf("offline runtime snapshots require Agent mode")
	}
	payload, err := loadRuntimeSnapshot(configuration.AgentConfig)
	if err != nil {
		return nil, err
	}
	nodeIDs := make([]int, 0, len(payload.Runtime.NodeInfos))
	for _, info := range payload.Runtime.NodeInfos {
		if info == nil || info.Id <= 0 {
			return nil, fmt.Errorf("offline runtime snapshot contains an invalid node")
		}
		nodeIDs = append(nodeIDs, info.Id)
	}
	manifest := panel.AgentManifest{PanelType: conf.RequiredPanelType, Nodes: nodeIDs}
	if err := manifest.Validate(); err != nil {
		return nil, fmt.Errorf("offline runtime assignment is invalid: %w", err)
	}
	configuration.NodeConfigs = manifest.NodeConfigs(configuration.AgentConfig)
	nodes, err := node.NewFromRuntimeSnapshot(configuration.NodeConfigs, payload.Runtime)
	if err != nil {
		return nil, err
	}
	return &preparedRuntime{
		config: configuration,
		nodes:  nodes,
		assignment: agent.Assignment{
			Revision:             payload.Revision,
			NodeRevision:         payload.NodeRevision,
			FallbackRevision:     payload.FallbackRevision,
			PollInterval:         time.Duration(payload.PollIntervalSeconds) * time.Second,
			AuthorizationRevoked: payload.AuthorizationRevoked,
		},
	}, nil
}

func persistRuntimeSnapshot(prepared *preparedRuntime) error {
	if prepared == nil || prepared.config == nil || prepared.nodes == nil {
		return nil
	}
	agentConfig := prepared.config.AgentConfig
	if !agentConfig.Enable {
		return nil
	}
	pollSeconds := int64(prepared.assignment.PollInterval / time.Second)
	if pollSeconds <= 0 {
		pollSeconds = int64(agentConfig.PollInterval)
	}
	runtimeState, err := prepared.nodes.RuntimeSnapshot()
	if err != nil {
		return fmt.Errorf("capture runtime snapshot: %w", err)
	}
	payload := runtimeSnapshotPayload{
		Version:              runtimeSnapshotVersion,
		SavedAt:              time.Now().Unix(),
		APIHost:              agentConfig.APIHost,
		AgentID:              agentConfig.AgentID,
		AgentInstanceID:      agentConfig.AgentInstanceID,
		Revision:             prepared.assignment.Revision,
		NodeRevision:         prepared.assignment.NodeRevision,
		FallbackRevision:     prepared.assignment.FallbackRevision,
		PollIntervalSeconds:  pollSeconds,
		AuthorizationRevoked: prepared.assignment.AuthorizationRevoked,
		Runtime:              runtimeState,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode runtime snapshot: %w", err)
	}
	envelope := signedRuntimeSnapshot{
		Payload: payloadJSON,
		HMAC:    runtimeSnapshotMAC(agentConfig.AgentToken, payloadJSON),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode signed runtime snapshot: %w", err)
	}
	return atomicWriteRuntimeSnapshot(encoded)
}

func loadRuntimeSnapshot(agentConfig conf.AgentConfig) (*runtimeSnapshotPayload, error) {
	path := runtimeSnapshotPath()
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat runtime snapshot: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("runtime snapshot is not a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("runtime snapshot permissions are not private")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open runtime snapshot: %w", err)
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, maxRuntimeSnapshotSize+1))
	if err != nil {
		return nil, fmt.Errorf("read runtime snapshot: %w", err)
	}
	if len(encoded) > maxRuntimeSnapshotSize {
		return nil, fmt.Errorf("runtime snapshot is too large")
	}
	var envelope signedRuntimeSnapshot
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return nil, fmt.Errorf("decode runtime snapshot envelope: %w", err)
	}
	expectedMAC := runtimeSnapshotMAC(agentConfig.AgentToken, envelope.Payload)
	if !hmac.Equal([]byte(strings.ToLower(envelope.HMAC)), []byte(expectedMAC)) {
		return nil, fmt.Errorf("runtime snapshot authentication failed")
	}
	var payload runtimeSnapshotPayload
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		return nil, fmt.Errorf("decode runtime snapshot: %w", err)
	}
	if payload.Version != runtimeSnapshotVersion {
		return nil, fmt.Errorf("unsupported runtime snapshot version %d", payload.Version)
	}
	if payload.SavedAt <= 0 || payload.SavedAt > time.Now().Add(5*time.Minute).Unix() {
		return nil, fmt.Errorf("runtime snapshot timestamp is invalid")
	}
	if payload.APIHost != agentConfig.APIHost || payload.AgentID != agentConfig.AgentID || payload.AgentInstanceID != agentConfig.AgentInstanceID {
		return nil, fmt.Errorf("runtime snapshot belongs to a different Agent")
	}
	if payload.PollIntervalSeconds <= 0 || payload.PollIntervalSeconds > 3600 {
		return nil, fmt.Errorf("runtime snapshot poll interval is invalid")
	}
	return &payload, nil
}

func runtimeSnapshotMAC(token string, payload []byte) string {
	key := sha256.Sum256([]byte("znode-runtime-snapshot-v1\x00" + token))
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func runtimeSnapshotPath() string {
	directory := strings.TrimSpace(os.Getenv("ZNODE_STATE_DIR"))
	if directory == "" {
		directory = "/var/lib/znode"
	}
	return filepath.Join(directory, runtimeSnapshotFile)
}

func atomicWriteRuntimeSnapshot(data []byte) error {
	path := runtimeSnapshotPath()
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create runtime state directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("secure runtime state directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".runtime.snapshot.*")
	if err != nil {
		return fmt.Errorf("create runtime snapshot: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write runtime snapshot: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync runtime snapshot: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close runtime snapshot: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("activate runtime snapshot: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err == nil {
		_ = directoryHandle.Sync()
		_ = directoryHandle.Close()
	}
	return nil
}
