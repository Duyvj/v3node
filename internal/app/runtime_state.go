package app

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"time"

	"github.com/Duyvj/v3node/internal/engine"
)

const runtimeStateVersion = 4

type UserPolicy struct {
	SpeedLimit  int `json:"speed_limit"`
	DeviceLimit int `json:"device_limit"`
}

type RuntimeState struct {
	Version              int                `json:"version"`
	Backend              string             `json:"backend"`
	ConfigSHA256         string             `json:"config_sha256"`
	EngineUsers          map[string]int     `json:"engine_users"`
	Policies             map[int]UserPolicy `json:"policies"`
	PullIntervalNanos    int64              `json:"pull_interval_nanos"`
	PushIntervalNanos    int64              `json:"push_interval_nanos"`
	DeviceOnlineMinBytes int64              `json:"device_online_min_bytes"`
	NodeReportMinBytes   int64              `json:"node_report_min_bytes"`
	Listener             RuntimeListener    `json:"listener"`
	ManagementSHA256     string             `json:"management_sha256,omitempty"`
}

// RuntimeListener persists only what is needed to claim the public port
// before a last-known-good engine starts. It deliberately excludes panel
// credentials, TLS key material, routes and transport settings.
type RuntimeListener struct {
	Protocol string `json:"protocol"`
	Listen   string `json:"listen,omitempty"`
	Port     uint16 `json:"port"`
}

func RuntimeStateFromCompiled(backend string, compiled CompiledState, engineUsers map[string]int, configHash [sha256.Size]byte, management []string) RuntimeState {
	// Most panels leave both optional limits at zero. Persist only effective
	// policy rows so runtime.json stays small on large nodes.
	policies := make(map[int]UserPolicy)
	for _, user := range compiled.Users {
		if user.SpeedLimit != 0 || user.DeviceLimit != 0 {
			policies[user.ID] = UserPolicy{SpeedLimit: user.SpeedLimit, DeviceLimit: user.DeviceLimit}
		}
	}
	users := make(map[string]int, len(engineUsers))
	for name, id := range engineUsers {
		users[name] = id
	}
	return RuntimeState{
		Version:              runtimeStateVersion,
		Backend:              backend,
		ConfigSHA256:         hex.EncodeToString(configHash[:]),
		EngineUsers:          users,
		Policies:             policies,
		PullIntervalNanos:    int64(compiled.PullInterval),
		PushIntervalNanos:    int64(compiled.PushInterval),
		DeviceOnlineMinBytes: compiled.DeviceOnlineMinBytes,
		NodeReportMinBytes:   compiled.NodeReportMinBytes,
		Listener:             runtimeListenerSpec(compiled.Node),
		ManagementSHA256:     protectedManagementSHA256(management),
	}
}

func protectedManagementSHA256(addresses []string) string {
	ordered := append([]string(nil), addresses...)
	sort.Strings(ordered)
	hash := sha256.New()
	for _, address := range ordered {
		_, _ = hash.Write([]byte(strconv.Itoa(len(address))))
		_, _ = hash.Write([]byte{':'})
		_, _ = hash.Write([]byte(address))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func runtimeStateProtectsManagement(state RuntimeState, addresses []string) bool {
	return state.Version >= runtimeStateVersion && state.ManagementSHA256 == protectedManagementSHA256(addresses)
}

func runtimeListenerSpec(node engine.NodeSpec) RuntimeListener {
	return RuntimeListener{
		Protocol: node.Protocol,
		Listen:   node.Listen,
		Port:     node.Port,
	}
}

func (s RuntimeState) ConfigHash() ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	decoded, err := hex.DecodeString(s.ConfigSHA256)
	if err != nil || len(decoded) != sha256.Size {
		return result, errors.New("runtime state contains an invalid config SHA256")
	}
	copy(result[:], decoded)
	return result, nil
}

func (s RuntimeState) PullInterval() time.Duration { return time.Duration(s.PullIntervalNanos) }
func (s RuntimeState) PushInterval() time.Duration { return time.Duration(s.PushIntervalNanos) }

func (s RuntimeState) Validate(maxUsers int, minPull, maxPull, minPush, maxPush time.Duration) error {
	if s.Version != 2 && s.Version != 3 && s.Version != runtimeStateVersion {
		return fmt.Errorf("unsupported runtime state version %d", s.Version)
	}
	if s.Backend != "sing-box" && s.Backend != "xray" {
		return fmt.Errorf("invalid runtime backend %q", s.Backend)
	}
	if s.Version >= 3 && (s.Listener.Port == 0 || !validRuntimeProtocol(s.Listener.Protocol)) {
		return errors.New("runtime state contains an invalid public listener")
	}
	if s.Version >= 3 && s.Listener.Listen != "" && net.ParseIP(s.Listener.Listen) == nil {
		return errors.New("runtime state contains an invalid public listen address")
	}
	if s.Version >= runtimeStateVersion {
		decoded, err := hex.DecodeString(s.ManagementSHA256)
		if err != nil || len(decoded) != sha256.Size {
			return errors.New("runtime state contains an invalid management protection SHA256")
		}
	}
	if _, err := s.ConfigHash(); err != nil {
		return err
	}
	if len(s.EngineUsers) > maxUsers || len(s.Policies) > maxUsers {
		return errors.New("runtime state exceeds configured user limit")
	}
	for name, id := range s.EngineUsers {
		if name == "" || len(name) > 256 || id <= 0 {
			return errors.New("runtime state contains an invalid engine user")
		}
	}
	for id, policy := range s.Policies {
		if id <= 0 || policy.SpeedLimit < 0 || policy.DeviceLimit < 0 {
			return errors.New("runtime state contains an invalid user policy")
		}
		if policy.SpeedLimit > 0 {
			return errors.New("runtime state contains an unenforceable speed limit")
		}
		if s.Backend == "xray" && policy.DeviceLimit > 0 {
			return errors.New("runtime state contains an unenforceable Xray device limit")
		}
	}
	if s.PullInterval() < minPull || s.PullInterval() > maxPull || s.PushInterval() < minPush || s.PushInterval() > maxPush {
		return errors.New("runtime state contains an interval outside local safety bounds")
	}
	return nil
}

func validRuntimeProtocol(protocol string) bool {
	switch protocol {
	case "vmess", "vless", "trojan", "shadowsocks", "hysteria2", "tuic", "anytls":
		return true
	default:
		return false
	}
}

func LoadRuntimeState(path string, maxUsers int, minPull, maxPull, minPush, maxPush time.Duration) (RuntimeState, error) {
	f, err := os.Open(path)
	if err != nil {
		return RuntimeState{}, err
	}
	defer f.Close()
	limit := int64(maxUsers)*320 + 4096
	if limit > 64<<20 {
		limit = 64 << 20
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return RuntimeState{}, fmt.Errorf("read runtime state: %w", err)
	}
	if int64(len(data)) > limit {
		return RuntimeState{}, errors.New("runtime state file is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state RuntimeState
	if err := decoder.Decode(&state); err != nil {
		return RuntimeState{}, fmt.Errorf("decode runtime state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return RuntimeState{}, errors.New("runtime state contains trailing JSON")
		}
		return RuntimeState{}, err
	}
	if err := state.Validate(maxUsers, minPull, maxPull, minPush, maxPush); err != nil {
		return RuntimeState{}, err
	}
	return state, nil
}

func SaveRuntimeState(path string, state RuntimeState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create runtime state directory: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".runtime-state-*.json")
	if err != nil {
		return fmt.Errorf("create staged runtime state: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	writer := bufio.NewWriterSize(f, 32<<10)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(state); err != nil {
		_ = f.Close()
		return fmt.Errorf("encode runtime state: %w", err)
	}
	if err := writer.Flush(); err != nil {
		_ = f.Close()
		return fmt.Errorf("flush runtime state: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("activate runtime state: %w", err)
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(filepath.Dir(path))
		if err != nil {
			return fmt.Errorf("open runtime state directory: %w", err)
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil || closeErr != nil {
			return errors.Join(syncErr, closeErr)
		}
	}
	return nil
}
