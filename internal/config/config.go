// Package config loads the small, local-only configuration used by v3node.
// Panel-provided node and user configuration is modeled separately.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	maxLocalConfigBytes = 1 << 20
	maxTokenBytes       = 16 << 10
)

// Duration accepts either a Go duration string or a number of seconds.
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return errors.New("empty duration")
	}
	if data[0] == '"' {
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("parse duration %q: %w", value, err)
		}
		d.Duration = parsed
		return nil
	}
	var seconds float64
	if err := json.Unmarshal(data, &seconds); err != nil {
		return errors.New("duration must be a string or seconds")
	}
	if seconds < 0 || seconds > float64((24*time.Hour)/time.Second) {
		return errors.New("duration seconds out of range")
	}
	d.Duration = time.Duration(seconds * float64(time.Second))
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Duration.String())
}

type Config struct {
	Panel   PanelConfig   `json:"panel"`
	Engine  EngineConfig  `json:"engine"`
	Runtime RuntimeConfig `json:"runtime"`
	Network NetworkConfig `json:"network"`
}

type PanelConfig struct {
	URL               string `json:"url"`
	NodeID            int64  `json:"node_id"`
	Token             string `json:"token,omitempty"`
	TokenFile         string `json:"token_file,omitempty"`
	AllowInsecureHTTP bool   `json:"allow_insecure_http,omitempty"`
	TLSCAFile         string `json:"tls_ca_file,omitempty"`
}

type EngineConfig struct {
	Backend       string   `json:"backend"`
	SingBoxBinary string   `json:"sing_box_binary"`
	XrayBinary    string   `json:"xray_binary"`
	StateDir      string   `json:"state_dir"`
	StatsListen   string   `json:"stats_listen"`
	ClashListen   string   `json:"clash_listen"`
	CheckTimeout  Duration `json:"check_timeout"`
	StopTimeout   Duration `json:"stop_timeout"`
}

type RuntimeConfig struct {
	LogLevel              string   `json:"log_level"`
	HTTPTimeout           Duration `json:"http_timeout"`
	StatsInterval         Duration `json:"stats_interval"`
	PullIntervalMin       Duration `json:"pull_interval_min"`
	PullIntervalMax       Duration `json:"pull_interval_max"`
	PushIntervalMin       Duration `json:"push_interval_min"`
	PushIntervalMax       Duration `json:"push_interval_max"`
	MaxConfigBytes        int64    `json:"max_config_bytes"`
	MaxUserResponseBytes  int64    `json:"max_user_response_bytes"`
	MaxUsers              int      `json:"max_users"`
	MaxOnlineIPs          int      `json:"max_online_ips"`
	MaxIPsPerUser         int      `json:"max_ips_per_user"`
	OnlineIPTTL           Duration `json:"online_ip_ttl"`
	MaxPanelPayloadBytes  int64    `json:"max_panel_payload_bytes"`
	MaxStatsResponseBytes int64    `json:"max_stats_response_bytes"`
}

type NetworkConfig struct {
	DNSServers      []string `json:"dns_servers,omitempty"`
	AddressStrategy string   `json:"address_strategy"`
	BlockPrivate    *bool    `json:"block_private,omitempty"`
}

func Defaults() Config {
	// Match the original v2node routing contract: private/VPC destinations are
	// reachable unless the operator explicitly opts into blocking them. The
	// renderers still unconditionally protect v3node's loopback management
	// endpoints, so disabling this broader policy does not expose their APIs.
	blockPrivate := false
	return Config{
		Engine: EngineConfig{
			Backend:       "auto",
			SingBoxBinary: "/usr/local/lib/v3node/edge-engine",
			XrayBinary:    "/usr/local/lib/v3node/xray",
			StateDir:      "/var/lib/v3node",
			StatsListen:   "127.0.0.1:10085",
			ClashListen:   "127.0.0.1:10086",
			CheckTimeout:  Duration{10 * time.Second},
			StopTimeout:   Duration{20 * time.Second},
		},
		Runtime: RuntimeConfig{
			// Busy VPN nodes otherwise emit one informational log entry per
			// connection. Operators can opt into info/debug while diagnosing.
			LogLevel:              "warn",
			HTTPTimeout:           Duration{15 * time.Second},
			StatsInterval:         Duration{5 * time.Second},
			PullIntervalMin:       Duration{15 * time.Second},
			PullIntervalMax:       Duration{time.Hour},
			PushIntervalMin:       Duration{15 * time.Second},
			PushIntervalMax:       Duration{time.Hour},
			MaxConfigBytes:        2 << 20,
			MaxUserResponseBytes:  32 << 20,
			MaxUsers:              100_000,
			MaxOnlineIPs:          200_000,
			MaxIPsPerUser:         1024,
			OnlineIPTTL:           Duration{3 * time.Minute},
			MaxPanelPayloadBytes:  32 << 20,
			MaxStatsResponseBytes: 64 << 20,
		},
		Network: NetworkConfig{
			AddressStrategy: "auto",
			BlockPrivate:    &blockPrivate,
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Defaults()
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open local config: %w", err)
	}
	defer f.Close()

	limited := io.LimitReader(f, maxLocalConfigBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return Config{}, fmt.Errorf("read local config: %w", err)
	}
	if len(data) > maxLocalConfigBytes {
		return Config{}, fmt.Errorf("local config exceeds %d bytes", maxLocalConfigBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode local config: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Config{}, err
	}
	if cfg.Panel.TokenFile != "" && !filepath.IsAbs(cfg.Panel.TokenFile) {
		cfg.Panel.TokenFile = filepath.Join(filepath.Dir(path), cfg.Panel.TokenFile)
	}
	if err := cfg.resolveToken(); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("local config contains multiple JSON values")
	}
	return fmt.Errorf("decode trailing local config data: %w", err)
}

func (c *Config) resolveToken() error {
	if strings.TrimSpace(c.Panel.Token) != "" && strings.TrimSpace(c.Panel.TokenFile) != "" {
		return errors.New("set only one of panel.token and panel.token_file")
	}
	if c.Panel.TokenFile == "" {
		c.Panel.Token = strings.TrimSpace(c.Panel.Token)
		return nil
	}
	f, err := os.Open(c.Panel.TokenFile)
	if err != nil {
		return fmt.Errorf("open panel token file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxTokenBytes+1))
	if err != nil {
		return fmt.Errorf("read panel token file: %w", err)
	}
	if len(data) > maxTokenBytes {
		return errors.New("panel token file is too large")
	}
	c.Panel.Token = strings.TrimSpace(string(data))
	return nil
}

func (c Config) Validate() error {
	u, err := url.Parse(c.Panel.URL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("panel.url must be an absolute base URL without credentials, query, or fragment")
	}
	if u.Scheme != "https" && !(c.Panel.AllowInsecureHTTP && u.Scheme == "http") {
		return errors.New("panel.url must use https (http is only allowed with allow_insecure_http)")
	}
	if c.Panel.NodeID <= 0 {
		return errors.New("panel.node_id must be positive")
	}
	if c.Panel.Token == "" {
		return errors.New("panel token is empty")
	}
	if c.Panel.TLSCAFile != "" && !filepath.IsAbs(c.Panel.TLSCAFile) {
		return errors.New("panel.tls_ca_file must be an absolute path")
	}
	if len(c.Panel.Token) > maxTokenBytes {
		return errors.New("panel token is too long")
	}
	if c.Engine.Backend != "auto" && c.Engine.Backend != "sing-box" && c.Engine.Backend != "xray" {
		return errors.New("engine.backend must be auto, sing-box, or xray")
	}
	if c.Engine.StateDir == "" {
		return errors.New("engine.state_dir is required")
	}
	for field, path := range map[string]string{
		"engine.sing_box_binary": c.Engine.SingBoxBinary,
		"engine.xray_binary":     c.Engine.XrayBinary,
		"engine.state_dir":       c.Engine.StateDir,
	} {
		if !isAbsoluteConfigPath(path) {
			return fmt.Errorf("%s must be an absolute path", field)
		}
	}
	if err := validateLoopback(c.Engine.StatsListen, "engine.stats_listen"); err != nil {
		return err
	}
	if err := validateLoopback(c.Engine.ClashListen, "engine.clash_listen"); err != nil {
		return err
	}
	statsHost, statsPortText, _ := net.SplitHostPort(c.Engine.StatsListen)
	clashHost, clashPortText, _ := net.SplitHostPort(c.Engine.ClashListen)
	statsPort, _ := strconv.Atoi(statsPortText)
	clashPort, _ := strconv.Atoi(clashPortText)
	if net.ParseIP(statsHost).Equal(net.ParseIP(clashHost)) && statsPort == clashPort {
		return errors.New("engine.stats_listen and engine.clash_listen must be different")
	}
	if err := validateDuration(c.Engine.CheckTimeout.Duration, time.Second, 2*time.Minute, "engine.check_timeout"); err != nil {
		return err
	}
	if err := validateDuration(c.Engine.StopTimeout.Duration, time.Second, 2*time.Minute, "engine.stop_timeout"); err != nil {
		return err
	}
	if c.Runtime.LogLevel != "debug" && c.Runtime.LogLevel != "info" && c.Runtime.LogLevel != "warn" && c.Runtime.LogLevel != "error" {
		return errors.New("runtime.log_level must be debug, info, warn, or error")
	}
	if c.Runtime.MaxConfigBytes < 64<<10 || c.Runtime.MaxConfigBytes > 16<<20 {
		return errors.New("runtime.max_config_bytes must be between 64 KiB and 16 MiB")
	}
	if c.Runtime.MaxUserResponseBytes < 1<<20 || c.Runtime.MaxUserResponseBytes > 64<<20 {
		return errors.New("runtime.max_user_response_bytes must be between 1 MiB and 64 MiB")
	}
	if c.Runtime.MaxUsers < 1 || c.Runtime.MaxUsers > 1_000_000 {
		return errors.New("runtime.max_users must be between 1 and 1000000")
	}
	if c.Runtime.MaxOnlineIPs < 1 || c.Runtime.MaxOnlineIPs > 1_000_000 {
		return errors.New("runtime.max_online_ips must be between 1 and 1000000")
	}
	if c.Runtime.MaxIPsPerUser < 1 || c.Runtime.MaxIPsPerUser > 1024 {
		return errors.New("runtime.max_ips_per_user is out of range")
	}
	if c.Runtime.MaxIPsPerUser > c.Runtime.MaxOnlineIPs {
		return errors.New("runtime.max_ips_per_user must not exceed runtime.max_online_ips")
	}
	if c.Runtime.MaxPanelPayloadBytes < 1<<20 || c.Runtime.MaxPanelPayloadBytes > 64<<20 {
		return errors.New("runtime.max_panel_payload_bytes must be between 1 MiB and 64 MiB")
	}
	if c.Runtime.MaxStatsResponseBytes < 1<<20 || c.Runtime.MaxStatsResponseBytes > 64<<20 {
		return errors.New("runtime.max_stats_response_bytes must be between 1 MiB and 64 MiB")
	}
	if err := validateDuration(c.Runtime.HTTPTimeout.Duration, time.Second, time.Minute, "runtime.http_timeout"); err != nil {
		return err
	}
	if err := validateDuration(c.Runtime.StatsInterval.Duration, time.Second, time.Minute, "runtime.stats_interval"); err != nil {
		return err
	}
	if err := validateDuration(c.Runtime.OnlineIPTTL.Duration, 30*time.Second, 24*time.Hour, "runtime.online_ip_ttl"); err != nil {
		return err
	}
	for field, interval := range map[string]time.Duration{
		"runtime.pull_interval_min": c.Runtime.PullIntervalMin.Duration,
		"runtime.pull_interval_max": c.Runtime.PullIntervalMax.Duration,
		"runtime.push_interval_min": c.Runtime.PushIntervalMin.Duration,
		"runtime.push_interval_max": c.Runtime.PushIntervalMax.Duration,
	} {
		if err := validateDuration(interval, 5*time.Second, 24*time.Hour, field); err != nil {
			return err
		}
	}
	if c.Runtime.PullIntervalMin.Duration > c.Runtime.PullIntervalMax.Duration || c.Runtime.PushIntervalMin.Duration > c.Runtime.PushIntervalMax.Duration {
		return errors.New("runtime interval minimum cannot exceed maximum")
	}
	switch c.Network.AddressStrategy {
	case "auto", "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only":
	default:
		return errors.New("network.address_strategy is invalid")
	}
	for _, server := range c.Network.DNSServers {
		if strings.TrimSpace(server) == "" || len(server) > 255 {
			return errors.New("network.dns_servers contains an invalid server")
		}
	}
	return nil
}

func validateLoopback(address, field string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%s must be host:port: %w", field, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%s must listen on a loopback IP", field)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%s must use a numeric port between 1 and 65535", field)
	}
	return nil
}

func isAbsoluteConfigPath(value string) bool {
	if filepath.IsAbs(value) {
		return true
	}
	// Tests and local inspection may load a Linux deployment configuration on
	// Windows. A leading slash remains an absolute target-host path.
	return runtime.GOOS == "windows" && strings.HasPrefix(value, "/")
}

func validateDuration(value, min, max time.Duration, field string) error {
	if value < min || value > max {
		return fmt.Errorf("%s must be between %s and %s", field, min, max)
	}
	return nil
}

// EffectiveGOMEMLIMIT returns a conservative soft Go heap limit for the
// controller only. It never imposes a hard cgroup limit on the data plane.
func EffectiveGOMEMLIMIT(totalRAM uint64) uint64 {
	const (
		min = 64 << 20
		max = 256 << 20
	)
	limit := totalRAM / 16
	if limit < min {
		return min
	}
	if limit > max {
		return max
	}
	return limit
}

func DefaultPath() string {
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\v3node\config.json`
	}
	return "/etc/v3node/config.json"
}
