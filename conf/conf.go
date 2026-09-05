package conf

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

const DefaultNodeRetryCount = 1
const DefaultNodeTimeout = 15
const RequiredPanelType = "v2node"

type Conf struct {
	Type             string           `mapstructure:"type"`
	LogConfig        LogConfig        `mapstructure:"Log"`
	NodeConfigs      []NodeConfig     `mapstructure:"Nodes"`
	AgentConfig      AgentConfig      `mapstructure:"Agent"`
	ResourceConfig   ResourceConfig   `mapstructure:"Resource"`
	PprofPort        int              `mapstructure:"PprofPort"`
	ConnectionConfig ConnectionConfig `mapstructure:"ConnectionConfig"`
}

type ResourceConfig struct {
	Profile                       string `mapstructure:"Profile"`                       // "low", "standard", "high_performance"
	MemLimitMB                    int    `mapstructure:"MemLimitMB"`                    // Max memory target in MB (0 to disable)
	GOGC                          int    `mapstructure:"GOGC"`                          // GC percent (e.g., 50 for low RAM, 80 for standard, 100 for high)
	BufferSize                    int    `mapstructure:"BufferSize"`                    // Buffer size per pipe in KB (e.g., 16, 32, 128)
	ConnectionIdle                int    `mapstructure:"ConnectionIdle"`                // Inactive connection timeout in seconds
	Handshake                     int    `mapstructure:"Handshake"`                     // Handshake timeout in seconds
	UplinkOnly                    int    `mapstructure:"UplinkOnly"`                    // Uplink only timeout in seconds
	DownlinkOnly                  int    `mapstructure:"DownlinkOnly"`                  // Downlink only timeout in seconds
	DisableSniffing               bool   `mapstructure:"DisableSniffing"`               // Disable domain sniffing for performance and app compatibility
	PeriodicMemoryReleaseInterval int    `mapstructure:"PeriodicMemoryReleaseInterval"` // Interval in seconds to release free memory back to OS (0 to disable)
}

func (r *ResourceConfig) ApplyDefaults() {
	if r.Profile == "" {
		r.Profile = "standard"
	}
	switch r.Profile {
	case "low":
		if r.GOGC == 0 {
			r.GOGC = 50
		}
		if r.BufferSize == 0 {
			r.BufferSize = 16
		}
		if r.ConnectionIdle == 0 {
			r.ConnectionIdle = 45
		}
		if r.Handshake == 0 {
			r.Handshake = 4
		}
		if r.UplinkOnly == 0 {
			r.UplinkOnly = 1
		}
		if r.DownlinkOnly == 0 {
			r.DownlinkOnly = 2
		}
		if r.PeriodicMemoryReleaseInterval == 0 {
			r.PeriodicMemoryReleaseInterval = 60
		}
	case "high", "high_performance":
		if r.GOGC == 0 {
			r.GOGC = 100
		}
		if r.BufferSize == 0 {
			r.BufferSize = 128
		}
		if r.ConnectionIdle == 0 {
			r.ConnectionIdle = 120
		}
		if r.Handshake == 0 {
			r.Handshake = 4
		}
		if r.UplinkOnly == 0 {
			r.UplinkOnly = 2
		}
		if r.DownlinkOnly == 0 {
			r.DownlinkOnly = 4
		}
	default: // "standard"
		if r.GOGC == 0 {
			r.GOGC = 80
		}
		if r.BufferSize == 0 {
			r.BufferSize = 32
		}
		if r.ConnectionIdle == 0 {
			r.ConnectionIdle = 60
		}
		if r.Handshake == 0 {
			r.Handshake = 4
		}
		if r.UplinkOnly == 0 {
			r.UplinkOnly = 2
		}
		if r.DownlinkOnly == 0 {
			r.DownlinkOnly = 4
		}
		if r.PeriodicMemoryReleaseInterval == 0 {
			r.PeriodicMemoryReleaseInterval = 120
		}
	}
}

type LogConfig struct {
	Level  string `mapstructure:"Level"`
	Output string `mapstructure:"Output"`
	Access string `mapstructure:"Access"`
}

type NodeConfig struct {
	APIHost                 string                   `mapstructure:"ApiHost"`
	NodeID                  int                      `mapstructure:"NodeID"`
	Key                     string                   `mapstructure:"ApiKey"`
	Token                   string                   `mapstructure:"Token"`
	AgentID                 string                   `mapstructure:"AgentID"`
	AgentInstanceID         string                   `mapstructure:"AgentInstanceID"`
	Timeout                 int                      `mapstructure:"Timeout"`
	RetryCount              *int                     `mapstructure:"RetryCount"`
	DisableSniffing         *bool                    `mapstructure:"DisableSniffing"`
	GlobalDeviceLimitConfig *GlobalDeviceLimitConfig `mapstructure:"GlobalDeviceLimitConfig"`
}

// AgentConfig lets one znode process receive and run multiple logical nodes
// assigned by ZBoard. Nodes remains the manual ZNode mode when
// Agent.Enable is false.
type AgentConfig struct {
	Enable                  bool                     `mapstructure:"Enable"`
	APIHost                 string                   `mapstructure:"ApiHost"`
	AgentID                 string                   `mapstructure:"AgentID"`
	AgentInstanceID         string                   `mapstructure:"AgentInstanceID"`
	AgentToken              string                   `mapstructure:"AgentToken"`
	PollInterval            int                      `mapstructure:"PollInterval"`
	GlobalDeviceLimitConfig *GlobalDeviceLimitConfig `mapstructure:"GlobalDeviceLimitConfig"`
}

// ConnectionConfig controls the Xray policy applied to every inbound session.
// BufferSize is in KiB. Defaults keep enough headroom for UDP/QUIC video while
// remaining below Xray's amd64 default.
type ConnectionConfig struct {
	Handshake                 uint32 `mapstructure:"Handshake"`
	ConnIdle                  uint32 `mapstructure:"ConnIdle"`
	UplinkOnly                uint32 `mapstructure:"UplinkOnly"`
	DownlinkOnly              uint32 `mapstructure:"DownlinkOnly"`
	BufferSize                int32  `mapstructure:"BufferSize"`
	DisableUDPContentSniffing bool   `mapstructure:"DisableUDPContentSniffing"`
	MaxConnectionsPerUser     int    `mapstructure:"MaxConnectionsPerUser"`
	MaxConnections            int    `mapstructure:"MaxConnections"`
}

// GlobalDeviceLimitConfig enables a Redis-backed, cross-node device/IP limit.
// If Redis is unavailable, FailClosed=false keeps traffic available and falls
// back to the bounded local tracker.
type GlobalDeviceLimitConfig struct {
	Enable                bool     `mapstructure:"Enable"`
	RedisNetwork          string   `mapstructure:"RedisNetwork"`
	RedisAddr             string   `mapstructure:"RedisAddr"`
	RedisUsername         string   `mapstructure:"RedisUsername"`
	RedisPassword         string   `mapstructure:"RedisPassword"`
	RedisDB               int      `mapstructure:"RedisDB"`
	RedisTLS              bool     `mapstructure:"RedisTLS"`
	RedisTLSServerName    string   `mapstructure:"RedisTLSServerName"`
	RedisTLSCAFile        string   `mapstructure:"RedisTLSCAFile"`
	RedisTLSCACert        string   `mapstructure:"RedisTLSCACert"`
	RedisSentinelMaster   string   `mapstructure:"RedisSentinelMaster"`
	RedisSentinelAddrs    []string `mapstructure:"RedisSentinelAddrs"`
	RedisSentinelUsername string   `mapstructure:"RedisSentinelUsername"`
	RedisSentinelPassword string   `mapstructure:"RedisSentinelPassword"`
	Timeout               int      `mapstructure:"Timeout"`
	Expiry                int      `mapstructure:"Expiry"`
	RefreshInterval       int      `mapstructure:"RefreshInterval"`
	// HandoverGrace lets a genuinely new address take the slot of one that has
	// gone silent for at least this many seconds, instead of being refused
	// until Expiry. A phone leaving WiFi for mobile data is the ordinary case.
	// Pointer so an omitted key still gets a working default while an explicit
	// 0 disables handover. Must stay at or above 2*RefreshInterval: an address
	// that is still transmitting only refreshes its score at that cadence, so
	// a shorter grace would evict a second client that is genuinely active.
	HandoverGrace         *int     `mapstructure:"HandoverGrace"`
	MaxIPsPerUser         int      `mapstructure:"MaxIPsPerUser"`
	KeyPrefix             string   `mapstructure:"KeyPrefix"`
	FailClosed            bool     `mapstructure:"FailClosed"`
	// Pointer allows omitted SyncEnabled to default to true while still
	// honoring an explicit false in a node config.
	SyncEnabled *bool  `mapstructure:"SyncEnabled"`
	SyncChannel string `mapstructure:"SyncChannel"`
	// Signed user snapshots are a control-plane fallback. ZNode always asks
	// ZBoard first and reads Redis only when that request fails.
	UserFallbackEnabled bool   `mapstructure:"UserFallbackEnabled"`
	UserSnapshotPrefix  string `mapstructure:"UserSnapshotPrefix"`
	UserSnapshotMaxAge  int    `mapstructure:"UserSnapshotMaxAge"`
	// UserSourceMode controls only signed UUID snapshot precedence. It never
	// changes Redis device limiter Enable/FailClosed behavior.
	UserSourceMode string `mapstructure:"UserSourceMode"`
}

func New() *Conf {
	c := &Conf{
		Type: RequiredPanelType,
		LogConfig: LogConfig{
			Level:  "info",
			Output: "",
			Access: "none",
		},
		ResourceConfig: ResourceConfig{
			Profile:         "standard",
			DisableSniffing: true,
		},
		ConnectionConfig: ConnectionConfig{
			Handshake:                 15,
			ConnIdle:                  60,
			UplinkOnly:                2,
			DownlinkOnly:              4,
			BufferSize:                32,
			DisableUDPContentSniffing: true,
			MaxConnectionsPerUser:     128,
			MaxConnections:            32768,
		},
		AgentConfig: AgentConfig{PollInterval: 15},
	}
	c.ResourceConfig.ApplyDefaults()
	return c
}

func (p *Conf) LoadFromPath(filePath string) error {
	f, err := openSecureConfigFile(filePath)
	if err != nil {
		return fmt.Errorf("open secure config file error: %s", err)
	}
	defer f.Close()
	v := viper.New()
	configType := strings.TrimPrefix(strings.ToLower(filepath.Ext(filePath)), ".")
	if configType == "yml" {
		configType = "yaml"
	}
	switch configType {
	case "json", "yaml", "toml":
		v.SetConfigType(configType)
	default:
		return fmt.Errorf("unsupported config file type %q", configType)
	}
	// Parse the already-verified descriptor. Reopening the pathname here would
	// reintroduce a symlink/swap race after the permission and owner checks.
	if err := v.ReadConfig(f); err != nil {
		return fmt.Errorf("read config file error: %s", err)
	}
	if err := v.Unmarshal(p); err != nil {
		return fmt.Errorf("unmarshal config error: %s", err)
	}
	p.Type = strings.ToLower(strings.TrimSpace(p.Type))
	if p.Type == "" {
		p.Type = RequiredPanelType
	}
	if p.Type != "v2node" && p.Type != "v2board" && p.Type != "zboard" {
		return fmt.Errorf("invalid config type %q: requires type=v2node, v2board, or zboard", p.Type)
	}
	p.ResourceConfig.ApplyDefaults()
	if p.ResourceConfig.BufferSize > 0 {
		p.ConnectionConfig.BufferSize = int32(p.ResourceConfig.BufferSize)
	}
	if p.ResourceConfig.ConnectionIdle > 0 {
		p.ConnectionConfig.ConnIdle = uint32(p.ResourceConfig.ConnectionIdle)
	}
	if p.ResourceConfig.Handshake > 0 {
		p.ConnectionConfig.Handshake = uint32(p.ResourceConfig.Handshake)
	}
	if p.ResourceConfig.UplinkOnly > 0 {
		p.ConnectionConfig.UplinkOnly = uint32(p.ResourceConfig.UplinkOnly)
	}
	if p.ResourceConfig.DownlinkOnly > 0 {
		p.ConnectionConfig.DownlinkOnly = uint32(p.ResourceConfig.DownlinkOnly)
	}
	if err := p.AgentConfig.applyDefaultsAndValidate(); err != nil {
		return err
	}
	for i := range p.NodeConfigs {
		if p.NodeConfigs[i].Key == "" && p.NodeConfigs[i].Token != "" {
			p.NodeConfigs[i].Key = p.NodeConfigs[i].Token
		}
		if p.NodeConfigs[i].AgentID == "" {
			p.NodeConfigs[i].AgentID = fmt.Sprintf("v2node-%d", p.NodeConfigs[i].NodeID)
		}
		apiHost, err := NormalizePanelAPIHost(p.NodeConfigs[i].APIHost)
		if err != nil {
			return fmt.Errorf("node config %d: %w", i, err)
		}
		p.NodeConfigs[i].APIHost = apiHost
		if p.NodeConfigs[i].RetryCount == nil {
			p.NodeConfigs[i].RetryCount = intPtr(DefaultNodeRetryCount)
		}
		if p.NodeConfigs[i].DisableSniffing == nil {
			p.NodeConfigs[i].DisableSniffing = boolPtr(p.ResourceConfig.DisableSniffing)
		}
		if p.NodeConfigs[i].GlobalDeviceLimitConfig != nil {
			p.NodeConfigs[i].GlobalDeviceLimitConfig.applyDefaults()
			if _, err := RedisTLSConfig(p.NodeConfigs[i].GlobalDeviceLimitConfig); err != nil {
				return fmt.Errorf("node config %d Redis: %w", i, err)
			}
		}
	}
	p.ConnectionConfig.applyDefaults()
	return nil
}

func (c *AgentConfig) applyDefaultsAndValidate() error {
	c.APIHost = strings.TrimRight(strings.TrimSpace(c.APIHost), "/")
	c.AgentID = strings.TrimSpace(c.AgentID)
	c.AgentInstanceID = strings.TrimSpace(c.AgentInstanceID)
	c.AgentToken = strings.TrimSpace(c.AgentToken)
	if c.PollInterval <= 0 {
		c.PollInterval = 15
	}
	if c.GlobalDeviceLimitConfig != nil {
		c.GlobalDeviceLimitConfig.applyDefaults()
		if _, err := RedisTLSConfig(c.GlobalDeviceLimitConfig); err != nil {
			return fmt.Errorf("agent Redis config: %w", err)
		}
	}
	if !c.Enable {
		return nil
	}
	if c.APIHost == "" {
		return fmt.Errorf("agent config error: ApiHost is required when Agent.Enable is true")
	}
	apiHost, err := NormalizePanelAPIHost(c.APIHost)
	if err != nil {
		return fmt.Errorf("agent config error: %w", err)
	}
	c.APIHost = apiHost
	if c.AgentID == "" {
		return fmt.Errorf("agent config error: AgentID is required when Agent.Enable is true")
	}
	if c.AgentToken == "" {
		return fmt.Errorf("agent config error: AgentToken is required when Agent.Enable is true")
	}
	return nil
}

// NormalizePanelAPIHost validates the transport used for panel credentials.
// HTTPS is mandatory for remote panels. Plain HTTP is accepted only for a
// numeric loopback address so isolated local tests and local-only development
// do not weaken production traffic.
func NormalizePanelAPIHost(raw string) (string, error) {
	host := strings.TrimRight(strings.TrimSpace(raw), "/")
	parsed, err := url.Parse(host)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("ApiHost must be an absolute HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("ApiHost must not contain credentials, a query, or a fragment")
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "https" {
		return host, nil
	}
	if scheme == "http" {
		ip := net.ParseIP(parsed.Hostname())
		if ip != nil && ip.IsLoopback() {
			return host, nil
		}
	}
	return "", fmt.Errorf("ApiHost must use HTTPS (plain HTTP is allowed only on a numeric loopback address)")
}

func (c *ConnectionConfig) applyDefaults() {
	if c.Handshake == 0 {
		c.Handshake = 15
	}
	if c.ConnIdle == 0 {
		c.ConnIdle = 120
	}
	if c.UplinkOnly == 0 {
		c.UplinkOnly = 2
	}
	if c.DownlinkOnly == 0 {
		c.DownlinkOnly = 4
	}
	if c.BufferSize <= 0 {
		c.BufferSize = 128
	}
	if c.MaxConnectionsPerUser <= 0 {
		c.MaxConnectionsPerUser = 128
	}
	if c.MaxConnections <= 0 {
		c.MaxConnections = 32768
	}
	if c.MaxConnectionsPerUser > 4096 {
		c.MaxConnectionsPerUser = 4096
	}
	if c.MaxConnections > 262144 {
		c.MaxConnections = 262144
	}
	if c.MaxConnections < c.MaxConnectionsPerUser {
		c.MaxConnections = c.MaxConnectionsPerUser
	}
}

func (c *GlobalDeviceLimitConfig) applyDefaults() {
	c.UserSourceMode = strings.ToLower(strings.TrimSpace(c.UserSourceMode))
	if c.UserSourceMode == "" {
		c.UserSourceMode = "web_primary"
	}
	if c.UserSourceMode != "web_primary" && c.UserSourceMode != "redis_primary" {
		// Invalid remote configuration must fail safe to the live panel rather
		// than unexpectedly trusting a stale snapshot.
		c.UserSourceMode = "web_primary"
	}
	if c.RedisNetwork == "" {
		c.RedisNetwork = "tcp"
	}
	if c.RedisAddr == "" {
		c.RedisAddr = "127.0.0.1:6379"
	}
	c.RedisSentinelMaster = strings.TrimSpace(c.RedisSentinelMaster)
	if len(c.RedisSentinelAddrs) > 0 {
		seen := make(map[string]struct{}, len(c.RedisSentinelAddrs))
		addresses := make([]string, 0, len(c.RedisSentinelAddrs))
		for _, address := range c.RedisSentinelAddrs {
			address = strings.TrimSpace(address)
			if address == "" {
				continue
			}
			if _, exists := seen[address]; exists {
				continue
			}
			seen[address] = struct{}{}
			addresses = append(addresses, address)
		}
		c.RedisSentinelAddrs = addresses
	}
	if c.Timeout <= 0 {
		c.Timeout = 1
	}
	if c.Expiry <= 0 {
		c.Expiry = 60
	}
	if c.Expiry < 10 {
		c.Expiry = 10
	}
	if c.RefreshInterval <= 0 || c.RefreshInterval >= c.Expiry {
		c.RefreshInterval = c.Expiry / 3
		if c.RefreshInterval < 5 {
			c.RefreshInterval = 5
		}
	}
	if c.RefreshInterval < 5 {
		c.RefreshInterval = 5
	}
	if c.HandoverGrace == nil {
		c.HandoverGrace = intPtr(15)
	}
	if *c.HandoverGrace < 0 {
		c.HandoverGrace = intPtr(0)
	}
	if *c.HandoverGrace > c.Expiry {
		c.HandoverGrace = intPtr(c.Expiry)
	}
	// An address that is still transmitting only refreshes its score once per
	// RefreshInterval, so it must get at least two chances to do so inside the
	// grace window. Otherwise a second client that is genuinely active looks
	// silent and gets evicted, which is the sharing case we must still refuse.
	if grace := *c.HandoverGrace; grace > 0 {
		if c.RefreshInterval > grace/2 {
			c.RefreshInterval = grace / 2
			if c.RefreshInterval < 5 {
				c.RefreshInterval = 5
			}
		}
		if c.RefreshInterval*2 > grace {
			c.HandoverGrace = intPtr(c.RefreshInterval * 2)
		}
	}
	if c.MaxIPsPerUser <= 0 {
		c.MaxIPsPerUser = 256
	}
	if c.KeyPrefix == "" {
		c.KeyPrefix = "znode:device"
	}
	if c.SyncChannel == "" {
		c.SyncChannel = "v2board:device-sync"
	}
	// Sync is enabled by default whenever the Redis device limiter is enabled;
	// this removes the panel pull-interval delay for new/deleted device UUIDs.
	if c.SyncEnabled == nil {
		enabled := true
		c.SyncEnabled = &enabled
	}
	if c.UserSnapshotPrefix == "" {
		c.UserSnapshotPrefix = "zboard:user-snapshot"
	}
	if c.UserSnapshotMaxAge <= 0 {
		c.UserSnapshotMaxAge = 7 * 24 * 60 * 60
	}
	if c.UserSnapshotMaxAge > 30*24*60*60 {
		c.UserSnapshotMaxAge = 30 * 24 * 60 * 60
	}
}

func intPtr(v int) *int {
	return &v
}

func boolPtr(v bool) *bool {
	return &v
}

