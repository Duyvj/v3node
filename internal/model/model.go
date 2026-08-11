// Package model contains the panel wire model and the small set of domain
// values shared by the controller. It deliberately has no dependency on a
// protocol engine.
package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Protocol is a protocol name understood by the v2node panel contract.
type Protocol string

const (
	ProtocolVMess       Protocol = "vmess"
	ProtocolVLESS       Protocol = "vless"
	ProtocolTrojan      Protocol = "trojan"
	ProtocolShadowsocks Protocol = "shadowsocks"
	ProtocolHysteria2   Protocol = "hysteria2"
	ProtocolTUIC        Protocol = "tuic"
	ProtocolAnyTLS      Protocol = "anytls"
)

// Security values are kept numeric for compatibility with the existing panel.
const (
	SecurityNone    = 0
	SecurityTLS     = 1
	SecurityReality = 2
)

// Valid reports whether the protocol is part of the audited panel contract.
func (p Protocol) Valid() bool {
	switch p {
	case ProtocolVMess, ProtocolVLESS, ProtocolTrojan, ProtocolShadowsocks,
		ProtocolHysteria2, ProtocolTUIC, ProtocolAnyTLS:
		return true
	default:
		return false
	}
}

// Seconds accepts either a JSON number or the numeric string used by some
// V2Board-compatible panels.
type Seconds float64

// UnmarshalJSON implements the panel's number-or-string interval convention.
func (s *Seconds) UnmarshalJSON(data []byte) error {
	if s == nil {
		return errors.New("model.Seconds: nil receiver")
	}
	data = bytes.TrimSpace(data)
	if bytes.Equal(data, []byte("null")) {
		*s = 0
		return nil
	}
	if len(data) == 0 {
		return errors.New("empty interval")
	}

	var text string
	if data[0] == '"' {
		if err := json.Unmarshal(data, &text); err != nil {
			return fmt.Errorf("decode interval string: %w", err)
		}
		text = strings.TrimSpace(text)
	} else {
		text = string(data)
	}
	value, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return errors.New("interval must be a finite number")
	}
	*s = Seconds(value)
	return nil
}

// DurationClamped converts seconds to a safe polling duration. Missing,
// negative, overflowing and out-of-range values resolve to the supplied bounds.
func (s Seconds) DurationClamped(minimum, maximum time.Duration) time.Duration {
	if minimum <= 0 {
		minimum = time.Second
	}
	if maximum < minimum {
		maximum = minimum
	}
	seconds := float64(s)
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds <= 0 {
		return minimum
	}
	if seconds > float64(math.MaxInt64)/float64(time.Second) {
		return maximum
	}
	duration := time.Duration(seconds * float64(time.Second))
	if duration < minimum {
		return minimum
	}
	if duration > maximum {
		return maximum
	}
	return duration
}

// FlexibleUint64 accepts both a JSON integer and a quoted integer. The panel
// historically emits tls_settings.xver as a string.
type FlexibleUint64 uint64

// UnmarshalJSON implements the panel's number-or-string integer convention.
func (v *FlexibleUint64) UnmarshalJSON(data []byte) error {
	if v == nil {
		return errors.New("model.FlexibleUint64: nil receiver")
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return errors.New("empty unsigned integer")
	}
	if bytes.Equal(data, []byte("null")) {
		*v = 0
		return nil
	}
	var text string
	if data[0] == '"' {
		if err := json.Unmarshal(data, &text); err != nil {
			return fmt.Errorf("decode quoted unsigned integer: %w", err)
		}
		text = strings.TrimSpace(text)
	} else {
		text = string(data)
	}
	parsed, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return errors.New("value must be an unsigned integer")
	}
	*v = FlexibleUint64(parsed)
	return nil
}

// MarshalJSON preserves the string representation used by existing panels.
func (v FlexibleUint64) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatUint(uint64(v), 10))
}

// NodeConfig is the direct response body from /api/v2/server/config.
type NodeConfig struct {
	Protocol              Protocol           `json:"protocol"`
	ListenIP              string             `json:"listen_ip"`
	ServerPort            int                `json:"server_port"`
	Routes                []Route            `json:"routes"`
	BaseConfig            *BaseConfig        `json:"base_config"`
	TLS                   int                `json:"tls"`
	TLSSettings           TLSSettings        `json:"tls_settings"`
	Network               string             `json:"network"`
	NetworkSettings       json.RawMessage    `json:"network_settings"`
	TrustedXForwardedFor  []string           `json:"trusted_x_forwarded_for"`
	Encryption            string             `json:"encryption"`
	EncryptionSettings    EncryptionSettings `json:"encryption_settings"`
	ServerName            string             `json:"server_name"`
	Flow                  string             `json:"flow"`
	Cipher                string             `json:"cipher"`
	ServerKey             string             `json:"server_key"`
	CongestionControl     string             `json:"congestion_control"`
	ZeroRTTHandshake      bool               `json:"zero_rtt_handshake"`
	PaddingScheme         []string           `json:"padding_scheme,omitempty"`
	UpMbps                int                `json:"up_mbps"`
	DownMbps              int                `json:"down_mbps"`
	Obfs                  string             `json:"obfs"`
	ObfsPassword          string             `json:"obfs_password"`
	IgnoreClientBandwidth bool               `json:"ignore_client_bandwidth"`
}

// Validate rejects panel data which cannot describe a safe listener.
func (n NodeConfig) Validate() error {
	if !n.Protocol.Valid() {
		return fmt.Errorf("unsupported protocol %q", n.Protocol)
	}
	if n.ServerPort < 1 || n.ServerPort > 65535 {
		return fmt.Errorf("server_port must be between 1 and 65535")
	}
	if n.TLS < SecurityNone || n.TLS > SecurityReality {
		return fmt.Errorf("tls must be %d, %d, or %d", SecurityNone, SecurityTLS, SecurityReality)
	}
	if len(n.ListenIP) > 255 || len(n.Network) > 64 || len(n.ServerName) > 1024 {
		return errors.New("node config contains an overlong network field")
	}
	if len(n.Routes) > 65536 || len(n.TrustedXForwardedFor) > 65536 || len(n.PaddingScheme) > 65536 {
		return errors.New("node config contains too many list entries")
	}
	return nil
}

type Route struct {
	ID          int      `json:"id"`
	Match       []string `json:"match"`
	Action      string   `json:"action"`
	ActionValue *string  `json:"action_value"`
}

type BaseConfig struct {
	PushInterval           Seconds `json:"push_interval"`
	PullInterval           Seconds `json:"pull_interval"`
	DeviceOnlineMinTraffic int     `json:"device_online_min_traffic"`
	NodeReportMinTraffic   int     `json:"node_report_min_traffic"`
}

type TLSSettings struct {
	ServerName       string         `json:"server_name"`
	ServerNames      []string       `json:"server_names"`
	Dest             string         `json:"dest"`
	ServerPort       string         `json:"server_port"`
	ShortID          string         `json:"short_id"`
	ShortIDs         []string       `json:"short_ids"`
	PrivateKey       string         `json:"private_key"`
	MLDSA65Seed      string         `json:"mldsa65Seed"`
	Xver             FlexibleUint64 `json:"xver"`
	CertMode         string         `json:"cert_mode"`
	CertFile         string         `json:"cert_file"`
	KeyFile          string         `json:"key_file"`
	Provider         string         `json:"provider"`
	DNSEnv           string         `json:"dns_env"`
	RejectUnknownSNI string         `json:"reject_unknown_sni"`
}

// EffectiveServerNames handles both the old singular and new plural fields.
func (t TLSSettings) EffectiveServerNames() []string {
	if len(t.ServerNames) != 0 {
		return t.ServerNames
	}
	if t.ServerName == "" {
		return nil
	}
	return []string{t.ServerName}
}

// EffectiveShortIDs handles both the old singular and new plural fields.
func (t TLSSettings) EffectiveShortIDs() []string {
	if len(t.ShortIDs) != 0 {
		return t.ShortIDs
	}
	if t.ShortID == "" {
		return nil
	}
	return []string{t.ShortID}
}

type EncryptionSettings struct {
	Mode          string `json:"mode"`
	Ticket        string `json:"ticket"`
	ServerPadding string `json:"server_padding"`
	PrivateKey    string `json:"private_key"`
}

// User is an entry in the panel's {"users": [...]} response.
type User struct {
	ID          int    `json:"id" msgpack:"id"`
	UUID        string `json:"uuid" msgpack:"uuid"`
	SpeedLimit  int    `json:"speed_limit" msgpack:"speed_limit"`
	DeviceLimit int    `json:"device_limit" msgpack:"device_limit"`
}

// Validate rejects credentials and limits that cannot safely be applied.
func (u User) Validate() error {
	if u.ID <= 0 {
		return errors.New("user id must be positive")
	}
	if u.UUID == "" {
		return errors.New("user credential must not be empty")
	}
	if len(u.UUID) > 4096 {
		return errors.New("user credential is too long")
	}
	if u.SpeedLimit < 0 || u.DeviceLimit < 0 {
		return errors.New("user limits must not be negative")
	}
	return nil
}

// UserTraffic is a monotonically accumulated traffic delta for one user.
type UserTraffic struct {
	UserID   int
	Upload   int64
	Download int64
}

// OnlineUsers is the /alive request body: user ID to distinct client IPs.
type OnlineUsers map[int][]string

// AliveUsers is the /alivelist response: user ID to panel-side device count.
type AliveUsers map[int]int
