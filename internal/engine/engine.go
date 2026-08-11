// Package engine translates validated panel state into data-plane
// configuration. The controller does not implement VPN cryptography itself.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

const (
	InboundTag = "v3node-in"
	DirectTag  = "direct-out"
	BlockTag   = "block-out"
)

type NodeSpec struct {
	Protocol             string
	Listen               string
	Port                 uint16
	Flow                 string
	Cipher               string
	ServerKey            string
	Transport            string
	TransportSettings    json.RawMessage
	TrustedXForwardedFor []string
	TLS                  TLSSpec
	Encryption           string
	EncryptionSettings   json.RawMessage
	CongestionControl    string
	ZeroRTT              bool
	PaddingScheme        []string
	UpMbps               int
	DownMbps             int
	Obfs                 string
	ObfsPassword         string
	IgnoreClientBW       bool
	Routes               []RouteSpec
}

type TLSSpec struct {
	Mode             string // none, tls, reality
	ServerName       string
	ServerNames      []string
	DestinationHost  string
	DestinationPort  uint16
	ShortIDs         []string
	PrivateKey       string
	MLDSA65Seed      string
	Xver             uint64
	CertificateFile  string
	KeyFile          string
	RejectUnknownSNI bool
}

type UserSpec struct {
	ID          int
	Credential  string
	SpeedLimit  int
	DeviceLimit int
}

type RouteSpec struct {
	ID          int
	Match       []string
	Action      string
	ActionValue string
}

type Options struct {
	LogLevel        string
	StatsListen     string
	ClashListen     string
	ClashSecret     string
	AddressStrategy string
	DNSServers      []string
	BlockPrivate    bool
}

func protectedManagementEndpoints(addresses ...string) ([]string, []int, error) {
	cidrs := make(map[string]struct{}, len(addresses))
	ports := make(map[int]struct{}, len(addresses))
	for _, address := range addresses {
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid management listen address %q: %w", address, err)
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, nil, fmt.Errorf("management listen address %q is not loopback", address)
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return nil, nil, fmt.Errorf("management listen address %q has an invalid port", address)
		}
		if ipv4 := ip.To4(); ipv4 != nil {
			cidrs[ipv4.String()+"/32"] = struct{}{}
		} else {
			cidrs[ip.String()+"/128"] = struct{}{}
		}
		ports[port] = struct{}{}
	}
	resultCIDRs := make([]string, 0, len(cidrs))
	for cidr := range cidrs {
		resultCIDRs = append(resultCIDRs, cidr)
	}
	resultPorts := make([]int, 0, len(ports))
	for port := range ports {
		resultPorts = append(resultPorts, port)
	}
	sort.Strings(resultCIDRs)
	sort.Ints(resultPorts)
	return resultCIDRs, resultPorts, nil
}

type Rendered struct {
	Backend string
	Config  []byte
	Users   map[string]int // engine user name -> panel ID
}

type Renderer interface {
	Name() string
	Supports(NodeSpec) error
	Render(NodeSpec, []UserSpec, Options) (Rendered, error)
}

type Process interface {
	Check(context.Context, string) error
	Start(context.Context, string) error
	Stop(context.Context) error
	Healthy() bool
}

func Select(requested string, node NodeSpec) (Renderer, error) {
	requested = strings.ToLower(strings.TrimSpace(requested))
	sing := SingBoxRenderer{}
	xray := XrayRenderer{}
	switch requested {
	case "sing-box":
		if err := sing.Supports(node); err != nil {
			return nil, err
		}
		return sing, nil
	case "xray":
		if err := xray.Supports(node); err != nil {
			return nil, err
		}
		return xray, nil
	case "", "auto":
		// SplitHTTP/XHTTP are Xray transports. QUIC-native protocols and
		// Shadowsocks 2022 are handled by sing-box. Stock Xray preserves
		// legacy Shadowsocks multi-user accounting that sing-box cannot expose.
		// Xray also owns panel routes that explicitly reference its GeoIP/
		// GeoSite asset syntax; treating those strings as ordinary domains in
		// sing-box would silently change policy semantics.
		if node.Transport == "xhttp" || node.Transport == "splithttp" || len(node.TrustedXForwardedFor) > 0 || requiresXrayGeodata(node.Routes) {
			if err := xray.Supports(node); err != nil {
				return nil, err
			}
			return xray, nil
		}
		if node.Protocol == "shadowsocks" && !isShadowsocks2022(node.Cipher) {
			if err := xray.Supports(node); err != nil {
				return nil, err
			}
			return xray, nil
		}
		singErr := sing.Supports(node)
		if singErr == nil {
			return sing, nil
		}
		xrayErr := xray.Supports(node)
		if xrayErr == nil {
			return xray, nil
		}
		return nil, fmt.Errorf("no engine supports protocol %q with transport %q (sing-box: %v; Xray: %v)", node.Protocol, node.Transport, singErr, xrayErr)
	default:
		return nil, fmt.Errorf("unknown engine backend %q", requested)
	}
}

func requiresXrayGeodata(routes []RouteSpec) bool {
	for _, route := range routes {
		for _, match := range route.Match {
			match = strings.ToLower(strings.TrimSpace(match))
			if strings.HasPrefix(match, "geosite:") || strings.HasPrefix(match, "geoip:") || strings.HasPrefix(match, "ext:") {
				return true
			}
		}
	}
	return false
}

func ValidateSpec(node NodeSpec, users []UserSpec) error {
	switch node.Protocol {
	case "vmess", "vless", "trojan", "shadowsocks", "hysteria2", "tuic", "anytls":
	default:
		return fmt.Errorf("unsupported protocol %q", node.Protocol)
	}
	if node.Listen == "" {
		node.Listen = "::"
	}
	if node.Port == 0 {
		return errors.New("listen port is required")
	}
	if node.TLS.Mode != "none" && node.TLS.Mode != "tls" && node.TLS.Mode != "reality" {
		return fmt.Errorf("invalid TLS mode %q", node.TLS.Mode)
	}
	if node.TLS.Mode == "tls" && (node.TLS.CertificateFile == "" || node.TLS.KeyFile == "") {
		return errors.New("TLS certificate and key files are required")
	}
	if node.TLS.Mode == "reality" {
		if node.TLS.PrivateKey == "" || node.TLS.DestinationHost == "" || node.TLS.DestinationPort == 0 || len(node.TLS.ShortIDs) == 0 {
			return errors.New("Reality private key, destination, port, and short IDs are required")
		}
	}
	for _, route := range node.Routes {
		if err := validateRouteSpec(route); err != nil {
			return err
		}
	}
	seenID := make(map[int]struct{}, len(users))
	seenCredential := make(map[string]struct{}, len(users))
	for _, user := range users {
		if user.ID <= 0 || strings.TrimSpace(user.Credential) == "" {
			return errors.New("every user needs a positive ID and non-empty credential")
		}
		if _, ok := seenID[user.ID]; ok {
			return fmt.Errorf("duplicate user ID %d", user.ID)
		}
		if _, ok := seenCredential[user.Credential]; ok {
			return errors.New("duplicate user credential")
		}
		seenID[user.ID] = struct{}{}
		seenCredential[user.Credential] = struct{}{}
	}
	return nil
}

func validateRouteSpec(route RouteSpec) error {
	for _, match := range route.Match {
		if strings.TrimSpace(match) == "" {
			return fmt.Errorf("route %d action %q contains an empty match", route.ID, route.Action)
		}
	}
	switch route.Action {
	case "block", "block_ip", "block_port", "protocol":
		if len(route.Match) == 0 {
			return fmt.Errorf("route %d action %q requires at least one match", route.ID, route.Action)
		}
	case "dns":
		// An empty DNS match intentionally selects this resolver as the default,
		// matching the v2node panel contract.
		if strings.TrimSpace(route.ActionValue) == "" {
			return fmt.Errorf("route %d DNS action has no server", route.ID)
		}
	case "route", "route_ip", "default_out":
		// These are rejected by both renderers because arbitrary panel-provided
		// outbounds are outside this controller's trust boundary.
	default:
		return fmt.Errorf("route %d has unsupported action %q", route.ID, route.Action)
	}
	return nil
}

func userName(id int) string {
	return fmt.Sprintf("uid-%d", id)
}

func encodeJSON(value any) ([]byte, error) {
	// Engine configuration is private machine state. Compact JSON avoids
	// MarshalIndent's second expanded representation and materially lowers the
	// transient heap/config size on nodes with large user lists.
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
