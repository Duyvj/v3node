// Package engine translates validated panel state into data-plane
// configuration. The controller does not implement VPN cryptography itself.
package engine

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	InboundTag = "v3node-in"
	DirectTag  = "direct-out"
	BlockTag   = "block-out"
	DNSOutTag  = "dns-out"

	defaultRealityMaxTimeDifference = 5 * time.Minute
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
	Mode              string // none, tls, reality
	ManagedSelfSigned bool
	ServerName        string
	ServerNames       []string
	DestinationHost   string
	DestinationPort   uint16
	ShortIDs          []string
	PrivateKey        string
	MLDSA65Seed       string
	Xver              uint64
	MaxTimeDifference time.Duration
	CertificateFile   string
	KeyFile           string
	RejectUnknownSNI  bool
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
		// Shadowsocks are handled by the project's sing-box build, which exposes
		// authenticated users for bounded online/device and rate policies.
		// Xray also owns panel routes that explicitly reference its GeoIP/
		// GeoSite asset syntax; treating those strings as ordinary domains in
		// sing-box would silently change policy semantics. A non-empty trusted
		// X-Forwarded-For list is routed to Xray so its pinned-version safety
		// check can reject unsupported CIDR semantics explicitly.
		if node.Transport == "xhttp" || node.Transport == "splithttp" || len(node.TrustedXForwardedFor) > 0 || requiresXrayGeodata(node.Routes) {
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
		if err := validateRealitySpec(node); err != nil {
			return err
		}
	}
	if node.Protocol == "vless" && node.Flow != "" {
		if node.Flow != "xtls-rprx-vision" {
			return fmt.Errorf("unsupported VLESS flow %q", node.Flow)
		}
		usesVLESSEncryption := node.Encryption != "" && !strings.EqualFold(node.Encryption, "none")
		usesVisionTransport := (node.Transport == "" || node.Transport == "tcp" || node.Transport == "raw") && (node.TLS.Mode == "tls" || node.TLS.Mode == "reality")
		if !usesVLESSEncryption && !usesVisionTransport {
			return errors.New("VLESS xtls-rprx-vision requires TCP/raw with TLS/Reality or VLESS Encryption")
		}
	}
	if node.Protocol != "vless" && node.Encryption != "" && !strings.EqualFold(node.Encryption, "none") {
		return fmt.Errorf("protocol %s cannot use VLESS Encryption", node.Protocol)
	}
	if node.Protocol == "shadowsocks" && (strings.TrimSpace(node.Cipher) == "" || strings.EqualFold(node.Cipher, "none")) {
		return errors.New("Shadowsocks requires a non-empty authenticated encryption method")
	}
	if node.Protocol == "shadowsocks" && isShadowsocks2022(node.Cipher) {
		keyLength, err := shadowsocksKeyLength(node.Cipher)
		if err != nil {
			return err
		}
		serverKey, err := base64.StdEncoding.DecodeString(node.ServerKey)
		if err != nil || len(serverKey) != keyLength {
			return fmt.Errorf("Shadowsocks 2022 server_key must be standard base64 encoding of exactly %d bytes", keyLength)
		}
	}
	if node.Protocol == "hysteria2" && node.Obfs != "" {
		if node.Obfs != "salamander" {
			return fmt.Errorf("unsupported Hysteria2 obfuscation %q", node.Obfs)
		}
		if strings.TrimSpace(node.ObfsPassword) == "" {
			return errors.New("Hysteria2 salamander obfuscation requires obfs_password")
		}
	}
	defaultDNSRoutes := 0
	for _, route := range node.Routes {
		if err := validateRouteSpec(route); err != nil {
			return err
		}
		if route.Action == "dns" && len(route.Match) == 0 {
			defaultDNSRoutes++
			if defaultDNSRoutes > 1 {
				return errors.New("multiple matcherless DNS routes are ambiguous")
			}
		}
	}
	seenID := make(map[int]struct{}, len(users))
	seenCredential := make(map[string]struct{}, len(users))
	for _, user := range users {
		if user.ID <= 0 || strings.TrimSpace(user.Credential) == "" {
			return errors.New("every user needs a positive ID and non-empty credential")
		}
		if user.SpeedLimit < 0 || user.DeviceLimit < 0 {
			return fmt.Errorf("user %d has a negative policy limit", user.ID)
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

func validateRealitySpec(node NodeSpec) error {
	spec := node.TLS
	if spec.PrivateKey == "" || spec.DestinationHost == "" || spec.DestinationPort == 0 || len(spec.ShortIDs) == 0 {
		return errors.New("Reality private key, destination, port, and short IDs are required")
	}
	if strings.TrimSpace(spec.PrivateKey) != spec.PrivateKey {
		return errors.New("Reality private key must not contain surrounding whitespace")
	}
	privateKey, err := base64.RawURLEncoding.DecodeString(spec.PrivateKey)
	if err != nil || len(privateKey) != 32 {
		return errors.New("Reality private key must be raw URL-safe base64 encoding of exactly 32 bytes")
	}
	if spec.Xver > 2 {
		return errors.New("Reality xver must be 0, 1, or 2")
	}
	if err := validateRealityHost(spec.DestinationHost, "destination"); err != nil {
		return err
	}
	if riskyRealityName(spec.DestinationHost) {
		return fmt.Errorf("Reality destination %q is an Apple/iCloud domain that upstream Xray warns may cause GFW IP blocking", spec.DestinationHost)
	}
	if spec.DestinationPort == node.Port && realityDestinationLoopsBack(spec.DestinationHost, node.Listen) {
		return errors.New("Reality destination points back to the node listener")
	}

	serverNames := spec.ServerNames
	if len(serverNames) == 0 {
		if spec.ServerName == "" {
			return errors.New("Reality requires at least one explicit server name; use server_names with an empty entry only for intentional no-SNI mode")
		}
		serverNames = []string{spec.ServerName}
	}
	seenNames := make(map[string]struct{}, len(serverNames))
	for index, serverName := range serverNames {
		if err := validateRealityServerName(serverName); err != nil {
			return fmt.Errorf("Reality server_names[%d]: %w", index, err)
		}
		canonical := strings.ToLower(strings.TrimSuffix(serverName, "."))
		if _, exists := seenNames[canonical]; exists {
			return fmt.Errorf("Reality server_names[%d] duplicates another server name", index)
		}
		seenNames[canonical] = struct{}{}
		if riskyRealityName(serverName) {
			return fmt.Errorf("Reality server name %q is an Apple/iCloud domain that upstream Xray warns may cause GFW IP blocking", serverName)
		}
	}
	if spec.ServerName != "" {
		if err := validateRealityServerName(spec.ServerName); err != nil {
			return fmt.Errorf("Reality server_name: %w", err)
		}
	}

	seenShortIDs := make(map[[8]byte]struct{}, len(spec.ShortIDs))
	for index, value := range spec.ShortIDs {
		if len(value) > 16 || len(value)%2 != 0 {
			return fmt.Errorf("Reality short_ids[%d] must contain an even number of at most 16 hexadecimal characters", index)
		}
		var canonical [8]byte
		if _, err := hex.Decode(canonical[:], []byte(value)); err != nil {
			return fmt.Errorf("Reality short_ids[%d] must be hexadecimal", index)
		}
		if _, exists := seenShortIDs[canonical]; exists {
			return fmt.Errorf("Reality short_ids[%d] duplicates another short ID after zero padding", index)
		}
		seenShortIDs[canonical] = struct{}{}
	}
	if spec.MLDSA65Seed != "" {
		if spec.MLDSA65Seed == spec.PrivateKey {
			return errors.New("Reality ML-DSA-65 seed must differ from the X25519 private key")
		}
		seed, err := base64.RawURLEncoding.DecodeString(spec.MLDSA65Seed)
		if err != nil || len(seed) != 32 {
			return errors.New("Reality ML-DSA-65 seed must be raw URL-safe base64 encoding of exactly 32 bytes")
		}
	}
	return nil
}

func validateRealityServerName(value string) error {
	if value == "" {
		return nil
	}
	return validateRealityHost(value, "server name")
}

func validateRealityHost(value, field string) error {
	if strings.TrimSpace(value) != value || len(value) > 253 || strings.ContainsAny(value, "\x00\r\n\t /\\?#@*") {
		return fmt.Errorf("Reality %s is not a plain IP address or DNS name", field)
	}
	if ip := net.ParseIP(value); ip != nil {
		if ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("Reality %s must be a routable endpoint", field)
		}
		return nil
	}
	if value == "" || strings.Contains(value, ":") || strings.HasPrefix(value, ".") || strings.Contains(value, "..") {
		return fmt.Errorf("Reality %s is not a plain IP address or DNS name", field)
	}
	for _, label := range strings.Split(strings.TrimSuffix(value, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("Reality %s is not a valid DNS name", field)
		}
		for _, character := range label {
			if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-') {
				return fmt.Errorf("Reality %s is not a valid ASCII DNS name", field)
			}
		}
	}
	return nil
}

func riskyRealityName(value string) bool {
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	return value == "apple.com" || strings.HasSuffix(value, ".apple.com") || value == "icloud.com" || strings.HasSuffix(value, ".icloud.com")
}

func realityDestinationLoopsBack(destination, listen string) bool {
	destination = strings.ToLower(strings.TrimSuffix(destination, "."))
	if destination == "localhost" || strings.HasSuffix(destination, ".localhost") {
		return true
	}
	destinationIP := net.ParseIP(destination)
	if destinationIP != nil && destinationIP.IsLoopback() {
		return true
	}
	listenIP := net.ParseIP(listen)
	return destinationIP != nil && listenIP != nil && destinationIP.Equal(listenIP)
}

func realityMaxTimeDifference(spec TLSSpec) time.Duration {
	if spec.MaxTimeDifference > 0 {
		return spec.MaxTimeDifference
	}
	return defaultRealityMaxTimeDifference
}

// SecurityWarnings reports operational anti-fingerprinting risks which cannot
// be rejected without also rejecting legitimate reverse-proxy or NAT designs.
// It never includes credentials, keys, domains, or other panel secrets.
func SecurityWarnings(node NodeSpec) []string {
	warnings := make([]string, 0, 6)
	if node.TLS.Mode == "reality" {
		if node.Port != 443 {
			warnings = append(warnings, "REALITY is listening on a non-443 node port; pinned Xray warns this may increase GFW blocking risk unless external port 443 is forwarded here")
		}
		if node.TLS.Xver != 0 {
			warnings = append(warnings, "REALITY xver is enabled; the selected target must explicitly accept that PROXY protocol version")
		}
		for _, shortID := range node.TLS.ShortIDs {
			if shortID == "" {
				warnings = append(warnings, "REALITY accepts an empty short ID; use a random non-empty short ID when all clients support it")
				break
			}
		}
	}
	if node.TLS.ManagedSelfSigned {
		warnings = append(warnings, "self-signed TLS is not a normal public HTTPS identity and is not recommended for an anti-GFW public listener")
	}
	if node.TLS.Mode == "none" {
		warnings = append(warnings, "the engine listener has no TLS/REALITY camouflage; expose it only behind verified external TLS termination or on a trusted private link")
	}
	if acceptsProxyProtocol(node.TransportSettings) {
		warnings = append(warnings, "inbound PROXY protocol trusts an unauthenticated source address; expose this listener only to the intended load balancer or reverse proxy")
	}
	if node.Protocol == "shadowsocks" && node.TLS.Mode != "" && node.TLS.Mode != "none" {
		warnings = append(warnings, "Xray Shadowsocks UDP does not inherit TCP transport TLS/REALITY camouflage; use a reviewed TCP-only deployment or a protocol designed for the required UDP path")
	}
	if node.Protocol == "tuic" && node.ZeroRTT {
		warnings = append(warnings, "TUIC zero-RTT is enabled and is replayable by design")
	}
	return warnings
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
	case "route", "route_ip":
		if len(route.Match) == 0 {
			return fmt.Errorf("route %d action %q requires at least one match", route.ID, route.Action)
		}
	case "default_out":
		// A matcherless default route intentionally applies to both TCP and UDP.
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
