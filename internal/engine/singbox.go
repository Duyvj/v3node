package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type SingBoxRenderer struct{}

type singBoxUserConfig struct {
	Name     string `json:"name"`
	UUID     string `json:"uuid,omitempty"`
	Flow     string `json:"flow,omitempty"`
	Password string `json:"password,omitempty"`
}

func (SingBoxRenderer) Name() string { return "sing-box" }

func (SingBoxRenderer) Supports(node NodeSpec) error {
	switch node.Protocol {
	case "vmess", "vless", "trojan", "shadowsocks", "hysteria2", "tuic", "anytls":
	default:
		return fmt.Errorf("sing-box does not support protocol %q", node.Protocol)
	}
	switch node.Transport {
	case "", "tcp", "raw", "ws", "grpc", "httpupgrade", "http":
	case "xhttp", "splithttp":
		return errors.New("sing-box does not implement XHTTP/SplitHTTP; use the Xray backend")
	default:
		return fmt.Errorf("sing-box does not support transport %q", node.Transport)
	}
	if node.Protocol == "hysteria2" || node.Protocol == "tuic" {
		if node.Transport != "" && node.Transport != "tcp" && node.Transport != "raw" {
			return fmt.Errorf("sing-box %s is a native QUIC protocol and does not support V2Ray transport %q", node.Protocol, node.Transport)
		}
		if node.TLS.Mode == "reality" {
			return fmt.Errorf("sing-box %s requires certificate TLS and does not support Reality", node.Protocol)
		}
		if acceptsProxyProtocol(node.TransportSettings) {
			return fmt.Errorf("sing-box %s does not support TCP PROXY protocol", node.Protocol)
		}
	}
	if node.Protocol == "anytls" && node.Transport != "" && node.Transport != "tcp" && node.Transport != "raw" {
		return fmt.Errorf("stock sing-box AnyTLS does not support V2Ray transport %q", node.Transport)
	}
	if (node.Transport == "tcp" || node.Transport == "raw" || node.Transport == "") && hasNonPlainTCPHeader(node.TransportSettings) {
		return errors.New("sing-box cannot preserve the configured Xray TCP header; use the Xray backend")
	}
	if len(node.TrustedXForwardedFor) > 0 {
		return errors.New("trusted X-Forwarded-For requires the Xray backend")
	}
	if node.Protocol == "vless" && node.Encryption != "" && !strings.EqualFold(node.Encryption, "none") {
		return errors.New("VLESS encryption requires the Xray backend")
	}
	if node.TLS.RejectUnknownSNI {
		return errors.New("reject_unknown_sni requires the Xray backend")
	}
	if node.TLS.MLDSA65Seed != "" || node.TLS.Xver != 0 {
		return errors.New("Reality ML-DSA/xver settings require the Xray backend")
	}
	if node.TLS.Mode == "reality" && len(node.TLS.ServerNames) > 1 {
		return errors.New("Reality with multiple server names requires the Xray backend")
	}
	if err := singBoxTransportSettingsCompatible(node.Transport, node.TransportSettings); err != nil {
		return err
	}
	for _, route := range node.Routes {
		if route.Action == "route" || route.Action == "route_ip" || route.Action == "default_out" {
			return fmt.Errorf("route %d custom outbound requires the Xray backend", route.ID)
		}
		for _, match := range route.Match {
			if strings.HasPrefix(match, "geosite:") || strings.HasPrefix(match, "geoip:") {
				return fmt.Errorf("route %d uses Xray geodata matcher %q; use the Xray backend", route.ID, match)
			}
		}
	}
	return nil
}

func (r SingBoxRenderer) Render(node NodeSpec, users []UserSpec, opts Options) (Rendered, error) {
	if err := ValidateSpec(node, users); err != nil {
		return Rendered{}, err
	}
	if err := r.Supports(node); err != nil {
		return Rendered{}, err
	}
	if strings.TrimSpace(opts.ClashSecret) == "" || strings.ContainsAny(opts.ClashSecret, "\r\n") {
		return Rendered{}, errors.New("sing-box connections API requires a non-empty local secret")
	}

	inbound := map[string]any{
		"type":        node.Protocol,
		"tag":         InboundTag,
		"listen":      defaultListen(node.Listen),
		"listen_port": node.Port,
	}
	if acceptsProxyProtocol(node.TransportSettings) {
		inbound["proxy_protocol"] = true
	}
	userNames := make([]string, 0, len(users))
	userMap := make(map[string]int, len(users))
	engineUsers := make([]singBoxUserConfig, 0, len(users))
	for _, user := range users {
		name := userName(user.ID)
		entry, err := singBoxUser(node, user, name)
		if err != nil {
			return Rendered{}, err
		}
		engineUsers = append(engineUsers, entry)
		userNames = append(userNames, name)
		userMap[name] = user.ID
	}

	switch node.Protocol {
	case "shadowsocks":
		inbound["method"] = node.Cipher
		if isShadowsocks2022(node.Cipher) {
			if node.ServerKey == "" {
				return Rendered{}, errors.New("Shadowsocks 2022 requires server_key")
			}
			inbound["password"] = node.ServerKey
			inbound["users"] = engineUsers
		} else {
			if len(users) != 1 {
				return Rendered{}, errors.New("sing-box supports one password for legacy Shadowsocks; use Shadowsocks 2022 for multi-user nodes")
			}
			inbound["password"] = users[0].Credential
		}
	default:
		inbound["users"] = engineUsers
	}

	if transport, err := singBoxTransport(node.Transport, node.TransportSettings); err != nil {
		return Rendered{}, err
	} else if transport != nil {
		inbound["transport"] = transport
	}
	if tls, err := singBoxTLS(node.TLS); err != nil {
		return Rendered{}, err
	} else if tls != nil {
		inbound["tls"] = tls
	}
	applySingBoxProtocolOptions(inbound, node)

	routeRules, dnsRules, dnsServers, err := singBoxRoutes(node.Routes, opts.BlockPrivate)
	if err != nil {
		return Rendered{}, err
	}
	protectedCIDRs, protectedPorts, err := protectedManagementEndpoints(opts.StatsListen, opts.ClashListen)
	if err != nil {
		return Rendered{}, err
	}
	// Resolve domain destinations before evaluating IP rules. Without this
	// non-final action, a hostname resolving to loopback, cloud metadata, or an
	// RFC1918 address can bypass the management/private-address rejects below.
	// Protect controller/engine management listeners even when the operator
	// allows other private destinations.
	routeRules = append([]map[string]any{
		{"action": "resolve", "strategy": normalizeAddressStrategy(opts.AddressStrategy)},
		{"ip_cidr": protectedCIDRs, "port": protectedPorts, "action": "reject", "method": "drop"},
		// Sniffing is a bounded per-connection action and is needed for domain
		// routing when clients send an IP destination.
		{"action": "sniff", "timeout": "300ms"},
	}, routeRules...)

	defaultDNSTag := "system-dns"
	if len(opts.DNSServers) > 0 {
		defaultDNSTag = "regional-0"
		for i, server := range opts.DNSServers {
			parsed, err := singBoxDNSServer(server, fmt.Sprintf("regional-%d", i))
			if err != nil {
				return Rendered{}, err
			}
			dnsServers = append(dnsServers, parsed)
		}
	}
	needsBootstrap := false
	for _, server := range dnsServers {
		if server["domain_resolver"] == "system-dns" {
			needsBootstrap = true
			break
		}
	}
	if defaultDNSTag == "system-dns" || needsBootstrap {
		dnsServers = append(dnsServers, map[string]any{"type": "local", "tag": "system-dns"})
	}

	doc := map[string]any{
		"log": map[string]any{
			"level":     normalizeLogLevel(opts.LogLevel),
			"timestamp": true,
		},
		"dns": map[string]any{
			"servers":  dnsServers,
			"rules":    dnsRules,
			"final":    defaultDNSTag,
			"strategy": normalizeAddressStrategy(opts.AddressStrategy),
		},
		"inbounds": []any{inbound},
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": DirectTag},
		},
		"route": map[string]any{
			"rules": routeRules,
			"final": DirectTag,
		},
		"experimental": map[string]any{
			"v2ray_api": map[string]any{
				"listen": opts.StatsListen,
				"stats": map[string]any{
					"enabled": true,
					"users":   userNames,
				},
			},
			"clash_api": map[string]any{
				"external_controller": opts.ClashListen,
				"secret":              opts.ClashSecret,
			},
		},
	}
	data, err := encodeJSON(doc)
	if err != nil {
		return Rendered{}, fmt.Errorf("encode sing-box config: %w", err)
	}
	return Rendered{Backend: r.Name(), Config: data, Users: userMap}, nil
}

func defaultListen(value string) string {
	if value == "" {
		return "::"
	}
	return value
}

func normalizeLogLevel(value string) string {
	if value == "warn" {
		return "warn"
	}
	if value == "debug" || value == "error" {
		return value
	}
	return "info"
}

func normalizeAddressStrategy(value string) string {
	switch value {
	case "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only":
		return value
	default:
		return "prefer_ipv4"
	}
}

func singBoxUser(node NodeSpec, user UserSpec, name string) (singBoxUserConfig, error) {
	entry := singBoxUserConfig{Name: name}
	switch node.Protocol {
	case "vmess":
		entry.UUID = user.Credential
	case "vless":
		entry.UUID = user.Credential
		if node.Flow != "" {
			entry.Flow = node.Flow
		}
	case "trojan", "hysteria2", "anytls":
		entry.Password = user.Credential
	case "tuic":
		entry.UUID = user.Credential
		entry.Password = user.Credential
	case "shadowsocks":
		password := user.Credential
		if isShadowsocks2022(node.Cipher) {
			length, err := shadowsocksKeyLength(node.Cipher)
			if err != nil {
				return singBoxUserConfig{}, err
			}
			if len(user.Credential) < length {
				return singBoxUserConfig{}, fmt.Errorf("Shadowsocks user %d credential is shorter than %d bytes", user.ID, length)
			}
			password = base64.StdEncoding.EncodeToString([]byte(user.Credential[:length]))
		}
		entry.Password = password
	default:
		return singBoxUserConfig{}, fmt.Errorf("unsupported protocol %q", node.Protocol)
	}
	return entry, nil
}

func isShadowsocks2022(cipher string) bool {
	return strings.HasPrefix(strings.ToLower(cipher), "2022-")
}

func shadowsocksKeyLength(cipher string) (int, error) {
	switch strings.ToLower(cipher) {
	case "2022-blake3-aes-128-gcm":
		return 16, nil
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return 32, nil
	default:
		return 0, fmt.Errorf("unsupported Shadowsocks 2022 cipher %q", cipher)
	}
}

func hasNonPlainTCPHeader(raw json.RawMessage) bool {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || bytes.Equal(bytes.TrimSpace(raw), []byte("{}")) {
		return false
	}
	var settings map[string]any
	if json.Unmarshal(raw, &settings) != nil {
		return true
	}
	for _, key := range []string{"path", "Host", "host"} {
		if value, ok := settings[key].(string); ok && value != "" {
			return true
		}
	}
	header, ok := settings["header"].(map[string]any)
	if !ok {
		return false
	}
	typeName, _ := header["type"].(string)
	return typeName != "" && typeName != "none"
}

func singBoxTransportSettingsCompatible(kind string, raw json.RawMessage) error {
	kind = strings.ToLower(kind)
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	settings, err := decodeSettings(raw)
	if err != nil {
		return err
	}
	known := map[string]struct{}{"acceptProxyProtocol": {}}
	switch kind {
	case "", "tcp", "raw":
		known["header"] = struct{}{}
	case "ws":
		for _, key := range []string{"path", "headers", "maxEarlyData", "earlyDataHeaderName"} {
			known[key] = struct{}{}
		}
	case "grpc":
		for _, key := range []string{
			"serviceName", "service_name", "idle_timeout", "idleTimeout",
			"health_check_timeout", "healthCheckTimeout", "permit_without_stream", "permitWithoutStream",
			"multiMode", "multi_mode",
		} {
			known[key] = struct{}{}
		}
		for _, key := range []string{"multiMode", "multi_mode"} {
			if value, ok := settings[key].(bool); ok && value {
				return errors.New("gRPC multiMode requires the Xray backend")
			}
		}
	case "httpupgrade":
		for _, key := range []string{"host", "path", "headers", "header"} {
			known[key] = struct{}{}
		}
		if pathValue, _ := settings["path"].(string); webSocketEarlyData(pathValue) > 0 {
			return errors.New("HTTPUpgrade early data requires the Xray backend")
		}
	case "http":
		for _, key := range []string{"path", "host", "headers"} {
			known[key] = struct{}{}
		}
	default:
		return fmt.Errorf("sing-box does not support transport %q", kind)
	}
	for key := range settings {
		if _, ok := known[key]; !ok {
			return fmt.Errorf("transport %s setting %q requires the Xray backend", kind, key)
		}
	}
	return nil
}

func webSocketEarlyData(pathValue string) int64 {
	parsed, err := url.Parse(pathValue)
	if err != nil {
		return 0
	}
	value := parsed.Query().Get("ed")
	parsedValue, err := strconv.ParseInt(value, 10, 32)
	if err != nil || parsedValue <= 0 {
		return 0
	}
	return parsedValue
}

func acceptsProxyProtocol(raw json.RawMessage) bool {
	settings, err := decodeSettings(raw)
	if err != nil {
		return false
	}
	value, _ := settings["acceptProxyProtocol"].(bool)
	return value
}

func decodeSettings(raw json.RawMessage) (map[string]any, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return map[string]any{}, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var settings map[string]any
	if err := decoder.Decode(&settings); err != nil {
		return nil, fmt.Errorf("decode transport settings: %w", err)
	}
	return settings, nil
}

func singBoxTransport(kind string, raw json.RawMessage) (map[string]any, error) {
	kind = strings.ToLower(kind)
	if kind == "" || kind == "tcp" || kind == "raw" {
		return nil, nil
	}
	settings, err := decodeSettings(raw)
	if err != nil {
		return nil, err
	}
	result := map[string]any{"type": kind}
	switch kind {
	case "ws":
		if pathValue, ok := settings["path"].(string); ok && pathValue != "" {
			parsed, parseErr := url.Parse(pathValue)
			if parseErr != nil {
				return nil, fmt.Errorf("parse WebSocket path: %w", parseErr)
			}
			query := parsed.Query()
			if earlyData := webSocketEarlyData(pathValue); earlyData > 0 {
				if _, configured := settings["maxEarlyData"]; !configured {
					result["max_early_data"] = earlyData
				}
				if _, configured := settings["earlyDataHeaderName"]; !configured {
					result["early_data_header_name"] = "Sec-WebSocket-Protocol"
				}
				query.Del("ed")
				parsed.RawQuery = query.Encode()
			}
			result["path"] = parsed.String()
		}
		copyMap(settings, result, "headers", "headers")
		copyNumber(settings, result, "maxEarlyData", "max_early_data")
		copyString(settings, result, "earlyDataHeaderName", "early_data_header_name")
	case "grpc":
		copyStringAny(settings, result, []string{"serviceName", "service_name"}, "service_name")
		copyStringAny(settings, result, []string{"idle_timeout", "idleTimeout"}, "idle_timeout")
		copyStringAny(settings, result, []string{"health_check_timeout", "healthCheckTimeout"}, "ping_timeout")
		copyBoolAny(settings, result, []string{"permit_without_stream", "permitWithoutStream"}, "permit_without_stream")
	case "httpupgrade":
		copyString(settings, result, "host", "host")
		copyString(settings, result, "path", "path")
		copyMapAny(settings, result, []string{"headers", "header"}, "headers")
	case "http":
		copyStringAny(settings, result, []string{"path"}, "path")
		if host, ok := settings["host"]; ok {
			result["host"] = host
		}
		copyMap(settings, result, "headers", "headers")
	default:
		return nil, fmt.Errorf("unsupported sing-box transport %q", kind)
	}
	return result, nil
}

func copyString(src, dst map[string]any, from, to string) {
	if value, ok := src[from].(string); ok && value != "" {
		dst[to] = value
	}
}

func copyStringAny(src, dst map[string]any, from []string, to string) {
	for _, key := range from {
		if value, ok := src[key].(string); ok && value != "" {
			dst[to] = value
			return
		}
	}
}

func copyBoolAny(src, dst map[string]any, from []string, to string) {
	for _, key := range from {
		if value, ok := src[key].(bool); ok {
			dst[to] = value
			return
		}
	}
}

func copyMap(src, dst map[string]any, from, to string) {
	if value, ok := src[from].(map[string]any); ok && len(value) > 0 {
		dst[to] = value
	}
}

func copyMapAny(src, dst map[string]any, from []string, to string) {
	for _, key := range from {
		if value, ok := src[key].(map[string]any); ok && len(value) > 0 {
			dst[to] = value
			return
		}
	}
}

func copyNumber(src, dst map[string]any, from, to string) {
	if value, ok := src[from].(json.Number); ok {
		dst[to] = value
	}
}

func singBoxTLS(spec TLSSpec) (map[string]any, error) {
	if spec.Mode == "none" || spec.Mode == "" {
		return nil, nil
	}
	tls := map[string]any{"enabled": true}
	if spec.ServerName != "" {
		tls["server_name"] = spec.ServerName
	}
	switch spec.Mode {
	case "tls":
		tls["certificate_path"] = spec.CertificateFile
		tls["key_path"] = spec.KeyFile
	case "reality":
		tls["reality"] = map[string]any{
			"enabled": true,
			"handshake": map[string]any{
				"server":      spec.DestinationHost,
				"server_port": spec.DestinationPort,
			},
			"private_key": spec.PrivateKey,
			"short_id":    spec.ShortIDs,
		}
	default:
		return nil, fmt.Errorf("unsupported TLS mode %q", spec.Mode)
	}
	return tls, nil
}

func applySingBoxProtocolOptions(inbound map[string]any, node NodeSpec) {
	switch node.Protocol {
	case "hysteria2":
		if node.UpMbps > 0 {
			inbound["up_mbps"] = node.UpMbps
		}
		if node.DownMbps > 0 {
			inbound["down_mbps"] = node.DownMbps
		}
		if node.Obfs != "" {
			inbound["obfs"] = map[string]any{"type": node.Obfs, "password": node.ObfsPassword}
		}
		inbound["ignore_client_bandwidth"] = node.IgnoreClientBW
	case "tuic":
		if node.CongestionControl != "" {
			inbound["congestion_control"] = node.CongestionControl
		}
		// The panel value is preserved, but false remains the secure default.
		inbound["zero_rtt_handshake"] = node.ZeroRTT
	case "anytls":
		if len(node.PaddingScheme) > 0 {
			inbound["padding_scheme"] = node.PaddingScheme
		}
	}
}

func singBoxDNSServer(value, tag string) (map[string]any, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty DNS server")
	}
	if net.ParseIP(value) != nil {
		return map[string]any{"type": "udp", "tag": tag, "server": value}, nil
	}
	if host, port, err := net.SplitHostPort(value); err == nil && net.ParseIP(host) != nil {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return nil, fmt.Errorf("invalid DNS port in %q", value)
		}
		return map[string]any{"type": "udp", "tag": tag, "server": host, "server_port": portNumber}, nil
	}
	if strings.HasPrefix(value, "tls://") {
		return singBoxEncryptedDNSServer(value, tag, "tls", 853, "")
	}
	if strings.HasPrefix(value, "https://") {
		return singBoxEncryptedDNSServer(value, tag, "https", 443, "/dns-query")
	}
	return nil, fmt.Errorf("unsupported DNS server %q", value)
}

func singBoxEncryptedDNSServer(value, tag, scheme string, defaultPort int, defaultPath string) (map[string]any, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != scheme || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return nil, fmt.Errorf("invalid %s DNS server %q", scheme, value)
	}
	host := parsed.Hostname()
	if host == "" || strings.ContainsAny(host, "\x00\r\n") {
		return nil, fmt.Errorf("invalid %s DNS host in %q", scheme, value)
	}
	port := defaultPort
	if portText := parsed.Port(); portText != "" {
		port, err = strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid DNS port in %q", value)
		}
	}
	result := map[string]any{
		"type":        scheme,
		"tag":         tag,
		"server":      host,
		"server_port": port,
	}
	if net.ParseIP(host) == nil {
		// Encrypted resolvers addressed by domain need a non-recursive bootstrap
		// resolver under sing-box's post-1.12 DNS schema.
		result["domain_resolver"] = "system-dns"
	}
	if scheme == "tls" {
		if parsed.EscapedPath() != "" && parsed.EscapedPath() != "/" {
			return nil, fmt.Errorf("DNS-over-TLS server %q must not contain a path", value)
		}
		return result, nil
	}
	path := parsed.EscapedPath()
	if path == "" || path == "/" {
		path = defaultPath
	}
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("invalid DNS-over-HTTPS path in %q", value)
	}
	result["path"] = path
	return result, nil
}

func singBoxRoutes(routes []RouteSpec, blockPrivate bool) ([]map[string]any, []map[string]any, []map[string]any, error) {
	// Keep the original v2node DNS contract: UDP queries sent by clients to an
	// arbitrary resolver on port 53 are answered by the engine's configured DNS
	// stack. This avoids resolver/location leaks without opening a second local
	// listener or keeping another process resident.
	rules := make([]map[string]any, 0, len(routes)+3)
	rules = append(rules, map[string]any{
		"network": "udp",
		"port":    []int{53},
		"action":  "hijack-dns",
	})
	dnsRules := make([]map[string]any, 0)
	dnsServers := make([]map[string]any, 0)
	if blockPrivate {
		rules = append(rules, map[string]any{"ip_is_private": true, "action": "reject", "method": "drop"})
		// Explicitly protect cloud metadata even if an engine changes its
		// private-address classification.
		rules = append(rules, map[string]any{"ip_cidr": []string{"169.254.169.254/32", "fd00:ec2::254/128"}, "action": "reject", "method": "drop"})
	}
	dnsIndex := 0
	for _, route := range routes {
		switch route.Action {
		case "block":
			if requiresXrayGeodata([]RouteSpec{route}) {
				return nil, nil, nil, fmt.Errorf("route %d uses Xray GeoIP/GeoSite asset syntax; use the Xray backend", route.ID)
			}
			rule := map[string]any{"action": "reject", "method": "drop"}
			applyDomains(rule, route.Match)
			if !hasMatcher(rule) {
				return nil, nil, nil, fmt.Errorf("route %d has no supported domain matcher", route.ID)
			}
			rules = append(rules, rule)
		case "block_ip":
			for _, cidr := range route.Match {
				if net.ParseIP(cidr) == nil {
					if _, _, err := net.ParseCIDR(cidr); err != nil {
						return nil, nil, nil, fmt.Errorf("route %d has invalid IP/CIDR %q", route.ID, cidr)
					}
				}
			}
			rules = append(rules, map[string]any{"ip_cidr": route.Match, "action": "reject", "method": "drop"})
		case "block_port":
			rule, err := portRule(route.Match)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("route %d: %w", route.ID, err)
			}
			rule["action"] = "reject"
			rule["method"] = "drop"
			rules = append(rules, rule)
		case "protocol":
			rules = append(rules, map[string]any{"protocol": route.Match, "action": "reject", "method": "drop"})
		case "dns":
			if requiresXrayGeodata([]RouteSpec{route}) {
				return nil, nil, nil, fmt.Errorf("route %d uses Xray GeoIP/GeoSite asset syntax; use the Xray backend", route.ID)
			}
			server, err := singBoxDNSServer(route.ActionValue, fmt.Sprintf("panel-dns-%d", dnsIndex))
			if err != nil {
				return nil, nil, nil, fmt.Errorf("route %d: %w", route.ID, err)
			}
			dnsIndex++
			dnsServers = append(dnsServers, server)
			rule := map[string]any{"action": "route", "server": server["tag"]}
			applyDomains(rule, route.Match)
			if !hasMatcher(rule) && len(route.Match) > 0 {
				return nil, nil, nil, fmt.Errorf("route %d has no supported DNS matcher", route.ID)
			}
			dnsRules = append(dnsRules, rule)
		case "route", "route_ip", "default_out":
			return nil, nil, nil, fmt.Errorf("route %d requests a custom outbound; arbitrary panel outbounds are disabled in the independent engine", route.ID)
		default:
			return nil, nil, nil, fmt.Errorf("route %d has unsupported action %q", route.ID, route.Action)
		}
	}
	return rules, dnsRules, dnsServers, nil
}

func applyDomains(rule map[string]any, values []string) {
	var exact, suffix, keyword, regex []string
	for _, value := range values {
		switch {
		case strings.HasPrefix(value, "full:"):
			exact = append(exact, strings.TrimPrefix(value, "full:"))
		case strings.HasPrefix(value, "domain:"):
			suffix = append(suffix, strings.TrimPrefix(value, "domain:"))
		case strings.HasPrefix(value, "keyword:"):
			keyword = append(keyword, strings.TrimPrefix(value, "keyword:"))
		case strings.HasPrefix(value, "regexp:"):
			regex = append(regex, strings.TrimPrefix(value, "regexp:"))
		case strings.HasPrefix(value, "geosite:"):
			// Geosite databases are intentionally not loaded implicitly.
		default:
			suffix = append(suffix, value)
		}
	}
	if len(exact) > 0 {
		rule["domain"] = exact
	}
	if len(suffix) > 0 {
		rule["domain_suffix"] = suffix
	}
	if len(keyword) > 0 {
		rule["domain_keyword"] = keyword
	}
	if len(regex) > 0 {
		rule["domain_regex"] = regex
	}
}

func hasMatcher(rule map[string]any) bool {
	for _, key := range []string{"domain", "domain_suffix", "domain_keyword", "domain_regex"} {
		if _, ok := rule[key]; ok {
			return true
		}
	}
	return false
}

func portRule(values []string) (map[string]any, error) {
	ports := make([]int, 0)
	ranges := make([]string, 0)
	for _, value := range values {
		value = strings.TrimSpace(value)
		if strings.Contains(value, "-") || strings.Contains(value, ":") {
			normalized := strings.ReplaceAll(value, "-", ":")
			parts := strings.Split(normalized, ":")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid port range %q", value)
			}
			start, err1 := strconv.Atoi(parts[0])
			end, err2 := strconv.Atoi(parts[1])
			if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range %q", value)
			}
			ranges = append(ranges, fmt.Sprintf("%d:%d", start, end))
			continue
		}
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q", value)
		}
		ports = append(ports, port)
	}
	rule := make(map[string]any)
	if len(ports) > 0 {
		rule["port"] = ports
	}
	if len(ranges) > 0 {
		rule["port_range"] = ranges
	}
	return rule, nil
}
