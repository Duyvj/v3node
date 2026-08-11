package engine

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// XrayRenderer targets an unmodified upstream Xray process. It intentionally
// supports only protocols for which stock Xray provides compatible user and
// statistics APIs. QUIC-native panel protocols are delegated to sing-box.
type XrayRenderer struct{}

type xrayClientConfig struct {
	Email    string `json:"email"`
	Level    int    `json:"level"`
	ID       string `json:"id,omitempty"`
	Flow     string `json:"flow,omitempty"`
	Password string `json:"password,omitempty"`
	Method   string `json:"method,omitempty"`
}

func (XrayRenderer) Name() string { return "xray" }

func (XrayRenderer) Supports(node NodeSpec) error {
	switch node.Protocol {
	case "vmess", "vless", "trojan", "shadowsocks":
	default:
		return fmt.Errorf("stock Xray backend does not support managed %q nodes", node.Protocol)
	}
	switch node.Transport {
	case "", "tcp", "raw", "ws", "websocket", "grpc", "httpupgrade", "xhttp", "splithttp":
		if node.Protocol == "shadowsocks" && node.Transport != "" && node.Transport != "tcp" && node.Transport != "raw" {
			return fmt.Errorf("Xray Shadowsocks backend does not support transport %q", node.Transport)
		}
		if node.TLS.Mode == "reality" && (node.Transport == "ws" || node.Transport == "websocket" || node.Transport == "httpupgrade") {
			return fmt.Errorf("Xray Reality does not support transport %q", node.Transport)
		}
		return nil
	default:
		return fmt.Errorf("Xray backend does not support transport %q", node.Transport)
	}
}

func (r XrayRenderer) Render(node NodeSpec, users []UserSpec, opts Options) (Rendered, error) {
	if err := ValidateSpec(node, users); err != nil {
		return Rendered{}, err
	}
	if err := r.Supports(node); err != nil {
		return Rendered{}, err
	}

	clients := make([]xrayClientConfig, 0, len(users))
	userMap := make(map[string]int, len(users))
	for _, user := range users {
		name := userName(user.ID)
		client := xrayClientConfig{Email: name}
		switch node.Protocol {
		case "vmess":
			client.ID = user.Credential
		case "vless":
			client.ID = user.Credential
			if node.Flow != "" {
				client.Flow = node.Flow
			}
		case "trojan":
			client.Password = user.Credential
		case "shadowsocks":
			client.Method = node.Cipher
			client.Password = user.Credential
			if isShadowsocks2022(node.Cipher) {
				length, err := shadowsocksKeyLength(node.Cipher)
				if err != nil {
					return Rendered{}, err
				}
				if len(user.Credential) < length {
					return Rendered{}, fmt.Errorf("Shadowsocks user %d credential is shorter than %d bytes", user.ID, length)
				}
				client.Method = ""
				client.Password = base64.StdEncoding.EncodeToString([]byte(user.Credential[:length]))
			}
		}
		clients = append(clients, client)
		userMap[name] = user.ID
	}

	settings := map[string]any{"clients": clients}
	if node.Protocol == "shadowsocks" {
		settings["network"] = "tcp,udp"
		if isShadowsocks2022(node.Cipher) {
			if node.ServerKey == "" {
				return Rendered{}, errors.New("Shadowsocks 2022 requires server_key")
			}
			settings["method"] = node.Cipher
			settings["password"] = node.ServerKey
		}
	}
	if node.Protocol == "vless" {
		decryption, err := xrayVLESSDecryption(node)
		if err != nil {
			return Rendered{}, err
		}
		settings["decryption"] = decryption
	}

	stream, err := xrayStream(node)
	if err != nil {
		return Rendered{}, err
	}
	mainInbound := map[string]any{
		"tag":            InboundTag,
		"listen":         defaultListen(node.Listen),
		"port":           node.Port,
		"protocol":       node.Protocol,
		"settings":       settings,
		"streamSettings": stream,
		"sniffing": map[string]any{
			"enabled":      true,
			"destOverride": []string{"http", "tls", "quic"},
			"routeOnly":    true,
		},
	}

	apiHost, apiPortText, err := net.SplitHostPort(opts.StatsListen)
	if err != nil {
		return Rendered{}, fmt.Errorf("invalid Xray API listen address: %w", err)
	}
	apiPort, err := strconv.Atoi(apiPortText)
	if err != nil || apiPort < 1 || apiPort > 65535 {
		return Rendered{}, errors.New("invalid Xray API port")
	}
	apiInbound := map[string]any{
		"tag":      "management-api-in",
		"listen":   apiHost,
		"port":     apiPort,
		"protocol": "dokodemo-door",
		"settings": map[string]any{"address": apiHost},
	}

	rules, dns, err := xrayRoutes(node.Routes, opts.BlockPrivate, opts.DNSServers, opts.AddressStrategy)
	if err != nil {
		return Rendered{}, err
	}
	protectedCIDRs, protectedPorts, err := protectedManagementEndpoints(opts.StatsListen, opts.ClashListen)
	if err != nil {
		return Rendered{}, err
	}
	protectedPortText := make([]string, len(protectedPorts))
	for index, port := range protectedPorts {
		protectedPortText[index] = strconv.Itoa(port)
	}
	rules = append([]map[string]any{
		{
			"type":        "field",
			"inboundTag":  []string{"management-api-in"},
			"outboundTag": "management-api",
		},
		{
			"type":        "field",
			"inboundTag":  []string{InboundTag},
			"ip":          protectedCIDRs,
			"port":        strings.Join(protectedPortText, ","),
			"outboundTag": BlockTag,
		},
	}, rules...)

	doc := map[string]any{
		"log": map[string]any{
			"loglevel": xrayLogLevel(opts.LogLevel),
		},
		"api": map[string]any{
			"tag":      "management-api",
			"services": []string{"StatsService"},
		},
		"stats": map[string]any{},
		"policy": map[string]any{
			"levels": map[string]any{
				"0": map[string]any{
					"statsUserUplink":   true,
					"statsUserDownlink": true,
					// Xray interprets bufferSize as KiB. Four KiB is its
					// conservative low-memory default on 64-bit ARM and avoids
					// the UDP loss/bandwidth waste documented for a zero buffer.
					"bufferSize": 4,
				},
			},
		},
		"dns":      dns,
		"inbounds": []any{apiInbound, mainInbound},
		"outbounds": []any{
			map[string]any{
				"tag":      DirectTag,
				"protocol": "freedom",
				"settings": xrayFreedomSettings(opts.AddressStrategy, opts.BlockPrivate),
			},
			map[string]any{
				"tag":      BlockTag,
				"protocol": "blackhole",
				"settings": map[string]any{},
			},
		},
		"routing": map[string]any{
			// Resolve unmatched domains before IP rules so the private/metadata
			// destination block cannot be bypassed with a DNS name.
			"domainStrategy": "IPIfNonMatch",
			"rules":          rules,
		},
	}
	data, err := encodeJSON(doc)
	if err != nil {
		return Rendered{}, fmt.Errorf("encode Xray config: %w", err)
	}
	return Rendered{Backend: r.Name(), Config: data, Users: userMap}, nil
}

func xrayVLESSDecryption(node NodeSpec) (string, error) {
	encryption := strings.ToLower(strings.TrimSpace(node.Encryption))
	if encryption == "" || encryption == "none" {
		return "none", nil
	}
	if encryption != "mlkem768x25519plus" {
		return "", fmt.Errorf("unsupported VLESS encryption %q", node.Encryption)
	}
	var settings struct {
		Mode          string `json:"mode"`
		Ticket        string `json:"ticket"`
		ServerPadding string `json:"server_padding"`
		PrivateKey    string `json:"private_key"`
	}
	if err := json.Unmarshal(node.EncryptionSettings, &settings); err != nil {
		return "", fmt.Errorf("decode VLESS encryption settings: %w", err)
	}
	for _, component := range []string{settings.Mode, settings.Ticket, settings.PrivateKey} {
		if component == "" || strings.Contains(component, ".") {
			return "", errors.New("VLESS encryption settings contain an empty or ambiguous component")
		}
	}
	parts := []string{encryption, settings.Mode, settings.Ticket}
	if settings.ServerPadding != "" {
		parts = append(parts, settings.ServerPadding)
	}
	parts = append(parts, settings.PrivateKey)
	return strings.Join(parts, "."), nil
}

func xrayLogLevel(value string) string {
	switch value {
	case "debug", "info", "warning", "error", "none":
		return value
	case "warn":
		return "warning"
	default:
		return "info"
	}
}

func xrayDomainStrategy(value string) string {
	switch value {
	case "ipv4_only":
		return "UseIPv4"
	case "prefer_ipv4":
		return "UseIPv4v6"
	case "ipv6_only":
		return "UseIPv6"
	case "prefer_ipv6":
		return "UseIPv6v4"
	default:
		return "UseIP"
	}
}

func xrayFreedomSettings(addressStrategy string, blockPrivate bool) map[string]any {
	settings := map[string]any{"domainStrategy": xrayDomainStrategy(addressStrategy)}
	if !blockPrivate {
		// Current Xray releases apply a server-side fallback policy which blocks
		// private/reserved destinations. An unconditional final allow restores
		// the configured block_private=false semantics; management listeners are
		// still protected by an earlier routing rule.
		settings["finalRules"] = []any{map[string]any{"action": "allow"}}
	}
	return settings
}

func xrayStream(node NodeSpec) (map[string]any, error) {
	method := strings.ToLower(node.Transport)
	if method == "" || method == "tcp" {
		method = "raw"
	}
	if method == "ws" {
		method = "websocket"
	}
	if method == "splithttp" {
		method = "xhttp"
	}
	stream := map[string]any{"method": method, "security": "none"}
	sockopt := make(map[string]any)
	if acceptsProxyProtocol(node.TransportSettings) {
		sockopt["acceptProxyProtocol"] = true
	}
	if len(node.TrustedXForwardedFor) > 0 {
		sockopt["trustedXForwardedFor"] = node.TrustedXForwardedFor
	}
	if len(sockopt) > 0 {
		stream["sockopt"] = sockopt
	}
	if len(node.TransportSettings) > 0 {
		var settings map[string]any
		decoder := json.NewDecoder(strings.NewReader(string(node.TransportSettings)))
		decoder.UseNumber()
		if err := decoder.Decode(&settings); err != nil {
			return nil, fmt.Errorf("decode Xray transport settings: %w", err)
		}
		key := map[string]string{
			"raw":         "rawSettings",
			"websocket":   "wsSettings",
			"grpc":        "grpcSettings",
			"httpupgrade": "httpupgradeSettings",
			"xhttp":       "xhttpSettings",
		}[method]
		if key == "" {
			return nil, fmt.Errorf("unsupported Xray transport method %q", method)
		}
		delete(settings, "acceptProxyProtocol")
		if node.Protocol == "shadowsocks" && method == "raw" {
			settings = xrayShadowsocksRawSettings(settings)
		}
		if len(settings) > 0 {
			stream[key] = settings
		}
	}
	switch node.TLS.Mode {
	case "", "none":
	case "tls":
		stream["security"] = "tls"
		stream["tlsSettings"] = map[string]any{
			"serverName":       node.TLS.ServerName,
			"rejectUnknownSni": node.TLS.RejectUnknownSNI,
			"minVersion":       "1.2",
			"certificates": []any{map[string]any{
				"certificateFile": node.TLS.CertificateFile,
				"keyFile":         node.TLS.KeyFile,
			}},
		}
	case "reality":
		stream["security"] = "reality"
		serverNames := node.TLS.ServerNames
		if len(serverNames) == 0 && node.TLS.ServerName != "" {
			serverNames = []string{node.TLS.ServerName}
		}
		stream["realitySettings"] = map[string]any{
			"show":        false,
			"target":      net.JoinHostPort(node.TLS.DestinationHost, strconv.Itoa(int(node.TLS.DestinationPort))),
			"serverNames": serverNames,
			"privateKey":  node.TLS.PrivateKey,
			"shortIds":    node.TLS.ShortIDs,
		}
		reality := stream["realitySettings"].(map[string]any)
		if node.TLS.Xver != 0 {
			reality["xver"] = node.TLS.Xver
		}
		if node.TLS.MLDSA65Seed != "" {
			reality["mldsa65Seed"] = node.TLS.MLDSA65Seed
		}
	default:
		return nil, fmt.Errorf("unsupported TLS mode %q", node.TLS.Mode)
	}
	return stream, nil
}

func xrayShadowsocksRawSettings(settings map[string]any) map[string]any {
	path, _ := settings["path"].(string)
	host, _ := settings["Host"].(string)
	if host == "" {
		host, _ = settings["host"].(string)
	}
	if path == "" && host == "" {
		return settings
	}
	if path == "" {
		path = "/"
	}
	request := map[string]any{"path": []string{path}}
	if host != "" {
		request["headers"] = map[string]any{"Host": []string{host}}
	}
	return map[string]any{
		"header": map[string]any{
			"type":    "http",
			"request": request,
		},
	}
}

func xrayRoutes(routes []RouteSpec, blockPrivate bool, configuredDNS []string, addressStrategy string) ([]map[string]any, map[string]any, error) {
	rules := make([]map[string]any, 0, len(routes)+1)
	dnsServers := make([]any, 0, len(configuredDNS)+1)
	for _, server := range configuredDNS {
		if strings.TrimSpace(server) == "" {
			return nil, nil, errors.New("configured DNS server is empty")
		}
		dnsServers = append(dnsServers, server)
	}
	if len(dnsServers) == 0 {
		// Resolving through the VPS resolver keeps DNS egress in the VPS region
		// instead of leaking the controller host's or client's resolver.
		dnsServers = append(dnsServers, "localhost")
	}
	if blockPrivate {
		rules = append(rules, map[string]any{
			"type":       "field",
			"inboundTag": []string{InboundTag},
			"ip": []string{
				"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
				"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
				"::/128", "::1/128", "fc00::/7", "fe80::/10",
			},
			"outboundTag": BlockTag,
		})
	}
	for _, route := range routes {
		rule := map[string]any{"type": "field", "inboundTag": []string{InboundTag}}
		switch route.Action {
		case "block":
			rule["domain"] = route.Match
			rule["outboundTag"] = BlockTag
		case "block_ip":
			rule["ip"] = route.Match
			rule["outboundTag"] = BlockTag
		case "block_port":
			rule["port"] = strings.Join(route.Match, ",")
			rule["outboundTag"] = BlockTag
		case "protocol":
			rule["protocol"] = route.Match
			rule["outboundTag"] = BlockTag
		case "dns":
			if route.ActionValue == "" {
				return nil, nil, fmt.Errorf("DNS route %d has no server", route.ID)
			}
			dnsServers = append(dnsServers, map[string]any{
				"address":      route.ActionValue,
				"domains":      route.Match,
				"skipFallback": true,
			})
			continue
		case "route", "route_ip", "default_out":
			return nil, nil, fmt.Errorf("route %d requests a custom outbound; arbitrary panel outbounds are disabled", route.ID)
		default:
			return nil, nil, fmt.Errorf("route %d has unsupported action %q", route.ID, route.Action)
		}
		rules = append(rules, rule)
	}
	dns := map[string]any{
		"servers":       dnsServers,
		"queryStrategy": xrayDNSQueryStrategy(addressStrategy),
	}
	return rules, dns, nil
}

func xrayDNSQueryStrategy(value string) string {
	switch value {
	case "ipv4_only":
		return "UseIPv4"
	case "ipv6_only":
		return "UseIPv6"
	default:
		// Built-in DNS has no prefer/fallback query mode. UseIP returns both
		// families and lets Freedom apply UseIPv4v6/UseIPv6v4 ordering.
		return "UseIP"
	}
}
