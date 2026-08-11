package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	testRealityPrivateKey  = "YH_3NR-KMAo_6CQQrwq7YkL_IWBiAlX3MTEaJpDEFTU"
	testMLDSA65Seed        = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testVLESSEncryptionKey = "0B7MUsfiVdKqBK20cdhgsBnJyaz-XXrR3qal7rSVHFM"
)

func baseNode() NodeSpec {
	return NodeSpec{
		Protocol:  "vless",
		Listen:    "::",
		Port:      443,
		Flow:      "xtls-rprx-vision",
		Transport: "tcp",
		TLS: TLSSpec{
			Mode:            "reality",
			ServerName:      "www.example.com",
			DestinationHost: "www.example.com",
			DestinationPort: 443,
			PrivateKey:      testRealityPrivateKey,
			ShortIDs:        []string{"01234567"},
		},
	}
}

func baseOptions() Options {
	return Options{
		LogLevel:        "info",
		StatsListen:     "127.0.0.1:10085",
		ClashListen:     "127.0.0.1:10086",
		ClashSecret:     "test-only-connections-secret",
		AddressStrategy: "prefer_ipv4",
		BlockPrivate:    true,
	}
}

func TestSelect(t *testing.T) {
	node := baseNode()
	renderer, err := Select("auto", node)
	if err != nil || renderer.Name() != "sing-box" {
		t.Fatalf("renderer=%v err=%v", renderer, err)
	}
	node.Transport = "xhttp"
	renderer, err = Select("auto", node)
	if err != nil || renderer.Name() != "xray" {
		t.Fatalf("renderer=%v err=%v", renderer, err)
	}
	node = NodeSpec{Protocol: "shadowsocks", Transport: "tcp", Cipher: "aes-128-gcm"}
	renderer, err = Select("auto", node)
	if err != nil || renderer.Name() != "sing-box" {
		t.Fatalf("legacy Shadowsocks renderer=%v err=%v", renderer, err)
	}
	node.Cipher = "2022-blake3-aes-128-gcm"
	renderer, err = Select("auto", node)
	if err != nil || renderer.Name() != "sing-box" {
		t.Fatalf("Shadowsocks 2022 renderer=%v err=%v", renderer, err)
	}
	node = baseNode()
	node.Encryption = "mlkem768x25519plus"
	renderer, err = Select("auto", node)
	if err != nil || renderer.Name() != "xray" {
		t.Fatalf("VLESS encryption renderer=%v err=%v", renderer, err)
	}
	node = baseNode()
	node.TLS.MLDSA65Seed = testMLDSA65Seed
	renderer, err = Select("auto", node)
	if err != nil || renderer.Name() != "xray" {
		t.Fatalf("Reality ML-DSA renderer=%v err=%v", renderer, err)
	}
	node = baseNode()
	node.Routes = []RouteSpec{{ID: 1, Action: "block", Match: []string{"geosite:category-ads-all"}}}
	renderer, err = Select("auto", node)
	if err != nil || renderer.Name() != "xray" {
		t.Fatalf("GeoSite renderer=%v err=%v", renderer, err)
	}
	if _, err := (SingBoxRenderer{}).Render(node, []UserSpec{{ID: 1, Credential: "48e90e76-2a72-46be-ac91-45d96486977a"}}, baseOptions()); err == nil {
		t.Fatal("forced sing-box silently accepted an Xray GeoSite route")
	}
}

func TestSelectPreservesXrayOnlyTransportAndRealitySettings(t *testing.T) {
	node := baseNode()
	node.TLS.ServerNames = []string{"one.example", "two.example"}
	renderer, err := Select("auto", node)
	if err != nil || renderer.Name() != "xray" {
		t.Fatalf("multi-SNI Reality renderer=%v err=%v", renderer, err)
	}
	if _, err := Select("sing-box", node); err == nil {
		t.Fatal("forced sing-box accepted multi-SNI Reality")
	}
	node = baseNode()
	node.TLS.ServerNames = []string{"other.example"}
	renderer, err = Select("auto", node)
	if err != nil || renderer.Name() != "xray" {
		t.Fatalf("mismatched singular Reality SNI renderer=%v err=%v", renderer, err)
	}

	for _, test := range []struct {
		transport string
		settings  string
	}{
		{transport: "ws", settings: `{"path":"/vpn","host":"edge.example"}`},
		{transport: "grpc", settings: `{"serviceName":"vpn","multiMode":true}`},
		{transport: "grpc", settings: `{"serviceName":"vpn","authority":"edge.example"}`},
		{transport: "httpupgrade", settings: `{"path":"/vpn?ed=2048"}`},
	} {
		node = NodeSpec{Protocol: "vless", Port: 443, Transport: test.transport, TransportSettings: json.RawMessage(test.settings)}
		renderer, err = Select("auto", node)
		if err != nil || renderer.Name() != "xray" {
			t.Fatalf("%s settings %s renderer=%v err=%v", test.transport, test.settings, renderer, err)
		}
	}

	node = NodeSpec{
		Protocol: "shadowsocks", Port: 443, Transport: "tcp", Cipher: "2022-blake3-aes-128-gcm", ServerKey: "server-key",
		TransportSettings: json.RawMessage(`{"path":"/obfs","Host":"edge.example"}`),
	}
	renderer, err = Select("auto", node)
	if err != nil || renderer.Name() != "xray" {
		t.Fatalf("Shadowsocks HTTP obfuscation renderer=%v err=%v", renderer, err)
	}
}

func TestSingBoxConvertsWebSocketEarlyDataPath(t *testing.T) {
	transport, err := singBoxTransport("ws", json.RawMessage(`{"path":"/vpn?ed=2048"}`))
	if err != nil {
		t.Fatal(err)
	}
	if transport["path"] != "/vpn" || transport["max_early_data"] != int64(2048) || transport["early_data_header_name"] != "Sec-WebSocket-Protocol" {
		t.Fatalf("unexpected WebSocket transport: %#v", transport)
	}
}

func TestSelectRoutesUnrepresentableTransportQueriesToXray(t *testing.T) {
	for _, test := range []struct {
		transport string
		path      string
	}{
		{transport: "ws", path: "/vpn?ed=2048&token=x"},
		{transport: "ws", path: "/vpn?ed=0"},
		{transport: "ws", path: "/vpn?ed=invalid"},
		{transport: "httpupgrade", path: "/vpn?token=x"},
	} {
		node := NodeSpec{Protocol: "vless", Port: 443, Transport: test.transport, TransportSettings: json.RawMessage(`{"path":"` + test.path + `"}`)}
		renderer, err := Select("auto", node)
		if err != nil || renderer.Name() != "xray" {
			t.Fatalf("%s path %q renderer=%v err=%v", test.transport, test.path, renderer, err)
		}
	}
}

func TestSingBoxConvertsNumericGRPCTimeouts(t *testing.T) {
	transport, err := singBoxTransport("grpc", json.RawMessage(`{"serviceName":"vpn","idle_timeout":30,"health_check_timeout":5}`))
	if err != nil {
		t.Fatal(err)
	}
	if transport["idle_timeout"] != "30s" || transport["ping_timeout"] != "5s" {
		t.Fatalf("unexpected gRPC transport: %#v", transport)
	}
}

func TestSelectRoutesXrayGeodataMatchersToXray(t *testing.T) {
	for _, route := range []RouteSpec{
		{ID: 1, Action: "block", Match: []string{"geosite:category-ads-all"}},
		{ID: 2, Action: "block_ip", Match: []string{"geoip:private"}},
	} {
		node := baseNode()
		node.Routes = []RouteSpec{route}
		renderer, err := Select("auto", node)
		if err != nil {
			t.Fatalf("route %#v: %v", route, err)
		}
		if renderer.Name() != "xray" {
			t.Fatalf("route %#v selected %s, want xray", route, renderer.Name())
		}
		if _, err := Select("sing-box", node); err == nil {
			t.Fatalf("explicit sing-box accepted route %#v", route)
		}
	}
}

func TestValidateSpecRejectsMatcherlessBlockingRules(t *testing.T) {
	for _, action := range []string{"block", "block_ip", "block_port", "protocol"} {
		node := baseNode()
		node.Routes = []RouteSpec{{ID: 7, Action: action}}
		if err := ValidateSpec(node, []UserSpec{{ID: 1, Credential: "48e90e76-2a72-46be-ac91-45d96486977a"}}); err == nil {
			t.Fatalf("accepted matcherless %s route", action)
		}
	}
	node := baseNode()
	node.Routes = []RouteSpec{{ID: 8, Action: "dns", ActionValue: "1.1.1.1"}}
	if err := ValidateSpec(node, []UserSpec{{ID: 1, Credential: "48e90e76-2a72-46be-ac91-45d96486977a"}}); err != nil {
		t.Fatalf("default DNS route was rejected: %v", err)
	}
}

func TestValidateSpecRejectsMalformedRealitySecurity(t *testing.T) {
	user := []UserSpec{{ID: 1, Credential: "48e90e76-2a72-46be-ac91-45d96486977a"}}
	tests := []struct {
		name   string
		mutate func(*NodeSpec)
	}{
		{name: "private key", mutate: func(node *NodeSpec) { node.TLS.PrivateKey = "not-a-key" }},
		{name: "noncanonical private key", mutate: func(node *NodeSpec) { node.TLS.PrivateKey = strings.TrimSuffix(testRealityPrivateKey, "U") + "V" }},
		{name: "missing server names", mutate: func(node *NodeSpec) { node.TLS.ServerName = ""; node.TLS.ServerNames = nil }},
		{name: "wildcard server name", mutate: func(node *NodeSpec) { node.TLS.ServerName = "*.example.com"; node.TLS.ServerNames = nil }},
		{name: "duplicate server names", mutate: func(node *NodeSpec) { node.TLS.ServerNames = []string{"edge.example", "EDGE.EXAMPLE"} }},
		{name: "risky Apple target", mutate: func(node *NodeSpec) { node.TLS.DestinationHost = "www.icloud.com" }},
		{name: "odd short ID", mutate: func(node *NodeSpec) { node.TLS.ShortIDs = []string{"abc"} }},
		{name: "long short ID", mutate: func(node *NodeSpec) { node.TLS.ShortIDs = []string{"001122334455667788"} }},
		{name: "non-hex short ID", mutate: func(node *NodeSpec) { node.TLS.ShortIDs = []string{"not-hex!"} }},
		{name: "duplicate padded short ID", mutate: func(node *NodeSpec) { node.TLS.ShortIDs = []string{"aa", "aa00"} }},
		{name: "destination URL", mutate: func(node *NodeSpec) { node.TLS.DestinationHost = "https://example.com" }},
		{name: "listener loop", mutate: func(node *NodeSpec) { node.Listen = "127.0.0.1"; node.TLS.DestinationHost = "127.0.0.1" }},
		{name: "invalid ML-DSA seed", mutate: func(node *NodeSpec) { node.TLS.MLDSA65Seed = "bad-seed" }},
		{name: "noncanonical ML-DSA seed", mutate: func(node *NodeSpec) { node.TLS.MLDSA65Seed = strings.TrimSuffix(testMLDSA65Seed, "A") + "B" }},
		{name: "reused ML-DSA seed", mutate: func(node *NodeSpec) { node.TLS.MLDSA65Seed = node.TLS.PrivateKey }},
		{name: "invalid xver", mutate: func(node *NodeSpec) { node.TLS.Xver = 3 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			node := baseNode()
			test.mutate(&node)
			if err := ValidateSpec(node, user); err == nil {
				t.Fatal("invalid REALITY configuration was accepted")
			}
		})
	}

	node := baseNode()
	node.TLS.ServerName = ""
	node.TLS.ServerNames = []string{""}
	if err := ValidateSpec(node, user); err != nil {
		t.Fatalf("explicit no-SNI REALITY mode was rejected: %v", err)
	}
}

func TestSecurityWarningsExposeOperationalAntiGFWRisks(t *testing.T) {
	node := baseNode()
	node.Port = 8443
	node.TLS.ShortIDs = []string{""}
	warnings := strings.Join(SecurityWarnings(node), "\n")
	if !strings.Contains(warnings, "non-443") || !strings.Contains(warnings, "empty short ID") {
		t.Fatalf("missing REALITY security warnings: %q", warnings)
	}

	node = NodeSpec{Protocol: "trojan", Port: 443, Transport: "tcp", TLS: TLSSpec{Mode: "none"}}
	if warnings := strings.Join(SecurityWarnings(node), "\n"); !strings.Contains(warnings, "no TLS/REALITY") {
		t.Fatalf("missing plaintext listener warning: %q", warnings)
	}

	node = NodeSpec{
		Protocol:          "shadowsocks",
		Port:              443,
		Transport:         "tcp",
		TransportSettings: json.RawMessage(`{"acceptProxyProtocol":true}`),
		TLS:               TLSSpec{Mode: "tls"},
	}
	warnings = strings.Join(SecurityWarnings(node), "\n")
	if !strings.Contains(warnings, "inbound PROXY protocol") || !strings.Contains(warnings, "Shadowsocks UDP") {
		t.Fatalf("missing PROXY/UDP security warnings: %q", warnings)
	}

	node = NodeSpec{
		Protocol:           "vless",
		Encryption:         "mlkem768x25519plus",
		EncryptionSettings: json.RawMessage(`{"mode":"native","ticket":"600s","private_key":"` + testVLESSEncryptionKey + `"}`),
	}
	if warnings := strings.Join(SecurityWarnings(node), "\n"); !strings.Contains(warnings, "without a cardinality cap") {
		t.Fatalf("missing VLESS session-retention warning: %q", warnings)
	}
}

func TestXrayRealityRejectsUnsupportedTransport(t *testing.T) {
	for _, transport := range []string{"ws", "websocket", "httpupgrade"} {
		node := baseNode()
		node.Transport = transport
		if err := (XrayRenderer{}).Supports(node); err == nil {
			t.Fatalf("Xray Reality accepted unsupported transport %q", transport)
		}
	}
}

func TestSingBoxNativeProtocolsRejectUnsupportedTransportCombinations(t *testing.T) {
	for _, protocol := range []string{"hysteria2", "tuic"} {
		node := NodeSpec{Protocol: protocol, Transport: "tcp", TLS: baseNode().TLS}
		if err := (SingBoxRenderer{}).Supports(node); err == nil {
			t.Fatalf("%s accepted Reality", protocol)
		}
		node.TLS = TLSSpec{Mode: "tls", CertificateFile: "/test/cert.pem", KeyFile: "/test/key.pem"}
		node.Transport = "ws"
		if err := (SingBoxRenderer{}).Supports(node); err == nil {
			t.Fatalf("%s accepted WebSocket transport", protocol)
		}
	}
	node := NodeSpec{
		Protocol: "anytls", Transport: "grpc",
		TLS: TLSSpec{Mode: "tls", CertificateFile: "/test/cert.pem", KeyFile: "/test/key.pem"},
	}
	if err := (SingBoxRenderer{}).Supports(node); err == nil {
		t.Fatal("stock sing-box AnyTLS accepted a V2Ray transport")
	}
}

func TestSingBoxShadowsocksRejectsUnsupportedTLSAndTransport(t *testing.T) {
	node := NodeSpec{Protocol: "shadowsocks", Port: 8388, Transport: "tcp", Cipher: "aes-128-gcm", TLS: TLSSpec{Mode: "tls", CertificateFile: "/test/cert.pem", KeyFile: "/test/key.pem"}}
	renderer, err := Select("auto", node)
	if err != nil || renderer.Name() != "xray" {
		t.Fatalf("Shadowsocks TLS renderer=%v err=%v", renderer, err)
	}
	if _, err := Select("sing-box", node); err == nil {
		t.Fatal("sing-box accepted Shadowsocks TLS")
	}
	node.TLS = TLSSpec{Mode: "none"}
	node.Transport = "ws"
	if _, err := Select("auto", node); err == nil {
		t.Fatal("a backend accepted Shadowsocks WebSocket")
	}
}

func TestSingBoxTransportSettingsRejectWrongTypesAndAliasConflicts(t *testing.T) {
	tests := []struct {
		transport string
		settings  string
	}{
		{transport: "tcp", settings: `{"header":"none"}`},
		{transport: "ws", settings: `{"path":123}`},
		{transport: "ws", settings: `{"headers":[]}`},
		{transport: "grpc", settings: `{"serviceName":"one","service_name":"two"}`},
		{transport: "grpc", settings: `{"serviceName":1}`},
		{transport: "grpc", settings: `{"permitWithoutStream":"yes"}`},
		{transport: "httpupgrade", settings: `{"headers":"bad"}`},
		{transport: "http", settings: `{"host":["ok",1]}`},
		{transport: "ws", settings: `{"acceptProxyProtocol":"true"}`},
	}
	for _, test := range tests {
		node := NodeSpec{Protocol: "vless", Port: 443, Transport: test.transport, TransportSettings: json.RawMessage(test.settings), TLS: TLSSpec{Mode: "none"}}
		if _, err := Select("sing-box", node); err == nil {
			t.Fatalf("accepted %s settings %s", test.transport, test.settings)
		}
	}
}

func TestSingBoxCertificateTLSHasModernMinimumAndRealityReplayWindow(t *testing.T) {
	tlsConfig, err := singBoxTLS(TLSSpec{Mode: "tls", CertificateFile: "/test/cert.pem", KeyFile: "/test/key.pem"})
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig["min_version"] != "1.2" {
		t.Fatalf("TLS minimum = %#v", tlsConfig["min_version"])
	}
	realityConfig, err := singBoxTLS(baseNode().TLS)
	if err != nil {
		t.Fatal(err)
	}
	reality := realityConfig["reality"].(map[string]any)
	if reality["max_time_difference"] != "5m0s" {
		t.Fatalf("REALITY replay window = %#v", reality["max_time_difference"])
	}
}

func TestSingBoxRenderReality(t *testing.T) {
	got, err := (SingBoxRenderer{}).Render(baseNode(), []UserSpec{{ID: 42, Credential: "9f248408-79be-4f4d-927c-51cba1418b4f"}}, baseOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(got.Config) || !strings.Contains(string(got.Config), `"uid-42"`) || strings.Contains(string(got.Config), `"uuid":"uid-42"`) || !strings.Contains(string(got.Config), `"multiplex":{"enabled":true}`) {
		t.Fatalf("unexpected config: %s", got.Config)
	}
	if got.Users["uid-42"] != 42 {
		t.Fatalf("missing user map: %#v", got.Users)
	}
}

func TestSingBoxRendersBoundedUserRatePolicy(t *testing.T) {
	node := NodeSpec{Protocol: "shadowsocks", Port: 8388, Transport: "tcp", Cipher: "aes-128-gcm", TLS: TLSSpec{Mode: "none"}}
	users := []UserSpec{
		{ID: 7, Credential: "password-one", SpeedLimit: 10},
		{ID: 8, Credential: "password-two"},
	}
	renderer, err := Select("auto", node)
	if err != nil || renderer.Name() != "sing-box" {
		t.Fatalf("legacy Shadowsocks renderer=%v err=%v", renderer, err)
	}
	got, err := renderer.Render(node, users, baseOptions())
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Inbounds []struct {
			Users []singBoxUserConfig `json:"users"`
		} `json:"inbounds"`
		Experimental struct {
			V3Node struct {
				UserRates map[string]int64 `json:"user_rates"`
			} `json:"v3node"`
		} `json:"experimental"`
	}
	if err := json.Unmarshal(got.Config, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Inbounds) != 1 || len(document.Inbounds[0].Users) != 2 {
		t.Fatalf("legacy Shadowsocks users were not preserved: %#v", document.Inbounds)
	}
	if document.Experimental.V3Node.UserRates["uid-7"] != 1_250_000 || len(document.Experimental.V3Node.UserRates) != 1 {
		t.Fatalf("unexpected user rate map: %#v", document.Experimental.V3Node.UserRates)
	}
}

func TestSingBoxResolvesBeforeProtectedIPRules(t *testing.T) {
	opts := baseOptions()
	got, err := (SingBoxRenderer{}).Render(baseNode(), []UserSpec{{ID: 42, Credential: "9f248408-79be-4f4d-927c-51cba1418b4f"}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
		Experimental struct {
			ClashAPI struct {
				Secret string `json:"secret"`
			} `json:"clash_api"`
		} `json:"experimental"`
	}
	if err := json.Unmarshal(got.Config, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Route.Rules) < 4 {
		t.Fatalf("route rules = %#v", document.Route.Rules)
	}
	if rule := document.Route.Rules[0]; rule["action"] != "resolve" || rule["strategy"] != opts.AddressStrategy {
		t.Fatalf("first route rule must resolve domains before IP checks: %#v", rule)
	}
	if rule := document.Route.Rules[1]; rule["action"] != "reject" || rule["ip_cidr"] == nil || rule["port"] == nil {
		t.Fatalf("management reject must follow resolve: %#v", rule)
	}
	foundPrivateReject := false
	for _, rule := range document.Route.Rules[2:] {
		if rule["action"] == "reject" && rule["ip_is_private"] == true {
			foundPrivateReject = true
			break
		}
	}
	if !foundPrivateReject {
		t.Fatalf("private-address reject must follow resolve: %#v", document.Route.Rules)
	}
	if document.Experimental.ClashAPI.Secret != opts.ClashSecret {
		t.Fatalf("Clash API secret was not rendered")
	}
}

func TestXrayRenderXHTTP(t *testing.T) {
	node := baseNode()
	node.Transport = "xhttp"
	node.Flow = ""
	node.TransportSettings = json.RawMessage(`{"path":"/edge"}`)
	got, err := (XrayRenderer{}).Render(node, []UserSpec{{ID: 7, Credential: "48e90e76-2a72-46be-ac91-45d96486977a"}}, baseOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(got.Config) || !strings.Contains(string(got.Config), `"xhttpSettings"`) {
		t.Fatalf("unexpected config: %s", got.Config)
	}
}

func TestXrayStreamKeepsTransportSecurityWithEmptySettings(t *testing.T) {
	tests := []struct {
		name      string
		settings  json.RawMessage
		mode      string
		wantProxy bool
	}{
		{name: "missing-reality", mode: "reality"},
		{name: "null-reality", settings: json.RawMessage(`null`), mode: "reality"},
		{name: "empty-object-tls", settings: json.RawMessage(`{}`), mode: "tls"},
		{name: "proxy-only-tls", settings: json.RawMessage(`{"acceptProxyProtocol":true}`), mode: "tls", wantProxy: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			node := baseNode()
			node.TransportSettings = test.settings
			node.TLS.Mode = test.mode
			if test.mode == "tls" {
				node.TLS.CertificateFile = "/test/cert.pem"
				node.TLS.KeyFile = "/test/key.pem"
			}
			stream, err := xrayStream(node)
			if err != nil {
				t.Fatal(err)
			}
			if stream["security"] != test.mode {
				t.Fatalf("security = %#v, want %q; stream=%#v", stream["security"], test.mode, stream)
			}
			securityKey := test.mode + "Settings"
			if stream[securityKey] == nil {
				t.Fatalf("missing %s: %#v", securityKey, stream)
			}
			if _, exists := stream["rawSettings"]; exists {
				t.Fatalf("empty transport settings must be omitted: %#v", stream)
			}
			sockopt, _ := stream["sockopt"].(map[string]any)
			if got, _ := sockopt["acceptProxyProtocol"].(bool); got != test.wantProxy {
				t.Fatalf("acceptProxyProtocol = %t, want %t", got, test.wantProxy)
			}
		})
	}
}

func TestXrayDisablesImplicitForwardedForTrust(t *testing.T) {
	for _, transport := range []string{"ws", "httpupgrade", "xhttp"} {
		node := NodeSpec{Protocol: "vless", Port: 443, Transport: transport, TLS: TLSSpec{Mode: "none"}}
		stream, err := xrayStream(node)
		if err != nil {
			t.Fatal(err)
		}
		sockopt := stream["sockopt"].(map[string]any)
		headers, ok := sockopt["trustedXForwardedFor"].([]string)
		if !ok || len(headers) != 1 || headers[0] != xrayDisabledForwardedForHeader {
			t.Fatalf("implicit XFF trust was not disabled for %s: %#v", transport, stream)
		}
	}

	node := NodeSpec{Protocol: "vless", Port: 443, Transport: "ws", TLS: TLSSpec{Mode: "none"}}
	node.TrustedXForwardedFor = []string{"192.0.2.0/24"}
	if _, err := Select("xray", node); err == nil {
		t.Fatal("pinned Xray accepted unsupported CIDR trusted XFF")
	}
}

func TestXrayAddressStrategiesPreservePreferenceFallback(t *testing.T) {
	tests := []struct {
		input       string
		wantFreedom string
		wantDNS     string
	}{
		{input: "auto", wantFreedom: "UseIP", wantDNS: "UseIP"},
		{input: "ipv4_only", wantFreedom: "UseIPv4", wantDNS: "UseIPv4"},
		{input: "prefer_ipv4", wantFreedom: "UseIPv4v6", wantDNS: "UseIP"},
		{input: "ipv6_only", wantFreedom: "UseIPv6", wantDNS: "UseIPv6"},
		{input: "prefer_ipv6", wantFreedom: "UseIPv6v4", wantDNS: "UseIP"},
	}
	for _, test := range tests {
		if got := xrayDomainStrategy(test.input); got != test.wantFreedom {
			t.Errorf("xrayDomainStrategy(%q) = %q, want %q", test.input, got, test.wantFreedom)
		}
		if got := xrayDNSQueryStrategy(test.input); got != test.wantDNS {
			t.Errorf("xrayDNSQueryStrategy(%q) = %q, want %q", test.input, got, test.wantDNS)
		}
	}
}

func TestXrayRenderMinimizesAPIAndConnectionBuffer(t *testing.T) {
	node := baseNode()
	got, err := (XrayRenderer{}).Render(node, []UserSpec{{ID: 7, Credential: "48e90e76-2a72-46be-ac91-45d96486977a"}}, baseOptions())
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		API struct {
			Services []string `json:"services"`
		} `json:"api"`
		Policy struct {
			Levels map[string]struct {
				BufferSize int `json:"bufferSize"`
			} `json:"levels"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(got.Config, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.API.Services) != 1 || document.API.Services[0] != "StatsService" {
		t.Fatalf("unexpected API services: %#v", document.API.Services)
	}
	if document.Policy.Levels["0"].BufferSize != 4 {
		t.Fatalf("bufferSize = %d, want 4", document.Policy.Levels["0"].BufferSize)
	}
}

func TestXrayFreedomExplicitlyAllowsPrivateDestinationsWhenConfigured(t *testing.T) {
	settings := xrayFreedomSettings("prefer_ipv4", false)
	rules, ok := settings["finalRules"].([]any)
	if !ok || len(rules) != 1 || rules[0].(map[string]any)["action"] != "allow" {
		t.Fatalf("block_private=false did not override Xray fallback policy: %#v", settings)
	}
	if _, exists := xrayFreedomSettings("prefer_ipv4", true)["finalRules"]; exists {
		t.Fatal("block_private=true unexpectedly disables Xray fallback policy")
	}
}

func TestXrayRenderUsesConfiguredRegionalDNS(t *testing.T) {
	node := baseNode()
	node.Transport = "xhttp"
	node.Flow = ""
	opts := baseOptions()
	opts.DNSServers = []string{"https://dns.example/dns-query"}
	opts.AddressStrategy = "ipv6_only"
	got, err := (XrayRenderer{}).Render(node, []UserSpec{{ID: 7, Credential: "48e90e76-2a72-46be-ac91-45d96486977a"}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		DNS struct {
			Servers       []any  `json:"servers"`
			QueryStrategy string `json:"queryStrategy"`
		} `json:"dns"`
	}
	if err := json.Unmarshal(got.Config, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.DNS.Servers) != 1 || document.DNS.Servers[0] != opts.DNSServers[0] || document.DNS.QueryStrategy != "UseIPv6" {
		t.Fatalf("unexpected DNS config: %#v", document.DNS)
	}
}

func TestXrayRenderBuildsVLESSEncryptionContract(t *testing.T) {
	node := baseNode()
	node.Encryption = "mlkem768x25519plus"
	node.EncryptionSettings = json.RawMessage(`{"mode":"native","ticket":"600s","server_padding":"100-111-1111.75-0-111.50-0-3333","private_key":"` + testVLESSEncryptionKey + `"}`)
	got, err := (XrayRenderer{}).Render(node, []UserSpec{{ID: 7, Credential: "48e90e76-2a72-46be-ac91-45d96486977a"}}, baseOptions())
	if err != nil {
		t.Fatal(err)
	}
	text := string(got.Config)
	if !strings.Contains(text, `"decryption":"mlkem768x25519plus.native.600s.100-111-1111.75-0-111.50-0-3333.`+testVLESSEncryptionKey+`"`) || strings.Contains(text, `"encryptionSettings"`) {
		t.Fatalf("unexpected VLESS encryption config: %s", text)
	}
}

func TestXrayVLESSEncryptionRejectsMalformedComponents(t *testing.T) {
	tests := []string{
		`{"mode":"bad","ticket":"600s","private_key":"` + testVLESSEncryptionKey + `"}`,
		`{"mode":"native","ticket":"600","private_key":"` + testVLESSEncryptionKey + `"}`,
		`{"mode":"native","ticket":"3601s","private_key":"` + testVLESSEncryptionKey + `"}`,
		`{"mode":"native","ticket":"500-100s","private_key":"` + testVLESSEncryptionKey + `"}`,
		`{"mode":"native","ticket":"600s","server_padding":"99-111-1111","private_key":"` + testVLESSEncryptionKey + `"}`,
		`{"mode":"native","ticket":"600s","server_padding":"100-100-50","private_key":"` + testVLESSEncryptionKey + `"}`,
		`{"mode":"native","ticket":"600s","server_padding":"100-111-1111.75-00000000000000-111","private_key":"` + testVLESSEncryptionKey + `"}`,
		`{"mode":"native","ticket":"600s","server_padding":"100-111-1111.100-0-1001.50-0-3333","private_key":"` + testVLESSEncryptionKey + `"}`,
		`{"mode":"native","ticket":"600s","private_key":"bad"}`,
		`{"mode":"native","ticket":"600s","private_key":"` + strings.TrimSuffix(testVLESSEncryptionKey, "M") + `N"}`,
		`{"mode":"native","ticket":"600s","private_key":"` + testVLESSEncryptionKey + `","unknown":true}`,
	}
	for _, settings := range tests {
		node := NodeSpec{Protocol: "vless", Encryption: "mlkem768x25519plus", EncryptionSettings: json.RawMessage(settings)}
		if _, err := xrayVLESSDecryption(node); err == nil {
			t.Fatalf("accepted malformed VLESS encryption settings %s", settings)
		}
	}

	node := NodeSpec{Protocol: "vless", Encryption: "mlkem768x25519plus", EncryptionSettings: json.RawMessage(`{"mode":"random","ticket":"0s","private_key":"` + testVLESSEncryptionKey + `"}`)}
	if _, err := xrayVLESSDecryption(node); err != nil {
		t.Fatalf("valid stateless VLESS encryption was rejected: %v", err)
	}
	node.EncryptionSettings = json.RawMessage(`{"mode":"native","ticket":"600s","server_padding":"100-111-1111.75-0-111","private_key":"` + testVLESSEncryptionKey + `"}`)
	if _, err := xrayVLESSDecryption(node); err != nil {
		t.Fatalf("valid even-component VLESS padding was rejected: %v", err)
	}
	if err := validateVLESSPadding(strings.Repeat("100-35-35.", maxVLESSPaddingComponents) + "100-35-35"); err == nil {
		t.Fatal("VLESS padding component bound was not enforced")
	}
}

func TestXrayMatcherlessPanelDNSBecomesFinalResolver(t *testing.T) {
	_, dns, _, err := xrayRoutes([]RouteSpec{{ID: 7, Action: "dns", ActionValue: "https://dns.example/dns-query"}}, false, nil, "prefer_ipv4")
	if err != nil {
		t.Fatal(err)
	}
	servers := dns["servers"].([]any)
	if len(servers) != 1 {
		t.Fatalf("matcherless panel DNS is not the only default resolver: %#v", servers)
	}
	server, ok := servers[0].(map[string]any)
	if !ok || server["address"] != "https://dns.example/dns-query" || server["finalQuery"] != true {
		t.Fatalf("matcherless panel DNS is not the default resolver: %#v", servers)
	}
	if _, _, _, err := xrayRoutes([]RouteSpec{
		{ID: 7, Action: "dns", ActionValue: "1.1.1.1"},
		{ID: 8, Action: "dns", ActionValue: "8.8.8.8"},
	}, false, nil, "prefer_ipv4"); err == nil {
		t.Fatal("multiple matcherless DNS routes were accepted")
	}
}

func TestValidateSpecChecksProtocolEncryptionOptions(t *testing.T) {
	users := []UserSpec{{ID: 1, Credential: "48e90e76-2a72-46be-ac91-45d96486977a"}}
	node := NodeSpec{
		Protocol: "shadowsocks", Port: 8388, Transport: "tcp", Cipher: "2022-blake3-aes-128-gcm",
		ServerKey: "AAAAAAAAAAAAAAAAAAAAAA==", TLS: TLSSpec{Mode: "none"},
	}
	if err := ValidateSpec(node, users); err != nil {
		t.Fatalf("valid Shadowsocks 2022 server key was rejected: %v", err)
	}
	node.ServerKey = "short"
	if err := ValidateSpec(node, users); err == nil {
		t.Fatal("invalid Shadowsocks 2022 server key was accepted")
	}

	node = NodeSpec{Protocol: "hysteria2", Port: 443, Transport: "tcp", Obfs: "salamander", TLS: TLSSpec{Mode: "tls", CertificateFile: "/test/cert.pem", KeyFile: "/test/key.pem"}}
	if err := ValidateSpec(node, users); err == nil {
		t.Fatal("Hysteria2 salamander without a password was accepted")
	}

	node = NodeSpec{Protocol: "vless", Port: 443, Transport: "ws", Flow: "xtls-rprx-vision", TLS: TLSSpec{Mode: "tls", CertificateFile: "/test/cert.pem", KeyFile: "/test/key.pem"}}
	if err := ValidateSpec(node, users); err == nil {
		t.Fatal("Vision over WebSocket without VLESS Encryption was accepted")
	}
}

func TestRejectCustomOutbound(t *testing.T) {
	node := baseNode()
	node.Routes = []RouteSpec{{ID: 1, Action: "default_out", ActionValue: `{}`}}
	_, err := (SingBoxRenderer{}).Render(node, []UserSpec{{ID: 1, Credential: "48e90e76-2a72-46be-ac91-45d96486977a"}}, baseOptions())
	if err == nil {
		t.Fatal("expected custom outbound rejection")
	}
}

func TestXrayAcceptsBoundedCustomOutboundTargetStrategy(t *testing.T) {
	node := baseNode()
	node.Routes = []RouteSpec{{
		ID:          9,
		Action:      "default_out",
		ActionValue: `{"tag":"regional","protocol":"freedom","settings":{},"targetStrategy":"UseIPv4"}`,
	}}
	got, err := (XrayRenderer{}).Render(node, []UserSpec{{ID: 1, Credential: "48e90e76-2a72-46be-ac91-45d96486977a"}}, baseOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got.Config), `"targetStrategy":"UseIPv4"`) {
		t.Fatalf("custom outbound targetStrategy was not preserved: %s", got.Config)
	}
}

func TestXrayRejectsCustomOutboundProtectedDNSAndUnknownFields(t *testing.T) {
	for _, raw := range []string{
		`{"tag":"dns-out","protocol":"freedom","settings":{}}`,
		`{"tag":"regional","protocol":"freedom","settings":{},"unexpected":true}`,
	} {
		node := baseNode()
		node.Routes = []RouteSpec{{ID: 9, Action: "default_out", ActionValue: raw}}
		if _, err := (XrayRenderer{}).Render(node, []UserSpec{{ID: 1, Credential: "48e90e76-2a72-46be-ac91-45d96486977a"}}, baseOptions()); err == nil {
			t.Fatalf("accepted unsafe custom outbound %s", raw)
		}
	}
}

func TestParseUserStatName(t *testing.T) {
	user, direction, ok := parseUserStatName("user>>>uid-42>>>traffic>>>uplink")
	if !ok || user != "uid-42" || direction != "uplink" {
		t.Fatalf("got %q %q %t", user, direction, ok)
	}
	if _, _, ok := parseUserStatName("inbound>>>x>>>traffic>>>uplink"); ok {
		t.Fatal("accepted non-user statistic")
	}
}

func TestSingBoxParsesEncryptedDNSServerURLs(t *testing.T) {
	tests := []struct {
		value     string
		type_     string
		host      string
		port      int
		path      string
		bootstrap bool
	}{
		{value: "tls://dns.example:8853", type_: "tls", host: "dns.example", port: 8853, bootstrap: true},
		{value: "https://dns.example/custom-query", type_: "https", host: "dns.example", port: 443, path: "/custom-query", bootstrap: true},
		{value: "https://dns.example:4443", type_: "https", host: "dns.example", port: 4443, path: "/dns-query", bootstrap: true},
		{value: "https://[2001:db8::53]:8443/dns-query", type_: "https", host: "2001:db8::53", port: 8443, path: "/dns-query"},
	}
	for _, test := range tests {
		got, err := singBoxDNSServer(test.value, "regional")
		if err != nil {
			t.Fatalf("singBoxDNSServer(%q): %v", test.value, err)
		}
		if got["type"] != test.type_ || got["server"] != test.host || got["server_port"] != test.port {
			t.Fatalf("singBoxDNSServer(%q) = %#v", test.value, got)
		}
		if test.path == "" {
			if _, exists := got["path"]; exists {
				t.Fatalf("DoT result unexpectedly contains a path: %#v", got)
			}
		} else if got["path"] != test.path {
			t.Fatalf("DoH path = %#v, want %q", got["path"], test.path)
		}
		if test.bootstrap && got["domain_resolver"] != "system-dns" {
			t.Fatalf("hostname DNS server has no bootstrap resolver: %#v", got)
		}
		if !test.bootstrap {
			if _, exists := got["domain_resolver"]; exists {
				t.Fatalf("IP-address DNS server unexpectedly needs bootstrap: %#v", got)
			}
		}
	}
	for _, invalid := range []string{
		"tls://dns.example/not-allowed",
		"https://user:password@dns.example/dns-query",
		"https://dns.example/dns-query?secret=value",
	} {
		if _, err := singBoxDNSServer(invalid, "regional"); err == nil {
			t.Fatalf("accepted invalid encrypted DNS URL %q", invalid)
		}
	}
}

func TestSingBoxKeepsRouteSpecificDNSOutOfDefaultSelection(t *testing.T) {
	node := baseNode()
	node.Routes = []RouteSpec{{ID: 9, Action: "dns", Match: []string{"domain:example.com"}, ActionValue: "1.1.1.1"}}
	got, err := (SingBoxRenderer{}).Render(node, []UserSpec{{ID: 42, Credential: "9f248408-79be-4f4d-927c-51cba1418b4f"}}, baseOptions())
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		DNS struct {
			Final   string           `json:"final"`
			Servers []map[string]any `json:"servers"`
		} `json:"dns"`
		Route struct {
			DefaultDomainResolver string `json:"default_domain_resolver"`
		} `json:"route"`
	}
	if err := json.Unmarshal(got.Config, &document); err != nil {
		t.Fatal(err)
	}
	if document.DNS.Final != "system-dns" {
		t.Fatalf("route-specific resolver became default: %#v", document.DNS)
	}
	if document.Route.DefaultDomainResolver != "system-dns" {
		t.Fatalf("route-specific resolver became the outbound domain resolver: %#v", document.Route)
	}
	foundSystem := false
	for _, server := range document.DNS.Servers {
		if server["tag"] == "system-dns" {
			foundSystem = true
		}
	}
	if !foundSystem {
		t.Fatalf("default system resolver is missing: %#v", document.DNS.Servers)
	}

	opts := baseOptions()
	opts.DNSServers = []string{"9.9.9.9"}
	got, err = (SingBoxRenderer{}).Render(node, []UserSpec{{ID: 42, Credential: "9f248408-79be-4f4d-927c-51cba1418b4f"}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got.Config, &document); err != nil {
		t.Fatal(err)
	}
	if document.DNS.Final != "regional-0" {
		t.Fatalf("configured regional resolver is not default: %#v", document.DNS)
	}
	if document.Route.DefaultDomainResolver != "regional-0" {
		t.Fatalf("configured regional resolver is not used for outbound domains: %#v", document.Route)
	}

	node.Routes = []RouteSpec{{ID: 10, Action: "dns", ActionValue: "1.1.1.1"}}
	got, err = (SingBoxRenderer{}).Render(node, []UserSpec{{ID: 42, Credential: "9f248408-79be-4f4d-927c-51cba1418b4f"}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got.Config, &document); err != nil {
		t.Fatal(err)
	}
	if document.Route.DefaultDomainResolver != "panel-dns-0" {
		t.Fatalf("matcherless panel DNS is not used for outbound domains: %#v", document.Route)
	}
}
