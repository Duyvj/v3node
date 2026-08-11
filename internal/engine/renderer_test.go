package engine

import (
	"encoding/json"
	"strings"
	"testing"
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
			PrivateKey:      "private-key",
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
	node.TLS.MLDSA65Seed = "seed"
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

func TestSingBoxRenderReality(t *testing.T) {
	got, err := (SingBoxRenderer{}).Render(baseNode(), []UserSpec{{ID: 42, Credential: "9f248408-79be-4f4d-927c-51cba1418b4f"}}, baseOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(got.Config) || !strings.Contains(string(got.Config), `"uid-42"`) || strings.Contains(string(got.Config), `"uuid":"uid-42"`) {
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
	node.EncryptionSettings = json.RawMessage(`{"mode":"native","ticket":"ticket","server_padding":"100-111-1111.75-0-111.50-0-3333","private_key":"private"}`)
	got, err := (XrayRenderer{}).Render(node, []UserSpec{{ID: 7, Credential: "48e90e76-2a72-46be-ac91-45d96486977a"}}, baseOptions())
	if err != nil {
		t.Fatal(err)
	}
	text := string(got.Config)
	if !strings.Contains(text, `"decryption":"mlkem768x25519plus.native.ticket.100-111-1111.75-0-111.50-0-3333.private"`) || strings.Contains(text, `"encryptionSettings"`) {
		t.Fatalf("unexpected VLESS encryption config: %s", text)
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
	}
	if err := json.Unmarshal(got.Config, &document); err != nil {
		t.Fatal(err)
	}
	if document.DNS.Final != "system-dns" {
		t.Fatalf("route-specific resolver became default: %#v", document.DNS)
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
}
