package app

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Duyvj/v3node/internal/config"
	"github.com/Duyvj/v3node/internal/engine"
	"github.com/Duyvj/v3node/internal/model"
)

const (
	testRealityPrivateKey = "YH_3NR-KMAo_6CQQrwq7YkL_IWBiAlX3MTEaJpDEFTU"
	testMLDSA65Seed       = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func TestCompileState(t *testing.T) {
	node := model.NodeConfig{
		Protocol:        model.ProtocolVLESS,
		ListenIP:        "::",
		ServerPort:      443,
		Network:         "ws",
		NetworkSettings: json.RawMessage(`{"path":"/vpn"}`),
		TLS:             model.SecurityReality,
		TLSSettings: model.TLSSettings{
			ServerName: "www.example.com",
			Dest:       "www.example.com:443",
			PrivateKey: testRealityPrivateKey,
			ShortID:    "12345678",
		},
		BaseConfig: &model.BaseConfig{PullInterval: 60, PushInterval: 45, NodeReportMinTraffic: 1},
	}
	users := []model.User{{ID: 7, UUID: "c6b9f495-17a1-419b-a37f-7eef683a9456"}}
	local := config.Defaults()
	compiled, err := CompileState(node, users, local)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.PullInterval != time.Minute || compiled.PushInterval != 45*time.Second || compiled.NodeReportMinBytes != 1000 {
		t.Fatalf("unexpected compiled state: %#v", compiled)
	}
}

func TestCompileRealityFallsBackToServerName(t *testing.T) {
	node := model.NodeConfig{
		Protocol:   model.ProtocolVLESS,
		ServerPort: 443,
		Network:    "tcp",
		TLS:        model.SecurityReality,
		TLSSettings: model.TLSSettings{
			ServerName:  "www.example.com",
			ServerPort:  "8443",
			PrivateKey:  testRealityPrivateKey,
			ShortID:     "12345678",
			MLDSA65Seed: testMLDSA65Seed,
			Xver:        2,
		},
	}
	compiled, err := CompileState(node, []model.User{{ID: 1, UUID: "48e90e76-2a72-46be-ac91-45d96486977a"}}, config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Node.TLS.DestinationHost != "www.example.com" || compiled.Node.TLS.DestinationPort != 8443 || compiled.Node.TLS.Xver != 2 || compiled.Node.TLS.MLDSA65Seed != testMLDSA65Seed {
		t.Fatalf("unexpected Reality settings: %#v", compiled.Node.TLS)
	}
}

func TestCompileRealityFallsBackToPluralServerNames(t *testing.T) {
	node := model.NodeConfig{
		Protocol:   model.ProtocolVLESS,
		ServerPort: 443,
		Network:    "tcp",
		TLS:        model.SecurityReality,
		TLSSettings: model.TLSSettings{
			ServerNames: []string{"edge.example", "fallback.example"},
			PrivateKey:  testRealityPrivateKey,
			ShortIDs:    []string{"12345678"},
		},
	}
	compiled, err := CompileState(node, []model.User{{ID: 1, UUID: "48e90e76-2a72-46be-ac91-45d96486977a"}}, config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Node.TLS.ServerName != "edge.example" || compiled.Node.TLS.DestinationHost != "edge.example" || compiled.Node.TLS.DestinationPort != 443 {
		t.Fatalf("unexpected Reality plural-name fallback: %#v", compiled.Node.TLS)
	}
}

func TestCompileRealityPreservesLegacyEmptyShortID(t *testing.T) {
	node := model.NodeConfig{
		Protocol:   model.ProtocolVLESS,
		ServerPort: 443,
		Network:    "tcp",
		TLS:        model.SecurityReality,
		TLSSettings: model.TLSSettings{
			ServerName: "edge.example",
			PrivateKey: testRealityPrivateKey,
		},
	}
	compiled, err := CompileState(node, []model.User{{ID: 1, UUID: "48e90e76-2a72-46be-ac91-45d96486977a"}}, config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Node.TLS.ShortIDs) != 1 || compiled.Node.TLS.ShortIDs[0] != "" {
		t.Fatalf("legacy empty Reality short ID was not preserved: %#v", compiled.Node.TLS.ShortIDs)
	}
}

func TestParseRealityDestinationRejectsAmbiguousValues(t *testing.T) {
	valid := []struct {
		value        string
		fallbackPort string
		host         string
		port         uint16
	}{
		{value: "example.com:8443", host: "example.com", port: 8443},
		{value: "example.com", fallbackPort: "9443", host: "example.com", port: 9443},
		{value: "[2001:db8::1]:8443", host: "2001:db8::1", port: 8443},
		{value: "2001:db8::1", host: "2001:db8::1", port: 443},
		{value: "[2001:db8::1]", fallbackPort: "9443", host: "2001:db8::1", port: 9443},
	}
	for _, test := range valid {
		host, port, err := parseRealityDestination(test.value, test.fallbackPort)
		if err != nil || host != test.host || port != test.port {
			t.Errorf("parseRealityDestination(%q, %q) = %q, %d, %v", test.value, test.fallbackPort, host, port, err)
		}
	}

	for _, value := range []string{
		"https://example.com", "example.com:not-a-port", "example.com:0", ":443",
		"[broken", "example.com/path", "example.com:443:bad", "example.com\n:443",
	} {
		if _, _, err := parseRealityDestination(value, ""); err == nil {
			t.Errorf("accepted invalid Reality destination %q", value)
		}
	}
}

func TestCompilePreservesUserLimits(t *testing.T) {
	node := model.NodeConfig{Protocol: model.ProtocolVLESS, ServerPort: 443, Network: "tcp"}
	compiled, err := CompileState(node, []model.User{{
		ID: 1, UUID: "48e90e76-2a72-46be-ac91-45d96486977a", SpeedLimit: 10, DeviceLimit: 2,
	}}, config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Users) != 1 || compiled.Users[0].SpeedLimit != 10 || compiled.Users[0].DeviceLimit != 2 {
		t.Fatalf("user limits were not preserved: %#v", compiled.Users)
	}
}

func TestValidateBackendPoliciesRejectsXrayLimits(t *testing.T) {
	users := []engine.UserSpec{{ID: 1, Credential: "48e90e76-2a72-46be-ac91-45d96486977a", DeviceLimit: 2}}
	if err := ValidateBackendPolicies("sing-box", users); err != nil {
		t.Fatalf("sing-box device policy was rejected: %v", err)
	}
	if err := ValidateBackendPolicies("xray", users); err == nil {
		t.Fatal("unenforceable Xray device limit was accepted")
	}
	users[0].DeviceLimit = 0
	users[0].SpeedLimit = 10
	if err := ValidateBackendPolicies("xray", users); err == nil {
		t.Fatal("unenforceable Xray speed limit was accepted")
	}
}

func TestCompileRejectsDeviceLimitAboveTrackerCapacity(t *testing.T) {
	node := model.NodeConfig{Protocol: model.ProtocolVLESS, ServerPort: 443, Network: "tcp"}
	local := config.Defaults()
	_, err := CompileState(node, []model.User{{
		ID: 1, UUID: "48e90e76-2a72-46be-ac91-45d96486977a", DeviceLimit: local.Runtime.MaxIPsPerUser + 1,
	}}, local)
	if err == nil {
		t.Fatal("device limit above online tracker capacity was accepted")
	}
}

func TestCompileTLSUsesConventionalCertificatePaths(t *testing.T) {
	local := config.Defaults()
	local.Panel.NodeID = 42
	node := model.NodeConfig{
		Protocol: model.ProtocolTrojan, ServerPort: 443, Network: "tcp", TLS: model.SecurityTLS,
		TLSSettings: model.TLSSettings{CertMode: "file", ServerName: "edge.example"},
	}
	compiled, err := CompileState(node, []model.User{{ID: 1, UUID: "password"}}, local)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Node.TLS.CertificateFile != "/etc/v3node/trojan42.cer" || compiled.Node.TLS.KeyFile != "/etc/v3node/trojan42.key" {
		t.Fatalf("unexpected default certificate paths: %#v", compiled.Node.TLS)
	}
}

func TestCompileTLSNonePreservesExternalTermination(t *testing.T) {
	node := model.NodeConfig{
		Protocol: model.ProtocolVLESS, ServerPort: 443, Network: "ws", TLS: model.SecurityTLS,
		TLSSettings: model.TLSSettings{CertMode: "none", ServerName: "edge.example"},
	}
	compiled, err := CompileState(node, []model.User{{ID: 1, UUID: "48e90e76-2a72-46be-ac91-45d96486977a"}}, config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Node.TLS.Mode != "none" || compiled.Node.TLS.CertificateFile != "" || compiled.Node.TLS.KeyFile != "" {
		t.Fatalf("external TLS termination was changed: %#v", compiled.Node.TLS)
	}
}

func TestCompileTLSSelfUsesPrivateManagedState(t *testing.T) {
	local := config.Defaults()
	local.Panel.NodeID = 42
	node := model.NodeConfig{
		Protocol: model.ProtocolTrojan, ServerPort: 443, Network: "tcp", TLS: model.SecurityTLS,
		TLSSettings: model.TLSSettings{
			CertMode: "self", ServerName: "edge.example",
			CertFile: "/tmp/panel-selected.cer", KeyFile: "/tmp/panel-selected.key",
		},
	}
	compiled, err := CompileState(node, []model.User{{ID: 1, UUID: "password"}}, local)
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.Node.TLS.ManagedSelfSigned || compiled.Node.TLS.Mode != "tls" {
		t.Fatalf("self-signed mode was not preserved: %#v", compiled.Node.TLS)
	}
	if compiled.Node.TLS.CertificateFile != "/var/lib/v3node/certificates/trojan42.cer" || compiled.Node.TLS.KeyFile != "/var/lib/v3node/certificates/trojan42.key" {
		t.Fatalf("unexpected managed certificate paths: %#v", compiled.Node.TLS)
	}
}

func TestCompileRejectsUnauditedAutomaticCertificateMode(t *testing.T) {
	node := model.NodeConfig{
		Protocol: model.ProtocolTrojan, ServerPort: 443, Network: "tcp", TLS: model.SecurityTLS,
		TLSSettings: model.TLSSettings{CertMode: "dns", ServerName: "edge.example"},
	}
	if _, err := CompileState(node, []model.User{{ID: 1, UUID: "password"}}, config.Defaults()); err == nil {
		t.Fatal("automatic certificate mode was accepted")
	}
}
