package model

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNodeConfigWireCompatibility(t *testing.T) {
	t.Parallel()
	input := []byte(`{
		"protocol":"vless","listen_ip":"::","server_port":443,
		"routes":[{"id":1,"match":["domain:example.com"],"action":"block","action_value":null}],
		"base_config":{"push_interval":"12.5","pull_interval":30,"device_online_min_traffic":1024,"node_report_min_traffic":2048},
		"tls":2,"tls_settings":{"server_name":"one.example","server_names":["a.example","b.example"],"short_id":"aa","short_ids":["bb"],"xver":"1","mldsa65Seed":"seed","reject_unknown_sni":"1"},
		"network":"tcp","network_settings":{"header":{"type":"none"}},
		"trusted_x_forwarded_for":["127.0.0.1"],"encryption":"none",
		"encryption_settings":{"mode":"x","ticket":"y","server_padding":"z","private_key":"k"},
		"server_name":"server.example","flow":"xtls-rprx-vision","cipher":"aes-128-gcm","server_key":"secret",
		"congestion_control":"bbr","zero_rtt_handshake":true,"padding_scheme":["stop=8"],
		"up_mbps":100,"down_mbps":200,"obfs":"salamander","obfs_password":"pw","ignore_client_bandwidth":true
	}`)

	var got NodeConfig
	if err := json.Unmarshal(input, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if got.Protocol != ProtocolVLESS || got.ServerPort != 443 || got.TLSSettings.Xver != 1 {
		t.Fatalf("unexpected decoded node: %+v", got)
	}
	if got.BaseConfig.PushInterval.DurationClamped(5*time.Second, time.Minute) != 12500*time.Millisecond {
		t.Fatalf("unexpected push interval: %v", got.BaseConfig.PushInterval)
	}
	if got.TLSSettings.EffectiveServerNames()[0] != "a.example" || got.TLSSettings.EffectiveShortIDs()[0] != "bb" {
		t.Fatal("plural TLS compatibility fields did not take precedence")
	}
}

func TestNodeConfigValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		node NodeConfig
	}{
		{"unknown protocol", NodeConfig{Protocol: "wireguard", ServerPort: 443}},
		{"zero port", NodeConfig{Protocol: ProtocolVMess}},
		{"large port", NodeConfig{Protocol: ProtocolVMess, ServerPort: 65536}},
		{"unknown security", NodeConfig{Protocol: ProtocolVMess, ServerPort: 443, TLS: 3}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.node.Validate(); err == nil {
				t.Fatal("Validate() unexpectedly succeeded")
			}
		})
	}
}

func TestFlexibleScalarRejectionsAndClamping(t *testing.T) {
	t.Parallel()
	var seconds Seconds
	if err := json.Unmarshal([]byte(`"NaN"`), &seconds); err == nil {
		t.Fatal("NaN interval unexpectedly accepted")
	}
	if err := json.Unmarshal([]byte(`-5`), &seconds); err != nil {
		t.Fatalf("negative interval decode failed: %v", err)
	}
	if got := seconds.DurationClamped(10*time.Second, time.Minute); got != 10*time.Second {
		t.Fatalf("negative interval clamped to %v", got)
	}

	var integer FlexibleUint64
	if err := json.Unmarshal([]byte(`-1`), &integer); err == nil {
		t.Fatal("negative unsigned integer unexpectedly accepted")
	}
	if err := json.Unmarshal([]byte(`7`), &integer); err != nil || integer != 7 {
		t.Fatalf("numeric unsigned integer = %d, %v", integer, err)
	}
}

func TestUserValidationDoesNotExposeCredential(t *testing.T) {
	t.Parallel()
	user := User{ID: 1, UUID: string(make([]byte, 4097))}
	if err := user.Validate(); err == nil {
		t.Fatal("overlong credential unexpectedly accepted")
	} else if len(err.Error()) > 100 {
		t.Fatalf("validation error appears to include credential: %q", err)
	}
}
