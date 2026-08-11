package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaultsAndTokenFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data := `{"panel":{"url":"https://panel.example","node_id":7,"token_file":"token"},"engine":{},"runtime":{},"network":{}}`
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Panel.Token != "secret" || cfg.Runtime.MaxUsers != 100_000 {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestDefaultsMatchOriginalPrivateRoutingContract(t *testing.T) {
	cfg := Defaults()
	if cfg.Network.BlockPrivate == nil || *cfg.Network.BlockPrivate {
		t.Fatal("block_private must default to false for v2node routing compatibility")
	}
}

func TestValidateResourceAndEndpointBounds(t *testing.T) {
	valid := Defaults()
	valid.Panel.URL = "https://panel.example"
	valid.Panel.NodeID = 1
	valid.Panel.Token = "secret"
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"relative engine binary", func(config *Config) { config.Engine.SingBoxBinary = "edge-engine" }},
		{"same management endpoint", func(config *Config) { config.Engine.ClashListen = config.Engine.StatsListen }},
		{"named management port", func(config *Config) { config.Engine.StatsListen = "127.0.0.1:http" }},
		{"too many online IPs", func(config *Config) { config.Runtime.MaxOnlineIPs = 1_000_001 }},
		{"small panel payload limit", func(config *Config) { config.Runtime.MaxPanelPayloadBytes = 1024 }},
		{"large stats response limit", func(config *Config) { config.Runtime.MaxStatsResponseBytes = 65 << 20 }},
		{"per-user IPs exceed total", func(config *Config) {
			config.Runtime.MaxOnlineIPs = 10
			config.Runtime.MaxIPsPerUser = 11
		}},
		{"zero engine check timeout", func(config *Config) { config.Engine.CheckTimeout.Duration = 0 }},
		{"short pull interval", func(config *Config) { config.Runtime.PullIntervalMin.Duration = time.Second }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}

func TestLoadRejectsUnknownAndHTTP(t *testing.T) {
	for _, data := range []string{
		`{"panel":{"url":"https://panel.example","node_id":1,"token":"x"},"bad":true}`,
		`{"panel":{"url":"http://panel.example","node_id":1,"token":"x"}}`,
	} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("expected error for %s", data)
		}
	}
}

func TestEffectiveGOMEMLIMIT(t *testing.T) {
	if got := EffectiveGOMEMLIMIT(2 << 30); got != 128<<20 {
		t.Fatalf("got %d", got)
	}
	if got := EffectiveGOMEMLIMIT(512 << 20); got != 64<<20 {
		t.Fatalf("minimum got %d", got)
	}
}
