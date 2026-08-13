package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func multiConfigForTest(nodes ...NodeEntry) Config {
	cfg := Defaults()
	cfg.Panel = PanelConfig{}
	cfg.Nodes = append([]NodeEntry(nil), nodes...)
	return cfg
}

func localAbsolutePath(t *testing.T, elements ...string) string {
	t.Helper()
	return filepath.Join(append([]string{t.TempDir()}, elements...)...)
}

func TestNodeEntryAcceptsNativeAndV2NodeAliases(t *testing.T) {
	tests := []struct {
		name string
		node string
	}{
		{
			name: "native",
			node: `{"api_host":"https://panel.example","node_id":26,"api_key":"secret","timeout":"9s"}`,
		},
		{
			name: "v2node aliases",
			node: `{"ApiHost":"https://panel.example","NodeID":"26","ApiKey":"secret","Timeout":9}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			stateDir := filepath.ToSlash(localAbsolutePath(t, "state"))
			data := `{"nodes":[` + test.node + `],"engine":{"state_dir":` + strconv.Quote(stateDir) + `},"runtime":{},"network":{}}`
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			workers, err := cfg.NodeConfigs()
			if err != nil {
				t.Fatal(err)
			}
			if len(workers) != 1 || workers[0].Panel.URL != "https://panel.example" || workers[0].Panel.NodeID != 26 || workers[0].Panel.Token != "secret" {
				t.Fatalf("expanded worker = %#v", workers)
			}
			if workers[0].Runtime.HTTPTimeout.Duration != 9*time.Second {
				t.Fatalf("HTTP timeout = %s", workers[0].Runtime.HTTPTimeout.Duration)
			}
		})
	}
}

func TestMultiNodeAllowsExplicitInsecureHTTPPerEntry(t *testing.T) {
	cfg := multiConfigForTest(NodeEntry{
		APIHost: "http://panel.example", NodeID: 26, APIKey: "secret", AllowHTTP: true,
	})
	if err := cfg.Validate(); err != nil {
		t.Fatalf("explicit HTTP node rejected: %v", err)
	}
	workers, err := cfg.NodeConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if len(workers) != 1 || !workers[0].Panel.AllowInsecureHTTP {
		t.Fatalf("expanded HTTP policy = %#v", workers)
	}

	cfg.Nodes[0].AllowHTTP = false
	if err := cfg.Validate(); err == nil {
		t.Fatal("plain HTTP node accepted without explicit opt-in")
	}
}

func TestLegacySingletonExpansionIsUnchanged(t *testing.T) {
	cfg := Defaults()
	cfg.Panel = PanelConfig{URL: "https://panel.example", NodeID: 26, Token: "secret"}
	workers, err := cfg.NodeConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if len(workers) != 1 || workers[0].Panel != cfg.Panel || workers[0].Engine != cfg.Engine || workers[0].NodeName() != "default" {
		t.Fatalf("legacy expansion changed config: %#v", workers)
	}
}

func TestNodeExpansionIsStableAcrossReorder(t *testing.T) {
	a := NodeEntry{APIHost: "https://panel-a.example", NodeID: 26, APIKey: "one"}
	b := NodeEntry{APIHost: "https://panel-b.example", NodeID: 27, APIKey: "two"}
	cfg := multiConfigForTest(a, b)
	cfg.Engine.StateDir = localAbsolutePath(t, "state")
	forward, err := cfg.NodeConfigs()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Nodes = []NodeEntry{b, a}
	reverse, err := cfg.NodeConfigs()
	if err != nil {
		t.Fatal(err)
	}
	type localIdentity struct {
		state string
		stats string
		clash string
	}
	indexed := make(map[int64]localIdentity, len(forward))
	for _, worker := range forward {
		indexed[worker.Panel.NodeID] = localIdentity{worker.Engine.StateDir, worker.Engine.StatsListen, worker.Engine.ClashListen}
	}
	for _, worker := range reverse {
		want := indexed[worker.Panel.NodeID]
		got := localIdentity{worker.Engine.StateDir, worker.Engine.StatsListen, worker.Engine.ClashListen}
		if got != want {
			t.Fatalf("node %d local identity changed after reorder: got %#v, want %#v", worker.Panel.NodeID, got, want)
		}
	}
}

func TestCanonicalPanelIdentityNormalizesOriginAndPath(t *testing.T) {
	first := NodeEntry{APIHost: "HTTPS://Panel.Example:443/api/", NodeID: 26, APIKey: "one"}
	second := NodeEntry{APIHost: "https://panel.example/api", NodeID: 26, APIKey: "two"}
	if keyA, keyB := nodeInstanceKey(first), nodeInstanceKey(second); keyA != keyB {
		t.Fatalf("canonical identity keys differ: %q != %q", keyA, keyB)
	}
	if err := multiConfigForTest(first, second).Validate(); err == nil || !strings.Contains(err.Error(), "duplicate panel identity") {
		t.Fatalf("canonical duplicate error = %v", err)
	}
}

func TestDerivedNodeNameFitsLimitAndSeparatesPanels(t *testing.T) {
	first := nodeInstanceKey(NodeEntry{APIHost: "https://panel-a.example", NodeID: 9223372036854775807})
	second := nodeInstanceKey(NodeEntry{APIHost: "https://panel-b.example", NodeID: 9223372036854775807})
	if len(first) > 32 || !nodeNamePattern.MatchString(first) {
		t.Fatalf("derived name is invalid: %q", first)
	}
	if first == second {
		t.Fatalf("different panels derived the same name: %q", first)
	}
}

func TestMultiNodeRejectsDuplicateIsolationKeys(t *testing.T) {
	base := []NodeEntry{
		{Name: "node-a", APIHost: "https://panel-a.example", NodeID: 26, APIKey: "one", StateDir: localAbsolutePath(t, "a"), StatsListen: "127.0.0.1:11001", ClashListen: "127.0.0.1:11002"},
		{Name: "node-b", APIHost: "https://panel-b.example", NodeID: 27, APIKey: "two", StateDir: localAbsolutePath(t, "b"), StatsListen: "127.0.0.1:12001", ClashListen: "127.0.0.1:12002"},
	}
	tests := []struct {
		name   string
		mutate func([]NodeEntry)
		want   string
	}{
		{"panel identity", func(nodes []NodeEntry) { nodes[1].APIHost = nodes[0].APIHost; nodes[1].NodeID = nodes[0].NodeID }, "duplicate"},
		{"instance name", func(nodes []NodeEntry) { nodes[1].Name = nodes[0].Name }, "instance name"},
		{"state directory", func(nodes []NodeEntry) { nodes[1].StateDir = nodes[0].StateDir }, "state directory"},
		{"management port", func(nodes []NodeEntry) { nodes[1].StatsListen = "[::1]:11002" }, "management port"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nodes := append([]NodeEntry(nil), base...)
			test.mutate(nodes)
			err := multiConfigForTest(nodes...).Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestNodeConfigsRejectsMissingIdentityBeforeDerivingLocalState(t *testing.T) {
	tests := []NodeEntry{
		{NodeID: 26, APIKey: "secret"},
		{APIHost: "https://panel.example", NodeID: 0, APIKey: "secret"},
	}
	for _, entry := range tests {
		cfg := multiConfigForTest(entry)
		if _, err := cfg.NodeConfigs(); err == nil {
			t.Fatalf("NodeConfigs accepted incomplete identity: %#v", entry)
		}
	}
}

func TestNodeEntryRejectsConflictingAliasesAndUnknownFields(t *testing.T) {
	for _, node := range []string{
		`{"api_host":"https://one.example","ApiHost":"https://two.example","NodeID":26,"ApiKey":"secret"}`,
		`{"ApiHost":"https://one.example","NodeID":26,"ApiKey":"secret","surprise":true}`,
	} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(`{"nodes":[`+node+`],"engine":{},"runtime":{},"network":{}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("invalid node entry accepted: %s", node)
		}
	}
}
