package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Duyvj/v3node/internal/config"
)

func TestServiceCommandArgs(t *testing.T) {
	tests := map[string][]string{
		"start":   {"start", serviceName},
		"stop":    {"stop", serviceName},
		"restart": {"restart", serviceName},
		"enable":  {"enable", serviceName},
		"disable": {"disable", serviceName},
		"status":  {"status", serviceName, "--no-pager", "--full"},
	}
	for action, expected := range tests {
		actual, err := serviceCommandArgs(action)
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("%s args = %#v, want %#v", action, actual, expected)
		}
	}
	if _, err := serviceCommandArgs("unknown"); err == nil {
		t.Fatal("unknown action accepted")
	}
}

func TestRunGenerateWritesLoadableConfigAndSeparateToken(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	tokenPath := filepath.Join(directory, "panel.token")
	sourcePath := filepath.Join(directory, "source.token")
	if err := os.WriteFile(sourcePath, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := runGenerate([]string{
		"--config", configPath,
		"--panel-url", "https://panel.example.com/",
		"--node-id", "42",
		"--token-file", tokenPath,
		"--token-source", sourcePath,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("generate: %v (%s)", err, stderr.String())
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Panel.URL != "https://panel.example.com" || loaded.Panel.NodeID != 42 || loaded.Panel.Token != "secret-token" {
		t.Fatalf("unexpected generated panel config: %#v", loaded.Panel)
	}
	if loaded.Runtime.LogLevel != "warn" {
		t.Fatalf("generated log level = %q", loaded.Runtime.LogLevel)
	}
	if !strings.Contains(stdout.String(), "node 42") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if err := runGenerate([]string{
		"--config", configPath,
		"--panel-url", "https://panel.example.com",
		"--node-id", "42",
		"--token-file", tokenPath,
	}, &stdout, &stderr); err == nil {
		t.Fatal("generate overwrote existing config without --force")
	}
}

func TestRunGenerateSingleNodeKeepsLegacyDocumentShape(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	tokenPath := filepath.Join(directory, "panel.token")
	var stdout, stderr bytes.Buffer
	if err := runGenerate([]string{
		"--config", configPath,
		"--panel-url", "https://panel.example.com/",
		"--node-id", "42",
		"--token-file", tokenPath,
		"--skip-ownership",
	}, &stdout, &stderr); err != nil {
		t.Fatalf("generate: %v (%s)", err, stderr.String())
	}
	actual, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	expectedConfig := config.Defaults()
	expectedConfig.Panel = config.PanelConfig{
		URL:       "https://panel.example.com",
		NodeID:    42,
		TokenFile: tokenPath,
	}
	expected, err := json.MarshalIndent(expectedConfig, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	expected = append(expected, '\n')
	if !bytes.Equal(actual, expected) {
		t.Fatalf("single-node generated document changed\nactual:\n%s\nexpected:\n%s", actual, expected)
	}
	if bytes.Contains(actual, []byte(`"nodes"`)) {
		t.Fatalf("single-node document unexpectedly contains nodes: %s", actual)
	}
}

func TestRunGenerateMultipleNodesSharesTokenAndKeepsStableMapping(t *testing.T) {
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "panel.token")
	sourcePath := filepath.Join(directory, "source.token")
	if err := os.WriteFile(sourcePath, []byte("multi-node-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	generate := func(name string, ids ...string) ([]byte, config.Config) {
		t.Helper()
		configPath := filepath.Join(directory, name)
		args := []string{
			"--config", configPath,
			"--panel-url", "https://panel.example.com/",
			"--token-file", tokenPath,
			"--token-source", sourcePath,
			"--force",
			"--skip-ownership",
		}
		for _, id := range ids {
			args = append(args, "--node-id", id)
		}
		var stdout, stderr bytes.Buffer
		if err := runGenerate(args, &stdout, &stderr); err != nil {
			t.Fatalf("generate %s: %v (%s)", name, err, stderr.String())
		}
		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := config.Load(configPath)
		if err != nil {
			t.Fatalf("load %s: %v", name, err)
		}
		return data, loaded
	}

	firstData, first := generate("first.json", "27", "25", "26")
	secondData, second := generate("second.json", "26", "27", "25")
	for name, data := range map[string][]byte{"first": firstData, "second": secondData} {
		if bytes.Contains(data, []byte("multi-node-secret")) {
			t.Fatalf("%s config leaked panel secret: %s", name, data)
		}
		if bytes.Contains(data, []byte(`"api_key"`)) {
			t.Fatalf("%s config contains inline api_key: %s", name, data)
		}
		var document struct {
			Nodes []struct {
				TokenFile string `json:"token_file"`
			} `json:"nodes"`
		}
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		if len(document.Nodes) != 3 {
			t.Fatalf("%s document contains %d nodes, want 3", name, len(document.Nodes))
		}
		for _, node := range document.Nodes {
			if node.TokenFile != tokenPath {
				t.Fatalf("%s document token_file = %q, want shared %q", name, node.TokenFile, tokenPath)
			}
		}
	}
	for name, cfg := range map[string]config.Config{"first": first, "second": second} {
		if len(cfg.Nodes) != 3 {
			t.Fatalf("%s config contains %d nodes, want 3", name, len(cfg.Nodes))
		}
		for _, node := range cfg.Nodes {
			if node.TokenFile != "" || node.APIKey != "multi-node-secret" {
				t.Fatalf("%s node %d did not resolve the shared token safely: %#v", name, node.NodeID, node)
			}
			if node.StateDir == "" || node.StatsListen == "" || node.ClashListen == "" {
				t.Fatalf("%s node %d does not persist explicit isolation mapping: %#v", name, node.NodeID, node)
			}
		}
	}

	mapping := func(cfg config.Config) map[int64][3]string {
		t.Helper()
		workers, err := cfg.NodeConfigs()
		if err != nil {
			t.Fatal(err)
		}
		result := make(map[int64][3]string, len(workers))
		for _, worker := range workers {
			if worker.Panel.Token != "multi-node-secret" {
				t.Fatalf("node %d token was not resolved through the shared token file", worker.Panel.NodeID)
			}
			result[worker.Panel.NodeID] = [3]string{worker.Engine.StateDir, worker.Engine.StatsListen, worker.Engine.ClashListen}
		}
		return result
	}
	firstMapping := mapping(first)
	secondMapping := mapping(second)
	if !reflect.DeepEqual(firstMapping, secondMapping) {
		t.Fatalf("reordering IDs remapped node state or management ports:\nfirst=%#v\nsecond=%#v", firstMapping, secondMapping)
	}
	for nodeID, got := range firstMapping {
		if !strings.HasPrefix(got[0], "/var/lib/v3node/nodes/node-") || got[0] == "/var/lib/v3node" {
			t.Fatalf("node %d did not receive an identity-namespaced state directory: %q", nodeID, got[0])
		}
	}
}

func TestBuildGeneratedNodesSeparatesSameNodeIDAcrossPanels(t *testing.T) {
	engine := config.Defaults().Engine
	first, err := buildGeneratedNodes("https://panel-a.example", []int64{42, 43}, "/etc/v3node/panel.token", engine)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildGeneratedNodes("https://panel-b.example", []int64{42, 43}, "/etc/v3node/panel.token", engine)
	if err != nil {
		t.Fatal(err)
	}
	for index := range first {
		if first[index].Name == second[index].Name || first[index].StateDir == second[index].StateDir {
			t.Fatalf("node ID %d reused local identity across panels: first=%#v second=%#v", first[index].NodeID, first[index], second[index])
		}
	}
}

func TestRunGenerateRejectsDuplicateNodeID(t *testing.T) {
	directory := t.TempDir()
	err := runGenerate([]string{
		"--config", filepath.Join(directory, "config.json"),
		"--panel-url", "https://panel.example.com",
		"--node-id", "42",
		"--node-id", "42",
		"--token-file", filepath.Join(directory, "panel.token"),
		"--skip-ownership",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("generate duplicate error = %v", err)
	}
}

func TestRunGenerateMultipleNodesCanExplicitlyAllowHTTP(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	tokenPath := filepath.Join(directory, "panel.token")
	if err := os.WriteFile(tokenPath, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runGenerate([]string{
		"--config", configPath,
		"--panel-url", "http://panel.example.com",
		"--allow-insecure-http",
		"--node-id", "41",
		"--node-id", "42",
		"--token-file", tokenPath,
		"--skip-ownership",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range loaded.Nodes {
		if !node.AllowHTTP {
			t.Fatalf("node %d lost explicit HTTP opt-in", node.NodeID)
		}
	}
}

func TestRunGenerateRejectsTokenInPanelURL(t *testing.T) {
	err := runGenerate([]string{
		"--config", filepath.Join(t.TempDir(), "config.json"),
		"--panel-url", "https://user:token@panel.example.com",
		"--node-id", "1",
		"--token-file", filepath.Join(t.TempDir(), "token"),
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("credential-bearing panel URL accepted")
	}
}

func TestRunGenerateRejectsSameConfigAndTokenPath(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "generated.json")
	sourcePath := filepath.Join(directory, "source.token")
	old := []byte("existing contents\n")
	if err := os.WriteFile(destination, old, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte("new-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runGenerate([]string{
		"--config", destination,
		"--panel-url", "https://panel.example.com",
		"--node-id", "1",
		"--token-file", destination,
		"--token-source", sourcePath,
		"--force",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "must be different") {
		t.Fatalf("generate error = %v, want different-path rejection", err)
	}
	assertFileContents(t, destination, old)
}

func TestRunGenerateInvalidTokenLeavesExistingFilesUnchanged(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	tokenPath := filepath.Join(directory, "panel.token")
	sourcePath := filepath.Join(directory, "empty.token")
	oldConfig := []byte("old config\n")
	oldToken := []byte("old token\n")
	for path, contents := range map[string][]byte{
		configPath: oldConfig,
		tokenPath:  oldToken,
		sourcePath: []byte(" \r\n\t"),
	} {
		if err := os.WriteFile(path, contents, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	err := runGenerate([]string{
		"--config", configPath,
		"--panel-url", "https://panel.example.com",
		"--node-id", "1",
		"--token-file", tokenPath,
		"--token-source", sourcePath,
		"--force",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "token source is empty") {
		t.Fatalf("generate error = %v, want empty-token rejection", err)
	}
	assertFileContents(t, configPath, oldConfig)
	assertFileContents(t, tokenPath, oldToken)
}

func TestRunGenerateRollsBackBothFilesWhenCommitFails(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	tokenPath := filepath.Join(directory, "panel.token")
	sourcePath := filepath.Join(directory, "source.token")
	oldConfig := []byte("old config\n")
	oldToken := []byte("old token\n")
	for path, contents := range map[string][]byte{
		configPath: oldConfig,
		tokenPath:  oldToken,
		sourcePath: []byte("new token\n"),
	} {
		if err := os.WriteFile(path, contents, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	originalRename := renameAdminFile
	t.Cleanup(func() { renameAdminFile = originalRename })
	renames := 0
	renameAdminFile = func(oldPath, newPath string) error {
		renames++
		if renames == 4 {
			return os.ErrPermission
		}
		return os.Rename(oldPath, newPath)
	}
	err := runGenerate([]string{
		"--config", configPath,
		"--panel-url", "https://panel.example.com",
		"--node-id", "1",
		"--token-file", tokenPath,
		"--token-source", sourcePath,
		"--force",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("generate succeeded despite injected commit failure")
	}
	assertFileContents(t, configPath, oldConfig)
	assertFileContents(t, tokenPath, oldToken)
}

func assertFileContents(t *testing.T, path string, expected []byte) {
	t.Helper()
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("%s contents = %q, want %q", path, actual, expected)
	}
}
