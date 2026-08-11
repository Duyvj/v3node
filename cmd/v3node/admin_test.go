package main

import (
	"bytes"
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
