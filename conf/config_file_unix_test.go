//go:build !windows

package conf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigFileRejectsBroadPermissionsAndSymlinks(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte(`{"type":"zboard","Nodes":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := New().LoadFromPath(target); err == nil {
		t.Fatal("world-readable AgentToken config was accepted")
	}
	if err := os.Chmod(target, 0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(directory, "config.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := New().LoadFromPath(link); err == nil {
		t.Fatal("symlinked config was accepted")
	}
}
