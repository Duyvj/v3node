package app

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadOrCreateAPISecretPersistsProtectedValue(t *testing.T) {
	directory := t.TempDir()
	first, err := LoadOrCreateAPISecret(directory)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateAPISecret(directory)
	if err != nil {
		t.Fatal(err)
	}
	if first == "" || first != second {
		t.Fatalf("API secret was not stable: %q / %q", first, second)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(directory, apiSecretFile))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("API secret permissions = %o", info.Mode().Perm())
		}
	}
}

func TestLoadOrCreateAPISecretRejectsInvalidExistingFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, apiSecretFile)
	if err := os.WriteFile(path, []byte("not-a-valid-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateAPISecret(directory); err == nil {
		t.Fatal("invalid existing API secret was replaced silently")
	}
}
