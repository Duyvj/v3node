package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigureAssetLocationUsesConfigDirectory(t *testing.T) {
	t.Setenv(xrayAssetLocationEnv, "")
	directory := t.TempDir()
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(strings.Repeat("g", 2048)), 0600); err != nil {
			t.Fatal(err)
		}
	}

	got := configureAssetLocation(filepath.Join(directory, "config.json"))
	if got != directory {
		t.Fatalf("asset location = %q, want %q", got, directory)
	}
	if env := os.Getenv(xrayAssetLocationEnv); env != directory {
		t.Fatalf("%s = %q, want %q", xrayAssetLocationEnv, env, directory)
	}
}

func TestConfigureAssetLocationPreservesExplicitValue(t *testing.T) {
	t.Setenv(xrayAssetLocationEnv, "/custom/xray-assets")
	if got := configureAssetLocation(filepath.Join(t.TempDir(), "config.json")); got != "/custom/xray-assets" {
		t.Fatalf("asset location = %q", got)
	}
}

func TestHasGeoDataRejectsMissingOrTruncatedFiles(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "geoip.dat"), []byte("truncated"), 0600); err != nil {
		t.Fatal(err)
	}
	if hasGeoData(directory) {
		t.Fatal("truncated geodata must not be accepted")
	}
}
