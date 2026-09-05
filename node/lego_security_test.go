package node

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/go-acme/lego/v4/certificate"
)

func TestCancelledACMEOperationStopsBeforeUsingClientOrWritingFiles(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &Lego{config: &panel.CertInfo{
		CertFile: filepath.Join(t.TempDir(), "cancelled.pem"),
		KeyFile:  filepath.Join(t.TempDir(), "cancelled.key"),
	}}
	if err := client.CreateCertContext(ctx); err == nil {
		t.Fatal("cancelled certificate creation continued")
	}
	if err := client.RenewCertContext(ctx); err == nil {
		t.Fatal("cancelled certificate renewal continued")
	}
	if _, err := os.Stat(client.config.CertFile); !os.IsNotExist(err) {
		t.Fatalf("cancelled operation wrote certificate material: %v", err)
	}
}

func TestLegoWriteCertKeepsPrivateMaterialOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not enforced on Windows")
	}
	directory := t.TempDir()
	certPath := filepath.Join(directory, "tls", "node.pem")
	keyPath := filepath.Join(directory, "tls", "node.key")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("legacy-world-readable"), 0o644); err != nil {
		t.Fatal(err)
	}

	legoClient := &Lego{config: &panel.CertInfo{CertFile: certPath, KeyFile: keyPath}}
	if err := legoClient.writeCert(&certificate.Resource{
		Certificate: []byte("certificate"),
		PrivateKey:  []byte("private-key"),
	}); err != nil {
		t.Fatal(err)
	}

	assertFileMode(t, certPath, 0o644)
	assertFileMode(t, keyPath, 0o600)
}

func TestLegoUserSaveKeepsAccountKeyOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not enforced on Windows")
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	user := &User{Email: "security@example.test", key: privateKey}
	accountPath := filepath.Join(t.TempDir(), "user", "account.json")
	if err := user.Save(accountPath); err != nil {
		t.Fatal(err)
	}
	assertFileMode(t, accountPath, 0o600)
	if user.KeyEncoded != "" {
		t.Fatal("encoded private key remained attached to the in-memory user")
	}

	loaded := &User{}
	if err := loaded.Load(accountPath); err != nil {
		t.Fatal(err)
	}
	if loaded.GetPrivateKey() == nil || loaded.KeyEncoded != "" {
		t.Fatal("saved ACME account did not load securely")
	}
}

func TestDNSProviderInitializationDoesNotModifyProcessEnvironment(t *testing.T) {
	const existing = "CF_DNS_API_TOKEN"
	const absent = "CLOUDFLARE_DNS_API_TOKEN"
	if err := os.Setenv(existing, "original"); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv(existing)
	_ = os.Unsetenv(absent)

	provider, err := newDNSChallengeProvider("cloudflare", map[string]string{
		existing: "temporary",
		absent:   "temporary",
	})
	if err != nil || provider == nil {
		t.Fatalf("create Cloudflare provider: %v", err)
	}
	if value := os.Getenv(existing); value != "original" {
		t.Fatalf("existing environment was not restored: %q", value)
	}
	if _, set := os.LookupEnv(absent); set {
		t.Fatal("temporary DNS credential remained in process environment")
	}
}

func TestDNSProviderRejectsConflictingTokenAliases(t *testing.T) {
	if _, err := newDNSChallengeProvider("cloudflare", map[string]string{
		"CF_DNS_API_TOKEN":         "first",
		"CLOUDFLARE_DNS_API_TOKEN": "second",
	}); err == nil {
		t.Fatal("conflicting Cloudflare credential aliases were accepted")
	}
}

func TestLegoConfigValidatesExpandedCertificatePaths(t *testing.T) {
	if etc, statErr := os.Lstat("/etc"); statErr == nil && etc.Mode()&os.ModeSymlink == 0 {
		valid, err := resolvedLegoConfig(&panel.CertInfo{
			CertMode:   "dns",
			CertFile:   "/etc/znode/{domain}.pem",
			KeyFile:    "/etc/znode/{domain}.key",
			CertDomain: "node.example.test",
			Email:      "node@example.test",
		})
		if err != nil || valid.CertFile != "/etc/znode/node.example.test.pem" {
			t.Fatalf("valid expanded certificate config was rejected: config=%+v err=%v", valid, err)
		}
	}

	_, err := resolvedLegoConfig(&panel.CertInfo{
		CertMode:   "dns",
		CertFile:   "/etc/znode/{domain}.pem",
		KeyFile:    "/etc/znode/node.key",
		CertDomain: "../../tmp/panel-controlled",
		Email:      "node@example.test",
	})
	if err == nil {
		t.Fatal("certificate template escaped the writable allowlist after expansion")
	}

	_, err = resolvedLegoConfig(&panel.CertInfo{
		CertMode:   "dns",
		CertFile:   "/etc/znode/node.pem",
		KeyFile:    "/etc/znode/node.key",
		CertDomain: "node.example.test",
		Email:      "../../root",
	})
	if err == nil {
		t.Fatal("path-like ACME account email was accepted")
	}
}

func TestDecodePrivateRejectsMalformedPEM(t *testing.T) {
	user := &User{}
	if _, err := user.DecodePrivate("not PEM"); err == nil {
		t.Fatal("malformed account key should be rejected")
	}
}

func TestNewLegoUserRejectsAccountSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	link := filepath.Join(directory, "user.json")
	if err := os.WriteFile(target, []byte(`{"Email":"security@example.test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if _, err := NewLegoUser(link, "security@example.test"); err == nil {
		t.Fatal("ACME account symlink must be rejected")
	}
}

func assertFileMode(t *testing.T, path string, expected os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != expected {
		t.Fatalf("unexpected mode for %s: got %04o want %04o", path, mode, expected)
	}
}
