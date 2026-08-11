package app

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Duyvj/v3node/internal/engine"
)

func TestEnsureManagedCertificateCreatesAndReusesPair(t *testing.T) {
	directory := t.TempDir()
	spec := engine.TLSSpec{
		Mode:              "tls",
		ManagedSelfSigned: true,
		ServerName:        "edge.example",
		ServerNames:       []string{"edge.example", "backup.example"},
		CertificateFile:   filepath.Join(directory, "node.cer"),
		KeyFile:           filepath.Join(directory, "node.key"),
	}
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	if err := ensureSelfSignedCertificate(spec, now); err != nil {
		t.Fatal(err)
	}
	firstCertificate, err := os.ReadFile(spec.CertificateFile)
	if err != nil {
		t.Fatal(err)
	}
	firstKey, err := os.ReadFile(spec.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(firstCertificate, firstKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"edge.example", "backup.example"} {
		if err := leaf.VerifyHostname(name); err != nil {
			t.Fatalf("certificate does not cover %s: %v", name, err)
		}
	}
	if runtime.GOOS != "windows" {
		for _, path := range []string{spec.CertificateFile, spec.KeyFile} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm()&0o077 != 0 {
				t.Fatalf("managed file %s mode = %o", path, info.Mode().Perm())
			}
		}
	}
	if err := ensureSelfSignedCertificate(spec, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	secondCertificate, _ := os.ReadFile(spec.CertificateFile)
	secondKey, _ := os.ReadFile(spec.KeyFile)
	if string(firstCertificate) != string(secondCertificate) || string(firstKey) != string(secondKey) {
		t.Fatal("valid managed certificate was regenerated")
	}
}

func TestEnsureManagedCertificateRotatesWhenNameChanges(t *testing.T) {
	directory := t.TempDir()
	spec := engine.TLSSpec{
		Mode:              "tls",
		ManagedSelfSigned: true,
		ServerName:        "old.example",
		CertificateFile:   filepath.Join(directory, "node.cer"),
		KeyFile:           filepath.Join(directory, "node.key"),
	}
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	if err := ensureSelfSignedCertificate(spec, now); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(spec.CertificateFile)
	spec.ServerName = "new.example"
	if err := ensureSelfSignedCertificate(spec, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(spec.CertificateFile)
	if string(before) == string(after) {
		t.Fatal("certificate was not rotated after the server name changed")
	}
}

func TestEnsureManagedCertificateRejectsSymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require Windows developer mode")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	certificate := filepath.Join(directory, "node.cer")
	if err := os.Symlink(target, certificate); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	spec := engine.TLSSpec{
		ManagedSelfSigned: true,
		ServerName:        "edge.example",
		CertificateFile:   certificate,
		KeyFile:           filepath.Join(directory, "node.key"),
	}
	if err := ensureSelfSignedCertificate(spec, time.Now()); err == nil {
		t.Fatal("symlinked managed certificate target was accepted")
	}
}
