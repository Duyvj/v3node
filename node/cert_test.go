package node

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	panel "github.com/Duyvj/v3node/api/v2board"
)

func TestGenerateSelfSignedCertificateWritesMatchingRSAFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "nested", "node.cer")
	keyPath := filepath.Join(dir, "nested", "node.key")
	if err := generateSelfSslCertificate("node.example.com", certPath, keyPath); err != nil {
		t.Fatalf("generate certificate: %v", err)
	}

	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read certificate: %v", err)
	}
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Fatalf("unexpected certificate PEM block")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	if err := certificate.VerifyHostname("node.example.com"); err != nil {
		t.Fatalf("verify certificate hostname: %v", err)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" {
		t.Fatalf("unexpected private key PEM type: %v", keyBlock)
	}
	if _, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err != nil {
		t.Fatalf("parse private key: %v", err)
	}
}

func TestCertificateGenerationRejectsPanelControlledPathsOutsideZNode(t *testing.T) {
	controller := &Controller{info: &panel.NodeInfo{Common: &panel.CommonNode{CertInfo: &panel.CertInfo{
		CertMode: "self",
		CertFile: filepath.Join(t.TempDir(), "node.cer"),
		KeyFile:  filepath.Join(t.TempDir(), "node.key"),
	}}}}
	if err := controller.requestCert(); err == nil {
		t.Fatal("root certificate generation accepted a path outside /etc/znode")
	}
	if !pathWithinCertificateRoot("/etc/znode/nodes/node.cer", []string{"/etc/znode"}) {
		t.Fatal("valid ZNode certificate path was rejected")
	}
	if pathWithinCertificateRoot("/etc/znode-escape/node.cer", []string{"/etc/znode"}) {
		t.Fatal("prefix-confusable certificate path was accepted")
	}
	if err := validateCertificateMaterialPath("/etc/znode/config.json", false, true); err == nil {
		t.Fatal("certificate generation accepted a non-certificate target")
	}
}

func TestCertificateReaderRejectsOversizedMaterial(t *testing.T) {
	root := t.TempDir()
	oldRoots := certificateReadRoots
	certificateReadRoots = []string{root}
	t.Cleanup(func() { certificateReadRoots = oldRoots })

	path := filepath.Join(root, "oversized.pem")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxCertificateMaterialBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := validateCertificateMaterialPath(path, false, false); err == nil {
		t.Fatal("oversized certificate material was accepted")
	}
}
