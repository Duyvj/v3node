package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNodeMetricsCollectorCalculatesHostPercentagesAndNetworkRates(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	snapshot := platformSnapshot{
		cpuTotal:      1_000,
		cpuIdle:       400,
		memoryUsed:    20,
		memoryTotal:   100,
		diskUsed:      10,
		diskTotal:     100,
		networkRX:     1_000,
		networkTX:     2_000,
		uptimeSeconds: 10,
	}
	collector := newNodeMetricsCollectorWithSources(
		func() platformSnapshot { return snapshot },
		func() time.Time { return clock },
	)

	clock = clock.Add(2 * time.Second)
	snapshot.cpuTotal = 1_200
	snapshot.cpuIdle = 500
	snapshot.memoryUsed = 40
	snapshot.diskUsed = 25
	snapshot.networkRX += 2_000_000
	snapshot.networkTX += 1_000_000
	status := collector.Collect(nil)

	if status.CPUPercent != 50 {
		t.Fatalf("expected 50%% CPU, got %.2f", status.CPUPercent)
	}
	if status.MemoryPercent != 40 || status.DiskPercent != 25 {
		t.Fatalf("unexpected memory/disk percentages: %.2f/%.2f", status.MemoryPercent, status.DiskPercent)
	}
	if status.NetworkRXMbps != 8 || status.NetworkTXMbps != 4 {
		t.Fatalf("expected aggregate download/upload rates 8/4 Mbps, got %.2f/%.2f", status.NetworkRXMbps, status.NetworkTXMbps)
	}
}

func TestNodeMetricsCollectorHandlesCounterResetWithoutSpikes(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	snapshot := platformSnapshot{cpuTotal: 1_000, cpuIdle: 500, networkRX: 9_000, networkTX: 8_000}
	collector := newNodeMetricsCollectorWithSources(
		func() platformSnapshot { return snapshot },
		func() time.Time { return clock },
	)

	clock = clock.Add(time.Second)
	snapshot = platformSnapshot{cpuTotal: 10, cpuIdle: 5, networkRX: 20, networkTX: 30}
	status := collector.Collect(nil)
	if status.CPUPercent != 0 || status.NetworkRXMbps != 0 || status.NetworkTXMbps != 0 {
		t.Fatalf("counter reset must not create a telemetry spike: %+v", status)
	}
}

func TestCertificateMetricsUsesCertificateDERAndSPKI(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "node.example.com"},
		Issuer:       pkix.Name{CommonName: "test issuer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"node.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "certificate.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	certificateHash, publicKeyHash, expiresAt, issuer := certificateMetrics(path)
	certDigest := sha256.Sum256(der)
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	spkiDigest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)

	if certificateHash != hex.EncodeToString(certDigest[:]) {
		t.Fatalf("unexpected certificate hash: %s", certificateHash)
	}
	if publicKeyHash != base64.StdEncoding.EncodeToString(spkiDigest[:]) {
		t.Fatalf("unexpected public key hash: %s", publicKeyHash)
	}
	if expiresAt != notAfter.Unix() {
		t.Fatalf("unexpected expiration: %d", expiresAt)
	}
	if issuer == "" {
		t.Fatal("expected issuer")
	}
}

func TestCertificateMetricsSelectsLeafFromReversedFullchain(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	rootCertificate, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "node.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"node.example.com"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCertificate, leafPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}

	fullchain := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})...,
	)
	path := filepath.Join(t.TempDir(), "reversed-fullchain.pem")
	if err := os.WriteFile(path, fullchain, 0o600); err != nil {
		t.Fatal(err)
	}

	certificateHash, publicKeyHash, _, _ := certificateMetrics(path)
	leafCertificate, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	leafDigest := sha256.Sum256(leafDER)
	leafSPKI := sha256.Sum256(leafCertificate.RawSubjectPublicKeyInfo)
	if certificateHash != hex.EncodeToString(leafDigest[:]) {
		t.Fatalf("expected leaf certificate hash, got %s", certificateHash)
	}
	if publicKeyHash != base64.StdEncoding.EncodeToString(leafSPKI[:]) {
		t.Fatalf("expected leaf public key hash, got %s", publicKeyHash)
	}
}

func TestCachedCertificateMetricsRefreshesSameSizeAndModTime(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	makeCertificate := func(serial int64) []byte {
		t.Helper()
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "node.example.com"},
			NotBefore:    time.Unix(1_700_000_000, 0),
			NotAfter:     time.Unix(1_800_000_000, 0),
			DNSNames:     []string{"node.example.com"},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}

	first := makeCertificate(20)
	second := makeCertificate(21)
	if len(first) != len(second) {
		t.Fatalf("test certificates must have equal size: %d != %d", len(first), len(second))
	}
	path := filepath.Join(t.TempDir(), "certificate.pem")
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	modTime := time.Unix(1_710_000_000, 0)
	if err := os.Chtimes(path, modTime, modTime); err != nil {
		t.Fatal(err)
	}

	clock := time.Unix(1_720_000_000, 0)
	collector := &nodeMetricsCollector{now: func() time.Time { return clock }}
	firstHash, _, _, _ := collector.cachedCertificateMetrics(path)
	if err := os.WriteFile(path, second, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, modTime, modTime); err != nil {
		t.Fatal(err)
	}

	clock = clock.Add(certificateMetricsCacheTTL + time.Second)
	secondHash, _, _, _ := collector.cachedCertificateMetrics(path)
	if secondHash == firstHash {
		t.Fatal("certificate cache remained stale after its mandatory refresh interval")
	}
	secondDER, _ := pem.Decode(second)
	want := sha256.Sum256(secondDER.Bytes)
	if secondHash != hex.EncodeToString(want[:]) {
		t.Fatalf("expected refreshed certificate hash %x, got %s", want, secondHash)
	}
}
