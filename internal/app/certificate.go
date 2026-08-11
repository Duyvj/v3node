package app

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Duyvj/v3node/internal/engine"
)

const (
	maxManagedCertificateBytes = 256 << 10
	managedCertificateRenewal  = 30 * 24 * time.Hour
	// The original v2node uses a very long-lived self-signed certificate. A
	// 30-year lifetime avoids needing a background renewal worker for a local
	// trust mode while still allowing replacement whenever panel names change.
	managedCertificateLifetime = 30 * 365 * 24 * time.Hour
)

// EnsureManagedCertificate creates or renews panel-requested self-signed TLS
// material. It is a bounded one-shot operation during reconciliation; it does
// not add a resident certificate worker to the controller.
func EnsureManagedCertificate(node engine.NodeSpec) error {
	if !node.TLS.ManagedSelfSigned {
		return nil
	}
	return ensureSelfSignedCertificate(node.TLS, time.Now().UTC())
}

func ensureSelfSignedCertificate(spec engine.TLSSpec, now time.Time) error {
	names, err := managedCertificateNames(spec)
	if err != nil {
		return err
	}
	if !isAbsoluteTargetPath(spec.CertificateFile) || !isAbsoluteTargetPath(spec.KeyFile) {
		return errors.New("managed certificate and key paths must be absolute")
	}
	if filepath.Clean(spec.CertificateFile) == filepath.Clean(spec.KeyFile) {
		return errors.New("managed certificate and key paths must differ")
	}
	valid, _, oldKey, err := loadManagedCertificate(spec.CertificateFile, spec.KeyFile, names, now)
	if err != nil {
		return err
	}
	if valid {
		if err := os.Chmod(spec.CertificateFile, 0o600); err != nil {
			return fmt.Errorf("secure managed certificate permissions: %w", err)
		}
		if err := os.Chmod(spec.KeyFile, 0o600); err != nil {
			return fmt.Errorf("secure managed private-key permissions: %w", err)
		}
		return nil
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate self-signed private key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("generate self-signed certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(managedCertificateLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("create self-signed certificate: %w", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("encode self-signed private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := installManagedCertificatePair(spec.CertificateFile, spec.KeyFile, certificatePEM, keyPEM, oldKey); err != nil {
		return err
	}
	return nil
}

func managedCertificateNames(spec engine.TLSSpec) ([]string, error) {
	candidates := append([]string{spec.ServerName}, spec.ServerNames...)
	seen := make(map[string]struct{}, len(candidates))
	names := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		name := strings.TrimSpace(candidate)
		if name == "" {
			continue
		}
		if len(name) > 253 || strings.ContainsAny(name, "\x00\r\n/\\") {
			return nil, fmt.Errorf("invalid self-signed TLS server name %q", candidate)
		}
		name = strings.TrimSuffix(name, ".")
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, errors.New("self-signed TLS requires at least one server name")
	}
	return names, nil
}

func loadManagedCertificate(certPath, keyPath string, names []string, now time.Time) (bool, []byte, []byte, error) {
	certificatePEM, certExists, err := readManagedFile(certPath)
	if err != nil {
		return false, nil, nil, err
	}
	keyPEM, keyExists, err := readManagedFile(keyPath)
	if err != nil {
		return false, nil, nil, err
	}
	if !certExists || !keyExists {
		return false, certificatePEM, keyPEM, nil
	}
	pair, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil || len(pair.Certificate) == 0 {
		return false, certificatePEM, keyPEM, nil
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false, certificatePEM, keyPEM, nil
	}
	if now.Before(leaf.NotBefore) || !now.Add(managedCertificateRenewal).Before(leaf.NotAfter) {
		return false, certificatePEM, keyPEM, nil
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		return false, certificatePEM, keyPEM, nil
	}
	for _, name := range names {
		if err := leaf.VerifyHostname(name); err != nil {
			return false, certificatePEM, keyPEM, nil
		}
	}
	return true, certificatePEM, keyPEM, nil
}

func readManagedFile(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("inspect managed certificate file %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("managed certificate path %s is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxManagedCertificateBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > maxManagedCertificateBytes {
		return nil, false, fmt.Errorf("managed certificate file %s exceeds %d bytes", path, maxManagedCertificateBytes)
	}
	return data, true, nil
}

func installManagedCertificatePair(certPath, keyPath string, certificatePEM, keyPEM, oldKey []byte) error {
	if len(certificatePEM) == 0 || len(keyPEM) == 0 || len(certificatePEM) > maxManagedCertificateBytes || len(keyPEM) > maxManagedCertificateBytes {
		return errors.New("generated managed certificate pair is invalid")
	}
	for _, directory := range []string{filepath.Dir(certPath), filepath.Dir(keyPath)} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return fmt.Errorf("create managed certificate directory: %w", err)
		}
	}
	if err := writeManagedFile(keyPath, keyPEM); err != nil {
		return fmt.Errorf("install managed private key: %w", err)
	}
	if err := writeManagedFile(certPath, certificatePEM); err != nil {
		rollbackErr := restoreManagedFile(keyPath, oldKey)
		return errors.Join(fmt.Errorf("install managed certificate: %w", err), rollbackErr)
	}
	// Normalize permissions even when an existing pair was replaced.
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(certPath, 0o600); err != nil {
		return err
	}
	return nil
}

func restoreManagedFile(path string, old []byte) error {
	if old == nil {
		return os.Remove(path)
	}
	return writeManagedFile(path, old)
}

func writeManagedFile(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".v3node-certificate-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	remove := true
	defer func() {
		_ = temporary.Close()
		if remove {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := io.Copy(temporary, bytes.NewReader(data)); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	// os.Rename does not replace an existing regular file on Windows. Windows
	// is supported for tests/local inspection only; Linux keeps the atomic
	// replacement used in production.
	if runtime.GOOS == "windows" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	remove = false
	return nil
}
