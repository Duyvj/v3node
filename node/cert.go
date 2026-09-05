package node

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Duyvj/v3node/common/file"
	log "github.com/sirupsen/logrus"
)

var certificateReadRoots = []string{"/etc/znode", "/etc/letsencrypt", "/etc/ssl"}

const maxCertificateMaterialBytes int64 = 4 << 20

func pathWithinCertificateRoot(candidate string, roots []string) bool {
	clean := filepath.Clean(candidate)
	for _, root := range roots {
		relative, err := filepath.Rel(filepath.Clean(root), clean)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func validateCertificatePath(candidate string, writable bool) error {
	if candidate == "" || len(candidate) > 4096 || !filepath.IsAbs(candidate) {
		return fmt.Errorf("certificate path must be an absolute path")
	}
	clean := filepath.Clean(candidate)
	roots := certificateReadRoots
	if writable {
		roots = []string{"/etc/znode"}
	}
	if !pathWithinCertificateRoot(clean, roots) {
		return fmt.Errorf("certificate path %q is outside the allowed directories", candidate)
	}

	if !writable {
		resolved, err := filepath.EvalSymlinks(clean)
		if err != nil {
			return fmt.Errorf("resolve certificate path %q: %w", candidate, err)
		}
		if !pathWithinCertificateRoot(resolved, roots) {
			return fmt.Errorf("certificate path %q resolves outside the allowed directories", candidate)
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("certificate path %q is not a regular file", candidate)
		}
		if info.Size() < 1 || info.Size() > maxCertificateMaterialBytes {
			return fmt.Errorf("certificate path %q must be between 1 byte and %d bytes", candidate, maxCertificateMaterialBytes)
		}
		return nil
	}

	// Auto/self-signed certificate generation runs as root. Reject symlinks in
	// every existing component so a panel path cannot redirect an atomic rename
	// outside /etc/znode or overwrite another root-owned file.
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect certificate path %q: %w", candidate, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("certificate path %q contains a symbolic link", candidate)
		}
		if current != clean && !info.IsDir() {
			return fmt.Errorf("certificate path %q contains a non-directory component", candidate)
		}
		if current == clean {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("certificate path %q is not a regular file", candidate)
			}
			if info.Size() < 1 || info.Size() > maxCertificateMaterialBytes {
				return fmt.Errorf("certificate path %q must be between 1 byte and %d bytes", candidate, maxCertificateMaterialBytes)
			}
		}
	}
	return nil
}

func validateCertificateMaterialPath(candidate string, privateKey, writable bool) error {
	extension := strings.ToLower(filepath.Ext(candidate))
	allowed := extension == ".pem"
	if privateKey {
		allowed = allowed || extension == ".key"
	} else {
		allowed = allowed || extension == ".cer" || extension == ".crt"
	}
	if !allowed {
		kind := "certificate"
		if privateKey {
			kind = "private-key"
		}
		return fmt.Errorf("%s path has an unsupported extension", kind)
	}
	return validateCertificatePath(candidate, writable)
}

func (c *Controller) renewCertTask(ctx context.Context) error {
	l, err := NewLego(c.info.Common.CertInfo)
	if err != nil {
		log.WithField("tag", c.tag).Info("new lego error: ", err)
		return nil
	}
	// Lego does not expose a context-aware renewal API. Isolate it from the
	// controller lifecycle and stop waiting as soon as the task is cancelled.
	// The detached operation only owns its local Lego client and certificate
	// files; it never touches the controller/core after cancellation.
	done := make(chan error, 1)
	go func() { done <- l.RenewCertContext(ctx) }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err = <-done:
	}
	if err != nil {
		log.WithField("tag", c.tag).Info("renew cert error: ", err)
		return nil
	}
	// Certificate hashes are subscription credentials. Publish the new leaf
	// and SPKI pins immediately after renewal so clients never receive a stale
	// SHA256 until the next traffic-report interval.
	return c.reportNodeStatus(ctx)
}

func (c *Controller) requestCert() error {
	return c.requestCertContext(context.Background())
}

func (c *Controller) requestCertContext(ctx context.Context) error {
	cert := c.info.Common.CertInfo
	if cert == nil {
		return fmt.Errorf("certificate settings are missing")
	}
	writable := cert.CertMode == "dns" || cert.CertMode == "http" || cert.CertMode == "auto" || cert.CertMode == "self"
	if writable {
		resolved, err := resolvedCertificateConfig(cert)
		if err != nil {
			return err
		}
		cert = resolved
		c.info.Common.CertInfo = resolved
	}
	if cert.CertMode != "none" && cert.CertMode != "" {
		if err := validateCertificateMaterialPath(cert.CertFile, false, writable); err != nil {
			return err
		}
		if err := validateCertificateMaterialPath(cert.KeyFile, true, writable); err != nil {
			return err
		}
		if filepath.Clean(cert.CertFile) == filepath.Clean(cert.KeyFile) {
			return fmt.Errorf("certificate and private-key paths must be different")
		}
	}
	switch cert.CertMode {
	case "none", "":
	case "file":
		if cert.CertFile == "" || cert.KeyFile == "" {
			return fmt.Errorf("cert file path or key file path not exist")
		}
	case "dns", "http", "auto":
		if cert.CertFile == "" || cert.KeyFile == "" {
			return fmt.Errorf("cert file path or key file path not exist")
		}
		if file.IsExist(cert.CertFile) && file.IsExist(cert.KeyFile) {
			return nil
		}
		if cert.CertMode == "auto" && (cert.Provider == "" || len(cert.DNSEnv) == 0) {
			// Older panel rows enabled Auto TLS without persisting the DNS
			// provider/token. Do not crash-loop the whole Agent; create a local
			// certificate so the node can start and report a fingerprint.
			return generateSelfSslCertificate(cert.CertDomain, cert.CertFile, cert.KeyFile)
		}
		l, err := NewLego(cert)
		if err != nil {
			if cert.FallbackSelfSigned {
				return generateSelfSslCertificate(cert.CertDomain, cert.CertFile, cert.KeyFile)
			}
			return fmt.Errorf("create lego object error: %s", err)
		}
		err = l.CreateCertContext(ctx)
		if err != nil {
			if cert.FallbackSelfSigned {
				return generateSelfSslCertificate(cert.CertDomain, cert.CertFile, cert.KeyFile)
			}
			return fmt.Errorf("create lego cert error: %s", err)
		}
	case "self":
		if cert.CertFile == "" || cert.KeyFile == "" {
			return fmt.Errorf("cert file path or key file path not exist")
		}
		if file.IsExist(cert.CertFile) && file.IsExist(cert.KeyFile) {
			return nil
		}
		err := generateSelfSslCertificate(
			cert.CertDomain,
			cert.CertFile,
			cert.KeyFile)
		if err != nil {
			return fmt.Errorf("generate self cert error: %s", err)
		}
	default:
		return fmt.Errorf("unsupported certmode: %s", cert.CertMode)
	}
	return nil
}

func generateSelfSslCertificate(domain, certPath, keyPath string) error {
	lock := certificateOperationLock(certPath, keyPath)
	lock.Lock()
	defer lock.Unlock()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName: domain,
		},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
	}
	if ip := net.ParseIP(domain); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else if domain != "" {
		tmpl.DNSNames = []string{domain}
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := writeCertificateFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	if err := writeCertificateFile(keyPath, keyPEM, 0o600); err != nil {
		_ = os.Remove(certPath)
		return fmt.Errorf("write private key: %w", err)
	}
	return nil
}

func writeCertificateFile(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".znode-cert-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
