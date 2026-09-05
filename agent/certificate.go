package agent

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	panel "github.com/Duyvj/v3node/api/v2board"
	commonfile "github.com/Duyvj/v3node/common/file"
)

const maxCertificateFileSize = 4 << 20

var certificateRoots = []string{"/etc/znode", "/etc/letsencrypt", "/etc/ssl"}

type certificateReporter interface {
	ReportCertificate(context.Context, string, panel.CertificateReport) error
}

func reconcileCertificate(ctx context.Context, reporter certificateReporter, request *panel.AgentCertificateRequest) error {
	if reporter == nil || request == nil {
		return nil
	}
	report := panel.CertificateReport{NodeID: request.NodeID, Status: "completed"}
	certFile, data, err := readRequestedCertificate(request)
	if err != nil {
		report.Status = "failed"
		report.Message = err.Error()
		return reporter.ReportCertificate(ctx, request.ID, report)
	}
	var certs []*x509.Certificate
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr == nil {
			certs = append(certs, cert)
		}
	}
	if len(certs) == 0 {
		report.Status = "failed"
		report.Message = fmt.Sprintf("no PEM certificate found in %s", certFile)
		return reporter.ReportCertificate(ctx, request.ID, report)
	}
	cert := certs[0]
	for _, candidate := range certs {
		if !candidate.IsCA {
			cert = candidate
			break
		}
	}
	certHash := sha256.Sum256(cert.Raw)
	keyHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	report.SHA256 = hex.EncodeToString(certHash[:])
	report.PublicKeySHA256 = base64.StdEncoding.EncodeToString(keyHash[:])
	report.NotAfter = cert.NotAfter.Unix()
	report.Issuer = cert.Issuer.String()
	return reporter.ReportCertificate(ctx, request.ID, report)
}

func readRequestedCertificate(request *panel.AgentCertificateRequest) (string, []byte, error) {
	candidates := []string{request.CertFile}
	ext := filepath.Ext(request.CertFile)
	base := request.CertFile[:len(request.CertFile)-len(ext)]
	for _, candidateExt := range []string{".cer", ".crt", ".pem"} {
		candidates = append(candidates, base+candidateExt)
	}
	for _, candidateExt := range []string{"cer", "crt", "pem"} {
		matches, _ := filepath.Glob(fmt.Sprintf("/etc/znode/*%d.%s", request.NodeID, candidateExt))
		candidates = append(candidates, matches...)
	}

	seen := make(map[string]struct{}, len(candidates))
	var lastErr error
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		resolved, err := allowedCertificatePath(candidate)
		if err != nil {
			lastErr = err
			continue
		}
		data, err := commonfile.ReadRegularFileLimited(resolved, maxCertificateFileSize)
		if err == nil {
			return resolved, data, nil
		}
		lastErr = err
	}
	return "", nil, fmt.Errorf("certificate file for node %d was not found (requested %q): %v", request.NodeID, request.CertFile, lastErr)
}

func allowedCertificatePath(candidate string) (string, error) {
	candidate = filepath.Clean(strings.TrimSpace(candidate))
	if candidate == "." || !filepath.IsAbs(candidate) {
		return "", fmt.Errorf("certificate path must be absolute")
	}
	extension := strings.ToLower(filepath.Ext(candidate))
	if extension != ".cer" && extension != ".crt" && extension != ".pem" {
		return "", fmt.Errorf("certificate path has an unsupported extension")
	}

	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}
	resolvedExtension := strings.ToLower(filepath.Ext(resolved))
	if resolvedExtension != ".cer" && resolvedExtension != ".crt" && resolvedExtension != ".pem" {
		return "", fmt.Errorf("resolved certificate path has an unsupported extension")
	}
	allowed := false
	for _, root := range certificateRoots {
		rootResolved, rootErr := filepath.EvalSymlinks(root)
		if rootErr != nil {
			continue
		}
		relative, relErr := filepath.Rel(rootResolved, resolved)
		if relErr == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", fmt.Errorf("certificate path is outside the allowed certificate directories")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxCertificateFileSize {
		return "", fmt.Errorf("certificate file must be a regular file between 1 byte and %d bytes", maxCertificateFileSize)
	}
	return resolved, nil
}
