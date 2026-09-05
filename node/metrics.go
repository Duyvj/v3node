package node

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"runtime"
	"sync"
	"time"

	panel "github.com/Duyvj/v3node/api/v2board"
	commonfile "github.com/Duyvj/v3node/common/file"
)

type platformSnapshot struct {
	cpuTotal             uint64
	cpuIdle              uint64
	memoryUsed           uint64
	memoryTotal          uint64
	processMemory        uint64
	diskUsed             uint64
	diskTotal            uint64
	networkRX            uint64
	networkTX            uint64
	networkLinkSpeedMbps uint64
	uptimeSeconds        uint64
	load1                float64
}

type nodeMetricsCollector struct {
	mu            sync.Mutex
	previous      platformSnapshot
	lastAt        time.Time
	hostname      string
	certPath      string
	certFileInfo  os.FileInfo
	certModTime   int64
	certSize      int64
	certCheckedAt time.Time
	certHash      string
	certKeyHash   string
	certNotAfter  int64
	certIssuer    string
	readSnapshot  func() platformSnapshot
	now           func() time.Time
}

const certificateMetricsCacheTTL = 10 * time.Minute

func newNodeMetricsCollector() *nodeMetricsCollector {
	return newNodeMetricsCollectorWithSources(readPlatformSnapshot, time.Now)
}

func newNodeMetricsCollectorWithSources(readSnapshot func() platformSnapshot, now func() time.Time) *nodeMetricsCollector {
	if readSnapshot == nil {
		readSnapshot = readPlatformSnapshot
	}
	if now == nil {
		now = time.Now
	}
	hostname, _ := os.Hostname()
	return &nodeMetricsCollector{
		previous:     readSnapshot(),
		lastAt:       now(),
		hostname:     hostname,
		readSnapshot: readSnapshot,
		now:          now,
	}
}

func (c *nodeMetricsCollector) Collect(info *panel.NodeInfo) panel.NodeStatus {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	current := c.readSnapshot()
	elapsed := now.Sub(c.lastAt).Seconds()
	status := panel.NodeStatus{
		Timestamp:            now.Unix(),
		OS:                   runtime.GOOS,
		Arch:                 runtime.GOARCH,
		CPUCores:             runtime.NumCPU(),
		Load1:                roundMetric(current.load1),
		MemoryUsedBytes:      current.memoryUsed,
		MemoryTotalBytes:     current.memoryTotal,
		ProcessMemoryBytes:   current.processMemory,
		DiskUsedBytes:        current.diskUsed,
		DiskTotalBytes:       current.diskTotal,
		NetworkRXBytes:       current.networkRX,
		NetworkTXBytes:       current.networkTX,
		NetworkLinkSpeedMbps: current.networkLinkSpeedMbps,
		UptimeSeconds:        current.uptimeSeconds,
		Goroutines:           runtime.NumGoroutine(),
		TLSEnabled:           info != nil && info.Security == panel.Tls,
	}
	status.Hostname = c.hostname
	if current.memoryTotal > 0 {
		status.MemoryPercent = roundMetric(float64(current.memoryUsed) * 100 / float64(current.memoryTotal))
	}
	if current.diskTotal > 0 {
		status.DiskPercent = roundMetric(float64(current.diskUsed) * 100 / float64(current.diskTotal))
	}
	if totalDelta := current.cpuTotal - minUint64(current.cpuTotal, c.previous.cpuTotal); totalDelta > 0 {
		idleDelta := current.cpuIdle - minUint64(current.cpuIdle, c.previous.cpuIdle)
		status.CPUPercent = roundMetric(100 * (1 - float64(idleDelta)/float64(totalDelta)))
	}
	if elapsed > 0 {
		rxDelta := current.networkRX - minUint64(current.networkRX, c.previous.networkRX)
		txDelta := current.networkTX - minUint64(current.networkTX, c.previous.networkTX)
		status.NetworkRXMbps = roundMetric(float64(rxDelta) * 8 / 1_000_000 / elapsed)
		status.NetworkTXMbps = roundMetric(float64(txDelta) * 8 / 1_000_000 / elapsed)
	}
	if info != nil && info.Security == panel.Tls && info.Common != nil && info.Common.CertInfo != nil {
		status.TLSCertificateSHA256, status.TLSPublicKeySHA256, status.TLSNotAfter, status.TLSIssuer =
			c.cachedCertificateMetrics(info.Common.CertInfo.CertFile)
	}

	c.previous = current
	c.lastAt = now
	return status
}

func (c *nodeMetricsCollector) cachedCertificateMetrics(path string) (certificateHash, publicKeyHash string, notAfter int64, issuer string) {
	if path == "" {
		return "", "", 0, ""
	}
	now := c.now()
	info, err := os.Stat(path)
	if err == nil && c.certPath == path && c.certFileInfo != nil && os.SameFile(c.certFileInfo, info) &&
		c.certModTime == info.ModTime().UnixNano() && c.certSize == info.Size() &&
		now.Before(c.certCheckedAt.Add(certificateMetricsCacheTTL)) {
		return c.certHash, c.certKeyHash, c.certNotAfter, c.certIssuer
	}
	certificateHash, publicKeyHash, notAfterUnix, issuer := certificateMetrics(path)
	c.certPath = path
	if err == nil {
		c.certFileInfo = info
		c.certModTime = info.ModTime().UnixNano()
		c.certSize = info.Size()
	} else {
		c.certFileInfo = nil
		c.certModTime = 0
		c.certSize = 0
	}
	c.certCheckedAt = now
	c.certHash = certificateHash
	c.certKeyHash = publicKeyHash
	c.certNotAfter = notAfterUnix
	c.certIssuer = issuer
	return certificateHash, publicKeyHash, notAfterUnix, issuer
}

func certificateMetrics(path string) (certificateHash, publicKeyHash string, notAfter int64, issuer string) {
	if path == "" {
		return "", "", 0, ""
	}
	data, err := commonfile.ReadRegularFileLimited(path, maxCertificateMaterialBytes)
	if err != nil {
		return "", "", 0, ""
	}
	var certificates []*x509.Certificate
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			certificates = append(certificates, certificate)
		}
	}
	if len(certificates) == 0 {
		return "", "", 0, ""
	}
	// ACME fullchain files normally start with the leaf certificate, but some
	// providers write the chain in the opposite order. Apps pin the server leaf,
	// never the intermediate CA, so select the first non-CA certificate.
	certificate := certificates[0]
	for _, candidate := range certificates {
		if !candidate.IsCA {
			certificate = candidate
			break
		}
	}
	certDigest := sha256.Sum256(certificate.Raw)
	spkiDigest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(certDigest[:]), base64.StdEncoding.EncodeToString(spkiDigest[:]),
		certificate.NotAfter.Unix(), certificate.Issuer.String()
}

func minUint64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func roundMetric(value float64) float64 {
	if value < 0 {
		return 0
	}
	return float64(int64(value*100+0.5)) / 100
}
