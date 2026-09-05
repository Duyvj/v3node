package panel

import (
	"context"
	"fmt"
)

// NodeStatus is a compact runtime snapshot sent to the panel. Byte counters
// remain integers; rates are Mbps so the panel can render them without losing
// precision through PHP integer conversions.
type NodeStatus struct {
	Timestamp            int64   `json:"timestamp"`
	Hostname             string  `json:"hostname"`
	OS                   string  `json:"os"`
	Arch                 string  `json:"arch"`
	CPUCores             int     `json:"cpu_cores"`
	CPUPercent           float64 `json:"cpu_percent"`
	Load1                float64 `json:"load_1"`
	MemoryUsedBytes      uint64  `json:"memory_used_bytes"`
	MemoryTotalBytes     uint64  `json:"memory_total_bytes"`
	MemoryPercent        float64 `json:"memory_percent"`
	ProcessMemoryBytes   uint64  `json:"process_memory_bytes"`
	DiskUsedBytes        uint64  `json:"disk_used_bytes"`
	DiskTotalBytes       uint64  `json:"disk_total_bytes"`
	DiskPercent          float64 `json:"disk_percent"`
	NetworkRXBytes       uint64  `json:"network_rx_bytes"`
	NetworkTXBytes       uint64  `json:"network_tx_bytes"`
	NetworkRXMbps        float64 `json:"network_rx_mbps"`
	NetworkTXMbps        float64 `json:"network_tx_mbps"`
	NetworkLinkSpeedMbps uint64  `json:"network_link_speed_mbps"`
	UptimeSeconds        uint64  `json:"uptime_seconds"`
	Goroutines           int     `json:"goroutines"`
	TLSEnabled           bool    `json:"tls_enabled"`
	TLSCertificateSHA256 string  `json:"tls_certificate_sha256,omitempty"`
	TLSPublicKeySHA256   string  `json:"tls_public_key_sha256,omitempty"`
	TLSNotAfter          int64   `json:"tls_not_after,omitempty"`
	TLSIssuer            string  `json:"tls_issuer,omitempty"`
}

func (c *Client) ReportNodeStatus(ctx context.Context, status NodeStatus) error {
	const path = "/api/v1/server/UniProxy/status"
	response, err := c.client.R().
		SetContext(ctx).
		SetBody(status).
		ForceContentType("application/json").
		Post(path)
	if err != nil {
		return err
	}
	if response.IsError() {
		return fmt.Errorf("report node status: panel returned HTTP %d", response.StatusCode())
	}
	return nil
}
