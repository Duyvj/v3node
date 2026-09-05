package panel

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Duyvj/v3node/conf"
	"github.com/go-resty/resty/v2"
)

const agentManifestPath = "/api/v2/server/agent/config"
const agentMaintenanceReportPath = "/api/v2/server/agent/maintenance/report"
const agentCertificateReportPath = "/api/v2/server/agent/certificate/report"
const agentTerminalClaimPath = "/api/v2/server/agent/terminal/claim"
const agentTerminalExchangePath = "/api/v2/server/agent/terminal/exchange"
const agentAuthorizationHeader = "X-ZBoard-Agent-Authorization"

const maxAgentNodes = 10000

type AgentMaintenance struct {
	ID          string `json:"id"`
	Action      string `json:"action"`
	RequestedAt int64  `json:"requested_at"`
}

type AgentCertificateRequest struct {
	ID          string `json:"id"`
	NodeID      int    `json:"node_id"`
	CertFile    string `json:"cert_file"`
	RequestedAt int64  `json:"requested_at"`
}

// AgentManifest is the desired logical-node assignment returned by V2Board.
// Revision should change whenever Nodes changes. If an older panel omits it,
// EffectiveRevision derives a stable value from the sorted node IDs.
type AgentManifest struct {
	PanelType               string                        `json:"panel_type"`
	Revision                string                        `json:"revision"`
	NodeRevision            string                        `json:"node_revision,omitempty"`
	FallbackRevision        string                        `json:"fallback_revision,omitempty"`
	Nodes                   []int                         `json:"nodes"`
	PollInterval            int                           `json:"poll_interval"`
	Maintenance             *AgentMaintenance             `json:"maintenance,omitempty"`
	CertificateRequest      *AgentCertificateRequest      `json:"certificate_request,omitempty"`
	GlobalDeviceLimitConfig *conf.GlobalDeviceLimitConfig `json:"global_device_limit_config,omitempty"`
	AuthorizationRevoked    bool                          `json:"-"`
}

// AgentClient is deliberately separate from Client: it authenticates a VPS
// agent, while Client authenticates requests for one assigned logical node.
type AgentClient struct {
	client         *resty.Client
	terminalClient *resty.Client
	config         conf.AgentConfig
	instanceSecret string
}

// AgentTerminalSession is the small, byte-free metadata record returned by
// the terminal relay. Values are strings because the relay stores them in
// Redis hashes.
type AgentTerminalSession struct {
	ID     string
	Status map[string]string
}

type AgentTerminalInput struct {
	Seq  uint64 `json:"seq"`
	Data string `json:"data"`
}

type AgentTerminalExchange struct {
	Input  []AgentTerminalInput
	Status map[string]string
}

// AgentTerminalHTTPError preserves the panel status so the terminal worker
// can distinguish a closed/revoked session from a transient network failure.
type AgentTerminalHTTPError struct {
	StatusCode int
}

func (e *AgentTerminalHTTPError) Error() string {
	return fmt.Sprintf("terminal request: panel returned HTTP %d", e.StatusCode)
}

// IsTerminalSessionClosed reports responses that must immediately tear down
// the root PTY. Retrying these responses would keep a disabled session alive.
func IsTerminalSessionClosed(err error) bool {
	var responseError *AgentTerminalHTTPError
	if !errors.As(err, &responseError) {
		return false
	}
	return responseError.StatusCode == http.StatusUnauthorized ||
		responseError.StatusCode == http.StatusForbidden ||
		responseError.StatusCode == http.StatusNotFound
}

// ClaimTerminal asks the panel for one pending terminal session. No request
// body is sent: this makes the endpoint safe to poll through strict proxies.
func (c *AgentClient) ClaimTerminal(ctx context.Context) (*AgentTerminalSession, error) {
	var payload struct {
		Data *struct {
			ID     string            `json:"id"`
			Status map[string]string `json:"status"`
		} `json:"data"`
	}
	if err := c.terminalPost(ctx, agentTerminalClaimPath, nil, &payload); err != nil {
		return nil, err
	}
	if payload.Data == nil {
		return nil, nil
	}
	if strings.TrimSpace(payload.Data.ID) == "" {
		return nil, fmt.Errorf("claim terminal: response missing session ID")
	}
	return &AgentTerminalSession{ID: payload.Data.ID, Status: payload.Data.Status}, nil
}

// ExchangeTerminal optionally uploads one PTY output chunk and returns all
// pending terminal input and current size metadata for the claimed session.
func (c *AgentClient) ExchangeTerminal(ctx context.Context, id string, seq uint64, data string, inputAck uint64) (*AgentTerminalExchange, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("exchange terminal: session ID is required")
	}
	body := map[string]any{"id": id}
	if inputAck != 0 {
		body["input_ack"] = inputAck
	}
	if seq != 0 || data != "" {
		if seq == 0 || data == "" {
			return nil, fmt.Errorf("exchange terminal: sequence and data must be supplied together")
		}
		body["seq"] = seq
		body["data"] = data
	}
	var payload struct {
		Data struct {
			Input  []AgentTerminalInput `json:"input"`
			Status map[string]string    `json:"status"`
		} `json:"data"`
	}
	if err := c.terminalPost(ctx, agentTerminalExchangePath, body, &payload); err != nil {
		return nil, err
	}
	return &AgentTerminalExchange{Input: payload.Data.Input, Status: payload.Data.Status}, nil
}

// CloseTerminal releases relay state when the shell exits or the local idle
// deadline is reached, preventing a claimed-but-orphaned browser session.
func (c *AgentClient) CloseTerminal(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("close terminal: session ID is required")
	}
	var payload struct {
		Data map[string]any `json:"data"`
	}
	return c.terminalPost(ctx, agentTerminalExchangePath, map[string]any{"id": id, "close": true}, &payload)
}

func (c *AgentClient) terminalPost(ctx context.Context, path string, body any, result any) error {
	if c.instanceSecret == "" {
		return fmt.Errorf("terminal request: instance secret is unavailable")
	}
	request := c.terminalClient.R().SetContext(ctx).SetResult(result).ForceContentType("application/json")
	if body != nil {
		request.SetBody(body)
	}
	response, err := request.Post(path)
	if err != nil {
		return fmt.Errorf("terminal request: %w", err)
	}
	if response == nil {
		return fmt.Errorf("terminal request: received nil response")
	}
	if response.StatusCode() < http.StatusOK || response.StatusCode() >= http.StatusMultipleChoices {
		return &AgentTerminalHTTPError{StatusCode: response.StatusCode()}
	}
	return nil
}

func NewAgentClient(c conf.AgentConfig) (*AgentClient, error) {
	if !c.Enable {
		return nil, fmt.Errorf("agent client requires Agent.Enable=true")
	}
	if strings.TrimSpace(c.APIHost) == "" || strings.TrimSpace(c.AgentID) == "" || strings.TrimSpace(c.AgentToken) == "" {
		return nil, fmt.Errorf("agent client requires ApiHost, AgentID and AgentToken")
	}
	apiHost, err := conf.NormalizePanelAPIHost(c.APIHost)
	if err != nil {
		return nil, fmt.Errorf("agent client: %w", err)
	}
	c.APIHost = apiHost

	client := newAgentHTTPClient(c, conf.DefaultNodeRetryCount)
	terminalClient := newAgentHTTPClient(c, 0)
	instanceSecret := setInstanceSecretHeader(client)
	if instanceSecret != "" {
		terminalClient.SetHeader("X-ZNode-Instance-Secret", instanceSecret)
	}

	return &AgentClient{client: client, terminalClient: terminalClient, config: c, instanceSecret: instanceSecret}, nil
}

func newAgentHTTPClient(c conf.AgentConfig, retryCount int) *resty.Client {
	timeout := conf.DefaultNodeTimeout
	client := resty.New().
		SetBaseURL(c.APIHost).
		SetTimeout(time.Duration(timeout)*time.Second).
		SetResponseBodyLimit(maxBufferedPanelResponseBytes).
		SetRetryCount(retryCount).
		SetRedirectPolicy(resty.NoRedirectPolicy()).
		SetTLSClientConfig(&tls.Config{MinVersion: tls.VersionTLS12}).
		SetHeader("User-Agent", fmt.Sprintf("znode-agent go-resty/%s (https://github.com/go-resty/resty)", resty.Version)).
		SetHeader("X-ZNode-Agent-ID", c.AgentID).
		SetHeader("X-ZNode-Instance-ID", effectiveInstanceID(c.AgentInstanceID)).
		SetHeader("X-ZNode-Agent-Token", c.AgentToken).
		SetHeader("X-ZNode-Type", conf.RequiredPanelType).
		SetHeader("X-ZNode-Version", ClientVersion()).
		SetAuthToken(c.AgentToken)
	setAddressHeaders(client)
	return client
}

func (c *AgentClient) GetManifest(ctx context.Context) (*AgentManifest, error) {
	response, err := c.client.R().
		SetContext(ctx).
		ForceContentType("application/json").
		Get(agentManifestPath)
	if err != nil {
		return nil, fmt.Errorf("get agent manifest: %w", err)
	}
	if response == nil {
		return nil, fmt.Errorf("get agent manifest: received nil response")
	}
	if response.StatusCode() == http.StatusUnauthorized || response.StatusCode() == http.StatusForbidden {
		// A CDN, WAF or maintenance proxy may generate a generic 401/403 while
		// the panel is unavailable. Only an authenticated ZBoard response carries
		// this explicit marker; generic denials are transient control-plane errors
		// and must never tear down healthy VPN inbounds.
		if !strings.EqualFold(strings.TrimSpace(response.Header().Get(agentAuthorizationHeader)), "revoked") {
			return nil, fmt.Errorf("get agent manifest: unconfirmed authorization response HTTP %d", response.StatusCode())
		}
		markZBoardControlPlaneHealthy(c.config.APIHost, c.config.AgentID)
		return &AgentManifest{
			Revision:             fmt.Sprintf("authorization-revoked:%d", response.StatusCode()),
			Nodes:                make([]int, 0),
			PollInterval:         c.config.PollInterval,
			AuthorizationRevoked: true,
		}, nil
	}
	if response.IsError() {
		return nil, fmt.Errorf("get agent manifest: panel returned HTTP %d", response.StatusCode())
	}

	body := response.Body()
	var envelope struct {
		Status  string          `json:"status"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("decode agent manifest: %w", err)
	}
	if envelope.Status != "" && !strings.EqualFold(envelope.Status, "success") {
		return nil, fmt.Errorf("get agent manifest: panel rejected credentials: %s", envelope.Message)
	}
	if len(envelope.Data) > 0 && string(envelope.Data) != "null" {
		body = envelope.Data
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, fmt.Errorf("decode agent manifest: %w", err)
	}
	if _, ok := fields["nodes"]; !ok {
		return nil, fmt.Errorf("decode agent manifest: missing nodes field")
	}
	manifest := &AgentManifest{}
	if err := json.Unmarshal(body, manifest); err != nil {
		return nil, fmt.Errorf("decode agent manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	markZBoardControlPlaneHealthy(c.config.APIHost, c.config.AgentID)
	return manifest, nil
}

func (c *AgentClient) ReportMaintenance(ctx context.Context, commandID, status, message string) error {
	response, err := c.client.R().SetContext(ctx).SetBody(map[string]string{
		"id": commandID, "status": status, "message": message, "version": ClientVersion(),
	}).ForceContentType("application/json").Post(agentMaintenanceReportPath)
	if err != nil {
		return fmt.Errorf("report agent maintenance: %w", err)
	}
	if response.IsError() {
		return fmt.Errorf("report agent maintenance: panel returned HTTP %d", response.StatusCode())
	}
	return nil
}

func (c *AgentClient) ReportCertificate(ctx context.Context, requestID string, report CertificateReport) error {
	body := map[string]any{"id": requestID, "node_id": report.NodeID, "status": report.Status, "message": report.Message}
	if report.SHA256 != "" {
		body["sha256"] = report.SHA256
	}
	if report.PublicKeySHA256 != "" {
		body["public_key_sha256"] = report.PublicKeySHA256
	}
	if report.NotAfter > 0 {
		body["not_after"] = report.NotAfter
	}
	if report.Issuer != "" {
		body["issuer"] = report.Issuer
	}
	response, err := c.client.R().SetContext(ctx).SetBody(body).ForceContentType("application/json").Post(agentCertificateReportPath)
	if err != nil {
		return fmt.Errorf("report agent certificate: %w", err)
	}
	if response.IsError() {
		return fmt.Errorf("report agent certificate: panel returned HTTP %d", response.StatusCode())
	}
	return nil
}

type CertificateReport struct {
	NodeID          int
	Status          string
	SHA256          string
	PublicKeySHA256 string
	NotAfter        int64
	Issuer          string
	Message         string
}

func (m *AgentManifest) Validate() error {
	pt := strings.TrimSpace(m.PanelType)
	if pt == "" || (!strings.EqualFold(pt, "v2node") && !strings.EqualFold(pt, "v2board") && !strings.EqualFold(pt, "zboard")) {
		return fmt.Errorf("invalid agent manifest panel_type %q: expected v2node, v2board, or zboard", m.PanelType)
	}
	if len(m.Nodes) > maxAgentNodes {
		return fmt.Errorf("invalid agent manifest: too many assigned nodes")
	}
	if len(m.Revision) > 256 {
		return fmt.Errorf("invalid agent manifest: revision is too long")
	}
	if len(m.NodeRevision) > 256 || len(m.FallbackRevision) > 256 {
		return fmt.Errorf("invalid agent manifest: component revision is too long")
	}
	if m.GlobalDeviceLimitConfig != nil {
		if len(m.GlobalDeviceLimitConfig.RedisSentinelAddrs) > 64 {
			return fmt.Errorf("invalid agent manifest: too many Redis sentinels")
		}
		if _, err := conf.RedisTLSConfig(m.GlobalDeviceLimitConfig); err != nil {
			return fmt.Errorf("invalid agent manifest Redis config: %w", err)
		}
	}
	seen := make(map[int]struct{}, len(m.Nodes))
	for _, nodeID := range m.Nodes {
		if nodeID <= 0 {
			return fmt.Errorf("invalid agent manifest: node ID must be positive, got %d", nodeID)
		}
		if _, ok := seen[nodeID]; ok {
			return fmt.Errorf("invalid agent manifest: duplicate node ID %d", nodeID)
		}
		seen[nodeID] = struct{}{}
	}
	if m.Maintenance != nil {
		if len(m.Maintenance.ID) != 32 {
			return fmt.Errorf("invalid agent maintenance command ID")
		}
		if _, err := hex.DecodeString(m.Maintenance.ID); err != nil {
			return fmt.Errorf("invalid agent maintenance command ID: %w", err)
		}
		if m.Maintenance.Action != "update_latest" && m.Maintenance.Action != "rollback" {
			return fmt.Errorf("invalid agent maintenance action %q", m.Maintenance.Action)
		}
	}
	if m.CertificateRequest != nil {
		if len(m.CertificateRequest.ID) != 32 {
			return fmt.Errorf("invalid agent certificate request ID")
		}
		if _, err := hex.DecodeString(m.CertificateRequest.ID); err != nil {
			return fmt.Errorf("invalid agent certificate request ID: %w", err)
		}
		if m.CertificateRequest.NodeID <= 0 {
			return fmt.Errorf("invalid agent certificate request node ID")
		}
		if len(m.CertificateRequest.CertFile) == 0 || len(m.CertificateRequest.CertFile) > 4096 {
			return fmt.Errorf("invalid agent certificate request path")
		}
	}
	return nil
}

func (m *AgentManifest) EffectiveRevision() string {
	if revision := strings.TrimSpace(m.Revision); revision != "" {
		return revision
	}
	ids := append([]int(nil), m.Nodes...)
	sort.Ints(ids)
	payload, _ := json.Marshal(ids)
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

// EffectiveNodeRevision lets ZNode distinguish an inbound/node change from a
// Redis-only fallback update. Older ZBoard versions omit this field and retain
// the conservative full-reload behavior through the aggregate revision.
func (m *AgentManifest) EffectiveNodeRevision() string {
	if revision := strings.TrimSpace(m.NodeRevision); revision != "" {
		return revision
	}
	return m.EffectiveRevision()
}

func (m *AgentManifest) EffectiveFallbackRevision() string {
	if revision := strings.TrimSpace(m.FallbackRevision); revision != "" {
		return revision
	}
	payload, _ := json.Marshal(m.GlobalDeviceLimitConfig)
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func (m *AgentManifest) EffectivePollInterval(fallback int) time.Duration {
	seconds := m.PollInterval
	if seconds <= 0 {
		seconds = fallback
	}
	if seconds <= 0 {
		seconds = 15
	}
	// A broken or malicious panel must not create a tight polling loop.
	if seconds < 5 {
		seconds = 5
	}
	if seconds > 3600 {
		seconds = 3600
	}
	return time.Duration(seconds) * time.Second
}

// NodeConfigs turns the authoritative manifest into the per-node clients used
// by the existing runtime. Manual Nodes are untouched when agent mode is off.
func (m *AgentManifest) NodeConfigs(agent conf.AgentConfig) []conf.NodeConfig {
	deviceConfig := agent.GlobalDeviceLimitConfig
	if m.GlobalDeviceLimitConfig != nil {
		deviceConfig = m.GlobalDeviceLimitConfig
	}
	nodes := make([]conf.NodeConfig, 0, len(m.Nodes))
	for _, nodeID := range m.Nodes {
		config := cloneGlobalDeviceLimitConfig(deviceConfig)
		if config != nil && config.UserSourceMode != "redis_primary" {
			config.UserSourceMode = "web_primary"
		}
		nodes = append(nodes, conf.NodeConfig{
			APIHost:                 agent.APIHost,
			NodeID:                  nodeID,
			Key:                     agent.AgentToken,
			AgentID:                 agent.AgentID,
			AgentInstanceID:         agent.AgentInstanceID,
			Timeout:                 conf.DefaultNodeTimeout,
			GlobalDeviceLimitConfig: config,
		})
	}
	return nodes
}

func cloneGlobalDeviceLimitConfig(source *conf.GlobalDeviceLimitConfig) *conf.GlobalDeviceLimitConfig {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.RedisSentinelAddrs = append([]string(nil), source.RedisSentinelAddrs...)
	if source.SyncEnabled != nil {
		syncEnabled := *source.SyncEnabled
		cloned.SyncEnabled = &syncEnabled
	}
	return &cloned
}
