// Package panel implements the bounded HTTP contract used by
// V2Board-compatible v2node panels.
package panel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Duyvj/v3node/internal/model"
)

const (
	ConfigEndpoint    = "/api/v2/server/config"
	UsersEndpoint     = "/api/v1/server/UniProxy/user"
	AliveListEndpoint = "/api/v1/server/UniProxy/alivelist"
	TrafficEndpoint   = "/api/v1/server/UniProxy/push"
	OnlineEndpoint    = "/api/v1/server/UniProxy/alive"

	defaultTimeout          = 15 * time.Second
	defaultMaxResponseBytes = int64(4 << 20)
	defaultMaxUsers         = 100_000
	defaultMaxIPsPerUser    = 1024
	hardMaxResponseBytes    = int64(64 << 20)
	hardMaxUsers            = 1_000_000
	maxETagBytes            = 4096
	maxRedirects            = 5
)

// Config configures a Client. Plain HTTP is deliberately opt-in and intended
// only for local development and tests.
type Config struct {
	BaseURL                string
	Token                  string
	NodeID                 int
	NodeType               string
	Timeout                time.Duration
	MaxResponseBytes       int64
	MaxConfigResponseBytes int64
	MaxUserResponseBytes   int64
	MaxUsers               int
	MaxOnlineIPsPerUser    int
	AllowHTTP              bool
	UserAgent              string
	TLSCAFile              string
}

// Client is safe for concurrent use. Node and user refreshes are serialized
// independently so their ETags cannot be committed out of order.
type Client struct {
	baseURL  *url.URL
	token    string
	nodeID   int
	nodeType string
	http     *http.Client

	maxResponseBytes       int64
	maxConfigResponseBytes int64
	maxUserResponseBytes   int64
	maxUsers               int
	maxOnlineIPsPerUser    int
	userAgent              string

	nodeMu       sync.Mutex
	nodeETag     string
	nodeHash     [sha256.Size]byte
	haveNodeHash bool
	userMu       sync.Mutex
	userETag     string
	userHash     [sha256.Size]byte
	haveUserHash bool
}

// HTTPStatusError reports an unexpected panel response without including the
// request URL, token or response body.
type HTTPStatusError struct {
	Operation  string
	StatusCode int
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("panel %s returned HTTP status %d", e.Operation, e.StatusCode)
}

// New validates configuration and creates a bounded HTTPS client.
func New(config Config) (*Client, error) {
	baseURL, err := url.Parse(strings.TrimSpace(config.BaseURL))
	if err != nil {
		return nil, errors.New("panel base URL is invalid")
	}
	if !baseURL.IsAbs() || baseURL.Host == "" {
		return nil, errors.New("panel base URL must be absolute")
	}
	if baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, errors.New("panel base URL must not contain credentials, query, or fragment")
	}
	baseURL.Scheme = strings.ToLower(baseURL.Scheme)
	switch baseURL.Scheme {
	case "https":
	case "http":
		if !config.AllowHTTP {
			return nil, errors.New("plain HTTP panel URL is disabled")
		}
	default:
		return nil, errors.New("panel base URL scheme must be https")
	}

	if config.NodeID <= 0 {
		return nil, errors.New("panel node ID must be positive")
	}
	if config.Token == "" {
		return nil, errors.New("panel token must not be empty")
	}
	if len(config.Token) > 8192 {
		return nil, errors.New("panel token is too long")
	}
	if config.NodeType == "" {
		config.NodeType = "v2node"
	}
	if !validNodeType(config.NodeType) {
		return nil, errors.New("panel node type is invalid")
	}
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	if config.Timeout < 0 || config.Timeout > 5*time.Minute {
		return nil, errors.New("panel timeout must be between zero and five minutes")
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultMaxResponseBytes
	}
	if config.MaxResponseBytes < 1 || config.MaxResponseBytes > hardMaxResponseBytes {
		return nil, fmt.Errorf("panel response limit must be between 1 and %d bytes", hardMaxResponseBytes)
	}
	if config.MaxConfigResponseBytes == 0 {
		config.MaxConfigResponseBytes = config.MaxResponseBytes
	}
	if config.MaxUserResponseBytes == 0 {
		config.MaxUserResponseBytes = config.MaxResponseBytes
	}
	if config.MaxConfigResponseBytes < 1 || config.MaxConfigResponseBytes > hardMaxResponseBytes {
		return nil, fmt.Errorf("panel config response limit must be between 1 and %d bytes", hardMaxResponseBytes)
	}
	if config.MaxUserResponseBytes < 1 || config.MaxUserResponseBytes > hardMaxResponseBytes {
		return nil, fmt.Errorf("panel user response limit must be between 1 and %d bytes", hardMaxResponseBytes)
	}
	if config.MaxUsers == 0 {
		config.MaxUsers = defaultMaxUsers
	}
	if config.MaxUsers < 1 || config.MaxUsers > hardMaxUsers {
		return nil, fmt.Errorf("panel user limit must be between 1 and %d", hardMaxUsers)
	}
	if config.MaxOnlineIPsPerUser == 0 {
		config.MaxOnlineIPsPerUser = defaultMaxIPsPerUser
	}
	if config.MaxOnlineIPsPerUser < 1 || config.MaxOnlineIPsPerUser > 65536 {
		return nil, errors.New("online IP limit per user must be between 1 and 65536")
	}
	if config.UserAgent == "" {
		config.UserAgent = "v3node/clean-room"
	}
	if len(config.UserAgent) > 512 || strings.ContainsAny(config.UserAgent, "\r\n") {
		return nil, errors.New("panel user agent is invalid")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
	}
	if config.TLSCAFile != "" {
		file, err := os.Open(config.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("read panel TLS CA file: %w", err)
		}
		pemData, readErr := io.ReadAll(io.LimitReader(file, (4<<20)+1))
		closeErr := file.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read panel TLS CA file: %w", readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close panel TLS CA file: %w", closeErr)
		}
		if len(pemData) == 0 || len(pemData) > 4<<20 {
			return nil, errors.New("panel TLS CA file size is invalid")
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pemData) {
			return nil, errors.New("panel TLS CA file contains no valid certificate")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	transport.MaxResponseHeaderBytes = 1 << 20
	transport.ResponseHeaderTimeout = config.Timeout
	transport.TLSHandshakeTimeout = minDuration(config.Timeout, 10*time.Second)
	transport.IdleConnTimeout = 90 * time.Second
	transport.MaxIdleConns = 32
	transport.MaxIdleConnsPerHost = 8
	transport.MaxConnsPerHost = 16

	origin := originKey(baseURL)
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}
			if originKey(request.URL) != origin {
				return errors.New("cross-origin redirect refused")
			}
			if request.URL.User != nil {
				return errors.New("redirect URL credentials refused")
			}
			if len(via) != 0 && via[len(via)-1].Method != request.Method {
				return errors.New("redirect changed HTTP method")
			}
			return nil
		},
	}

	return &Client{
		baseURL:                baseURL,
		token:                  config.Token,
		nodeID:                 config.NodeID,
		nodeType:               config.NodeType,
		http:                   httpClient,
		maxResponseBytes:       config.MaxResponseBytes,
		maxConfigResponseBytes: config.MaxConfigResponseBytes,
		maxUserResponseBytes:   config.MaxUserResponseBytes,
		maxUsers:               config.MaxUsers,
		maxOnlineIPsPerUser:    config.MaxOnlineIPsPerUser,
		userAgent:              config.UserAgent,
	}, nil
}

// Close releases keep-alive connections owned by the client.
func (c *Client) Close() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}

// GetNodeConfig fetches and validates the node configuration. changed is false
// on HTTP 304 or a semantically identical HTTP 200. Response validators are
// committed only after decoding and validation.
func (c *Client) GetNodeConfig(ctx context.Context) (node *model.NodeConfig, changed bool, err error) {
	defer func() { err = redactPublicError(err, c.token) }()
	c.nodeMu.Lock()
	defer c.nodeMu.Unlock()

	headers := make(http.Header)
	headers.Set("Accept", "application/json")
	if c.nodeETag != "" {
		headers.Set("If-None-Match", c.nodeETag)
	}
	response, err := c.request(ctx, http.MethodGet, ConfigEndpoint, headers, nil, "fetch node config")
	if err != nil {
		return nil, false, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		drain(response.Body, c.maxConfigResponseBytes)
		if c.nodeETag == "" {
			return nil, false, errors.New("panel returned HTTP 304 without a cached node ETag")
		}
		return nil, false, nil
	}
	if response.StatusCode != http.StatusOK {
		drain(response.Body, c.maxConfigResponseBytes)
		return nil, false, &HTTPStatusError{Operation: "fetch node config", StatusCode: response.StatusCode}
	}
	body, err := readBounded(response, c.maxConfigResponseBytes)
	if err != nil {
		return nil, false, fmt.Errorf("decode node config: %w", err)
	}
	defer clear(body)
	var decoded model.NodeConfig
	if err := decodeOneJSON(body, &decoded); err != nil {
		return nil, false, fmt.Errorf("decode node config: %w", err)
	}
	if err := decoded.Validate(); err != nil {
		return nil, false, fmt.Errorf("validate node config: %w", err)
	}
	if err := validateETag(response.Header.Get("ETag")); err != nil {
		return nil, false, err
	}
	semantic, err := hashSemantic(decoded)
	if err != nil {
		return nil, false, fmt.Errorf("hash node config: %w", err)
	}
	c.nodeETag = response.Header.Get("ETag")
	changed = !c.haveNodeHash || semantic != c.nodeHash
	c.nodeHash = semantic
	c.haveNodeHash = true
	if !changed {
		return nil, false, nil
	}
	return &decoded, true, nil
}

// GetUsers fetches the user envelope in JSON or MessagePack. changed is false
// on HTTP 304 or a semantically identical HTTP 200. Response validators are
// committed only after all users validate.
func (c *Client) GetUsers(ctx context.Context) (users []model.User, changed bool, err error) {
	defer func() { err = redactPublicError(err, c.token) }()
	c.userMu.Lock()
	defer c.userMu.Unlock()

	headers := make(http.Header)
	headers.Set("Accept", "application/x-msgpack, application/msgpack, application/json")
	headers.Set("X-Response-Format", "msgpack")
	if c.userETag != "" {
		headers.Set("If-None-Match", c.userETag)
	}
	response, err := c.request(ctx, http.MethodGet, UsersEndpoint, headers, nil, "fetch users")
	if err != nil {
		return nil, false, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		drain(response.Body, c.maxUserResponseBytes)
		if c.userETag == "" {
			return nil, false, errors.New("panel returned HTTP 304 without a cached user ETag")
		}
		return nil, false, nil
	}
	if response.StatusCode != http.StatusOK {
		drain(response.Body, c.maxUserResponseBytes)
		return nil, false, &HTTPStatusError{Operation: "fetch users", StatusCode: response.StatusCode}
	}
	body, err := readBounded(response, c.maxUserResponseBytes)
	if err != nil {
		return nil, false, fmt.Errorf("decode users: %w", err)
	}
	defer clear(body)
	if isMessagePack(response.Header.Get("Content-Type")) {
		users, err = decodeUsersMessagePack(body, c.maxUsers)
	} else {
		users, err = decodeUsersJSON(body, c.maxUsers)
	}
	if err != nil {
		return nil, false, fmt.Errorf("decode users: %w", err)
	}
	if err := validateETag(response.Header.Get("ETag")); err != nil {
		return nil, false, err
	}
	semantic := hashUsers(users)
	c.userETag = response.Header.Get("ETag")
	changed = !c.haveUserHash || semantic != c.userHash
	c.userHash = semantic
	c.haveUserHash = true
	if !changed {
		return nil, false, nil
	}
	return users, true, nil
}

// GetAlive fetches panel-side online device counts.
func (c *Client) GetAlive(ctx context.Context) (alive model.AliveUsers, err error) {
	defer func() { err = redactPublicError(err, c.token) }()
	headers := make(http.Header)
	headers.Set("Accept", "application/json")
	response, err := c.request(ctx, http.MethodGet, AliveListEndpoint, headers, nil, "fetch alive users")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		drain(response.Body, c.maxResponseBytes)
		return nil, &HTTPStatusError{Operation: "fetch alive users", StatusCode: response.StatusCode}
	}
	body, err := readBounded(response, c.maxResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("decode alive users: %w", err)
	}
	alive, err = decodeAliveJSON(body, c.maxUsers)
	if err != nil {
		return nil, fmt.Errorf("decode alive users: %w", err)
	}
	return alive, nil
}

// ReportTraffic sends the audited {uid:[upload,download]} payload.
func (c *Client) ReportTraffic(ctx context.Context, traffic []model.UserTraffic) (err error) {
	defer func() { err = redactPublicError(err, c.token) }()
	if len(traffic) > c.maxUsers {
		return fmt.Errorf("traffic report exceeds limit of %d users", c.maxUsers)
	}
	payload := make(map[int][2]int64, len(traffic))
	estimatedBytes := int64(2) // {}
	for index, item := range traffic {
		if item.UserID <= 0 {
			return errors.New("traffic report contains a non-positive user ID")
		}
		if item.Upload < 0 || item.Download < 0 {
			return errors.New("traffic report contains a negative byte count")
		}
		if _, exists := payload[item.UserID]; exists {
			return fmt.Errorf("traffic report contains duplicate user ID %d", item.UserID)
		}
		entryBytes := int64(len(strconv.Itoa(item.UserID)) + len(strconv.FormatInt(item.Upload, 10)) +
			len(strconv.FormatInt(item.Download, 10)) + 6) // "id":[up,down]
		if index != 0 {
			entryBytes++ // comma
		}
		if !addWithinLimit(&estimatedBytes, entryBytes, c.maxResponseBytes) {
			return fmt.Errorf("traffic report payload exceeds limit of %d bytes", c.maxResponseBytes)
		}
		payload[item.UserID] = [2]int64{item.Upload, item.Download}
	}
	return c.postJSON(ctx, TrafficEndpoint, payload, "report traffic")
}

// ReportOnline sends the audited {uid:[ip,...]} payload.
func (c *Client) ReportOnline(ctx context.Context, online model.OnlineUsers) (err error) {
	defer func() { err = redactPublicError(err, c.token) }()
	if online == nil {
		online = make(model.OnlineUsers)
	}
	if len(online) > c.maxUsers {
		return fmt.Errorf("online report exceeds limit of %d users", c.maxUsers)
	}
	estimatedBytes := int64(2) // {}
	entryIndex := 0
	for userID, addresses := range online {
		if userID <= 0 {
			return errors.New("online report contains a non-positive user ID")
		}
		if len(addresses) > c.maxOnlineIPsPerUser {
			return fmt.Errorf("online report for user %d exceeds limit of %d IPs", userID, c.maxOnlineIPsPerUser)
		}
		entryBytes := int64(len(strconv.Itoa(userID)) + 5) // "id":[]
		for addressIndex, address := range addresses {
			parsed, parseErr := netip.ParseAddr(address)
			if parseErr != nil || parsed.Zone() != "" || len(address) > 512 {
				return fmt.Errorf("online report for user %d contains an invalid address", userID)
			}
			entryBytes += int64(len(address) + 2) // quoted IP
			if addressIndex != 0 {
				entryBytes++ // comma
			}
		}
		if entryIndex != 0 {
			entryBytes++ // comma
		}
		entryIndex++
		if !addWithinLimit(&estimatedBytes, entryBytes, c.maxResponseBytes) {
			return fmt.Errorf("online report payload exceeds limit of %d bytes", c.maxResponseBytes)
		}
	}
	return c.postJSON(ctx, OnlineEndpoint, online, "report online users")
}

func (c *Client) postJSON(ctx context.Context, endpoint string, value any, operation string) error {
	body, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode %s: %w", operation, err)
	}
	if int64(len(body)) > c.maxResponseBytes {
		return fmt.Errorf("%s payload exceeds limit of %d bytes", operation, c.maxResponseBytes)
	}
	headers := make(http.Header)
	headers.Set("Accept", "application/json")
	headers.Set("Content-Type", "application/json")
	response, err := c.request(ctx, http.MethodPost, endpoint, headers, body, operation)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		drain(response.Body, c.maxResponseBytes)
		return &HTTPStatusError{Operation: operation, StatusCode: response.StatusCode}
	}
	// Once a 2xx status has arrived, the panel may already have committed the
	// report. A truncated or oversized response body is therefore not a safe
	// reason to retry non-idempotent traffic accounting. Drain only to preserve
	// connection reuse when possible and treat the status as the acknowledgement.
	drain(response.Body, c.maxResponseBytes)
	return nil
}

func (c *Client) request(ctx context.Context, method, endpoint string, headers http.Header, body []byte, operation string) (*http.Response, error) {
	if ctx == nil {
		return nil, errors.New("panel request context must not be nil")
	}
	requestURL := *c.baseURL
	requestURL.Path = strings.TrimRight(c.baseURL.Path, "/") + endpoint
	requestURL.RawPath = ""
	query := requestURL.Query()
	query.Set("node_type", c.nodeType)
	query.Set("node_id", strconv.Itoa(c.nodeID))
	query.Set("token", c.token)
	requestURL.RawQuery = query.Encode()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), reader)
	if err != nil {
		return nil, fmt.Errorf("panel %s request is invalid", operation)
	}
	request.Header = headers.Clone()
	request.Header.Set("User-Agent", c.userAgent)
	response, err := c.http.Do(request)
	if err != nil {
		return nil, safeRequestError(operation, err, c.token, ctx)
	}
	return response, nil
}

func readBounded(response *http.Response, limit int64) ([]byte, error) {
	if response.ContentLength > limit {
		return nil, fmt.Errorf("response exceeds limit of %d bytes", limit)
	}
	reader := &io.LimitedReader{R: response.Body, N: limit + 1}
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response exceeds limit of %d bytes", limit)
	}
	return body, nil
}

func drain(body io.Reader, limit int64) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, limit+1))
}

func decodeOneJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func validateETag(etag string) error {
	if len(etag) > maxETagBytes || strings.ContainsAny(etag, "\r\n") {
		return errors.New("panel returned an invalid ETag")
	}
	return nil
}

func hashSemantic(value any) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	result := sha256.Sum256(encoded)
	clear(encoded)
	return result, nil
}

func hashUsers(users []model.User) [sha256.Size]byte {
	// User order has no data-plane meaning: compilation sorts by ID. Hash a
	// sorted slice so panels that vary array order do not restart the engine.
	// The response slice is owned by this client, so sorting it in place avoids
	// another multi-megabyte []User allocation on large nodes. Stream fields
	// into the hash instead of JSON-marshaling the complete user list.
	sort.Slice(users, func(i, j int) bool { return users[i].ID < users[j].ID })
	digest := sha256.New()
	writeHashInt64(digest, int64(len(users)))
	for _, user := range users {
		writeHashInt64(digest, int64(user.ID))
		writeHashInt64(digest, int64(len(user.UUID)))
		_, _ = digest.Write([]byte(user.UUID))
		writeHashInt64(digest, int64(user.SpeedLimit))
		writeHashInt64(digest, int64(user.DeviceLimit))
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func writeHashInt64(destination io.Writer, value int64) {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], uint64(value))
	_, _ = destination.Write(encoded[:])
}

func isMessagePack(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = strings.TrimSpace(strings.Split(contentType, ";")[0])
	}
	switch strings.ToLower(mediaType) {
	case "application/x-msgpack", "application/msgpack", "application/vnd.msgpack":
		return true
	default:
		return false
	}
}

func validNodeType(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func originKey(value *url.URL) string {
	scheme := strings.ToLower(value.Scheme)
	host := strings.ToLower(value.Hostname())
	port := value.Port()
	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func safeRequestError(operation string, err error, token string, ctx context.Context) error {
	if contextError := ctx.Err(); contextError != nil && errors.Is(err, contextError) {
		return fmt.Errorf("panel %s: %w", operation, contextError)
	}
	message := redactText(err.Error(), token)
	return fmt.Errorf("panel %s request failed: %s", operation, message)
}

type redactedError struct {
	message string
	cause   error
}

func (e *redactedError) Error() string { return e.message }
func (e *redactedError) Unwrap() error { return e.cause }

func redactPublicError(err error, token string) error {
	if err == nil {
		return nil
	}
	message := redactText(err.Error(), token)
	if message == err.Error() {
		return err
	}
	return &redactedError{message: message, cause: err}
}

func redactText(message, token string) string {
	variants := []string{token, url.QueryEscape(token), url.PathEscape(token)}
	sort.Slice(variants, func(i, j int) bool { return len(variants[i]) > len(variants[j]) })
	for _, variant := range variants {
		if variant != "" {
			message = strings.ReplaceAll(message, variant, "[REDACTED]")
		}
	}
	return message
}

func intFits(value int64) bool {
	if strconv.IntSize == 32 {
		return value >= math.MinInt32 && value <= math.MaxInt32
	}
	return true
}

func addWithinLimit(total *int64, addition, limit int64) bool {
	if addition < 0 || *total > limit-addition {
		return false
	}
	*total += addition
	return true
}
