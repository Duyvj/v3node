package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const maxConnectionsBody = 64 << 20

var connectionIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,80}$`)

type ActiveConnection struct {
	ID        string
	User      string
	SourceIP  netip.Addr
	Upload    uint64
	Download  uint64
	StartedAt time.Time
}

type ConnectionsClient struct {
	base       *url.URL
	httpClient *http.Client
	maxItems   int
	secret     string
}

type connectionWire struct {
	ID       string    `json:"id"`
	Upload   uint64    `json:"upload"`
	Download uint64    `json:"download"`
	Start    time.Time `json:"start"`
	Metadata struct {
		SourceIP    string `json:"sourceIP"`
		User        string `json:"user"`
		InboundUser string `json:"inboundUser"`
	} `json:"metadata"`
}

func NewConnectionsClient(address string, timeout time.Duration, maxItems int, secret string) (*ConnectionsClient, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid connections API address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("connections API must use a loopback IP")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if maxItems <= 0 {
		maxItems = 100_000
	}
	if strings.TrimSpace(secret) == "" || strings.ContainsAny(secret, "\r\n") {
		return nil, errors.New("connections API secret must not be empty")
	}
	base, _ := url.Parse("http://" + address + "/connections")
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &ConnectionsClient{base: base, httpClient: client, maxItems: maxItems, secret: secret}, nil
}

func (c *ConnectionsClient) Snapshot(ctx context.Context) ([]ActiveConnection, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("read active connections: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("read active connections: unexpected HTTP status %d", resp.StatusCode)
	}
	limit := connectionsBodyLimit(c.maxItems)
	if resp.ContentLength > limit {
		return nil, errors.New("active connections response is too large")
	}
	limited := &io.LimitedReader{R: resp.Body, N: limit + 1}
	result, err := decodeConnections(limited, c.maxItems)
	if limited.N <= 0 {
		return nil, errors.New("active connections response is too large")
	}
	if err != nil {
		return nil, fmt.Errorf("decode active connections: %w", err)
	}
	return result, nil
}

func decodeConnections(reader io.Reader, maxItems int) ([]ActiveConnection, error) {
	decoder := json.NewDecoder(reader)
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("active connections response must be a JSON object")
	}
	result := make([]ActiveConnection, 0, min(maxItems, 1024))
	foundConnections := false
	count := 0
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("active connections response contains a non-string key")
		}
		if key != "connections" {
			if err := skipJSONValue(decoder); err != nil {
				return nil, err
			}
			continue
		}
		if foundConnections {
			return nil, errors.New("active connections response contains duplicate connections fields")
		}
		foundConnections = true
		opening, err := decoder.Token()
		if err != nil || opening != json.Delim('[') {
			return nil, errors.New("active connections field must be an array")
		}
		for decoder.More() {
			count++
			if count > maxItems {
				return nil, fmt.Errorf("active connection count exceeds limit %d", maxItems)
			}
			var connection connectionWire
			if err := decoder.Decode(&connection); err != nil {
				return nil, err
			}
			user := connection.Metadata.User
			if user == "" {
				user = connection.Metadata.InboundUser
			}
			ip, err := netip.ParseAddr(connection.Metadata.SourceIP)
			if err != nil || user == "" || !connectionIDPattern.MatchString(connection.ID) {
				continue
			}
			result = append(result, ActiveConnection{
				ID:        connection.ID,
				User:      user,
				SourceIP:  ip.Unmap(),
				Upload:    connection.Upload,
				Download:  connection.Download,
				StartedAt: connection.Start,
			})
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return nil, errors.New("active connections array is not closed")
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, errors.New("active connections response is not closed")
	}
	if !foundConnections {
		return nil, errors.New("active connections response has no connections field")
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("active connections response has trailing token %v", token)
		}
		return nil, err
	}
	return result, nil
}

func skipJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, nested := token.(json.Delim)
	if !nested || (delimiter != '{' && delimiter != '[') {
		return nil
	}
	depth := 1
	for depth > 0 {
		token, err = decoder.Token()
		if err != nil {
			return err
		}
		if delimiter, nested = token.(json.Delim); nested {
			switch delimiter {
			case '{', '[':
				depth++
				if depth > 64 {
					return errors.New("active connections response is nested too deeply")
				}
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

func connectionsBodyLimit(maxItems int) int64 {
	limit := int64(maxItems)*1024 + 64<<10
	if limit < 1<<20 {
		return 1 << 20
	}
	if limit > maxConnectionsBody {
		return maxConnectionsBody
	}
	return limit
}

func (c *ConnectionsClient) Close(ctx context.Context, id string) error {
	if !connectionIDPattern.MatchString(id) {
		return errors.New("invalid connection ID")
	}
	u := *c.base
	u.Path += "/" + id
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("close connection: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusNoContent && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return fmt.Errorf("close connection: unexpected HTTP status %d", resp.StatusCode)
	}
	return nil
}
