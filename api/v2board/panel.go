package panel

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/Duyvj/v3node/conf"
	"github.com/go-resty/resty/v2"
)

// Panel is the interface for different panel's api.

type Client struct {
	client           *resty.Client
	APIHost          string
	AgentID          string
	Token            string
	NodeId           int
	nodeEtag         string
	userEtag         string
	responseBodyHash string
	UserList         *UserListBody
	AliveMap         *AliveMap
	fallbackConfig   *conf.GlobalDeviceLimitConfig
	fallbackMu       sync.Mutex
}

// UpdateFallbackConfig changes only the signed Redis user-snapshot source.
// It does not touch Xray inbounds, users, or the device limiter.
func (c *Client) UpdateFallbackConfig(config *conf.GlobalDeviceLimitConfig) {
	c.fallbackMu.Lock()
	c.fallbackConfig = cloneGlobalDeviceLimitConfig(config)
	c.fallbackMu.Unlock()
}

// Ordinary panel responses are small JSON documents. Keep a hard ceiling so
// a compromised/misconfigured endpoint cannot make the root Agent buffer an
// unbounded body. The user list is streamed separately in user.go.
const maxBufferedPanelResponseBytes = 8 << 20

func New(c *conf.NodeConfig) (*Client, error) {
	if c == nil {
		return nil, fmt.Errorf("node client requires a config")
	}
	if strings.TrimSpace(c.AgentID) == "" || strings.TrimSpace(c.Key) == "" {
		return nil, fmt.Errorf("node client requires per-agent credentials; legacy manual/global tokens are disabled")
	}
	apiHost, err := conf.NormalizePanelAPIHost(c.APIHost)
	if err != nil {
		return nil, fmt.Errorf("node client: %w", err)
	}
	client := resty.New()
	client.SetResponseBodyLimit(maxBufferedPanelResponseBytes)
	// Agent credentials are also carried in an X-ZNode header, which Go's
	// default cross-origin redirect policy does not classify as sensitive.
	// Never follow panel redirects: a compromised/misconfigured endpoint must
	// not be able to bounce the request to another host and steal the token.
	client.SetRedirectPolicy(resty.NoRedirectPolicy())
	client.SetTLSClientConfig(&tls.Config{MinVersion: tls.VersionTLS12})
	retryCount := conf.DefaultNodeRetryCount
	if c.RetryCount != nil {
		retryCount = *c.RetryCount
	}
	client.SetRetryCount(retryCount)
	client.SetHeader("User-Agent", fmt.Sprintf("v2node go-resty/%s (https://github.com/go-resty/resty)", resty.Version))
	client.SetHeader("X-V2Node-Version", ClientVersion())
	client.SetHeader("X-ZNode-Version", ClientVersion())
	client.SetHeader("X-V2Node-Type", conf.RequiredPanelType)
	client.SetHeader("X-ZNode-Type", conf.RequiredPanelType)
	if c.Timeout > 0 {
		client.SetTimeout(time.Duration(c.Timeout) * time.Second)
	} else {
		client.SetTimeout(time.Duration(conf.DefaultNodeTimeout) * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			logrus.Error(v.Err)
		}
	})
	client.SetBaseURL(apiHost)
	// set params
	query := map[string]string{
		"node_type": "v2node",
		"node_id":   strconv.Itoa(c.NodeID),
		"type":      conf.RequiredPanelType,
	}
	client.SetHeader("X-V2Node-Agent-ID", c.AgentID)
	client.SetHeader("X-ZNode-Agent-ID", c.AgentID)
	client.SetHeader("X-V2Node-Instance-ID", effectiveInstanceID(c.AgentInstanceID))
	client.SetHeader("X-ZNode-Instance-ID", effectiveInstanceID(c.AgentInstanceID))
	setInstanceSecretHeader(client)
	client.SetHeader("X-V2Node-Agent-Token", c.Key)
	client.SetHeader("X-ZNode-Agent-Token", c.Key)
	client.SetAuthToken(c.Key)
	setAddressHeaders(client)
	client.SetQueryParams(query)
	return &Client{
		client:         client,
		Token:          c.Key,
		APIHost:        apiHost,
		AgentID:        c.AgentID,
		NodeId:         c.NodeID,
		UserList:       &UserListBody{},
		AliveMap:       &AliveMap{},
		fallbackConfig: cloneGlobalDeviceLimitConfig(c.GlobalDeviceLimitConfig),
	}, nil
}
