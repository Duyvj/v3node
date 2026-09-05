package panel

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"encoding/json/jsontext"
	"encoding/json/v2"

	"github.com/vmihailenco/msgpack/v5"
)

type OnlineUser struct {
	UID int
	IP  string
}

type UserInfo struct {
	// Id is the node-side identity used for traffic and online-device reports.
	// It may be a synthetic subscription/device ID, so multiple UUIDs owned by
	// the same account remain independent on the node.
	Id             int    `json:"id" msgpack:"id"`
	UserId         int    `json:"user_id,omitempty" msgpack:"user_id,omitempty"`
	SubscriptionId int    `json:"subscription_id,omitempty" msgpack:"subscription_id,omitempty"`
	Uuid           string `json:"uuid" msgpack:"uuid"`
	SpeedLimit     int    `json:"speed_limit" msgpack:"speed_limit"`
	DeviceLimit    int    `json:"device_limit" msgpack:"device_limit"`
}

type UserListBody struct {
	Users []UserInfo `json:"users" msgpack:"users"`
}

type AliveMap struct {
	Alive map[int]int `json:"alive"`
}

type UserRevisionBody struct {
	Revision string `json:"revision"`
}

const maxPanelUsers = 200000
const maxPanelUserResponseBytes int64 = 64 << 20
const trafficCapabilityPath = "/api/v1/server/UniProxy/capability"
const userRevisionPath = "/api/v1/server/UniProxy/revision"

// GetUserRevision fetches a tiny authenticated desired-state marker. Even in
// Redis-primary mode this request remains enabled so token rotation/revocation
// is observed while Redis supplies the heavier user snapshot.
func (c *Client) GetUserRevision(ctx context.Context) (string, error) {
	r, err := c.client.R().
		SetContext(ctx).
		ForceContentType("application/json").
		Get(userRevisionPath)
	if err != nil {
		return "", fmt.Errorf("get user revision: %w", err)
	}
	if r == nil || r.RawResponse == nil {
		return "", fmt.Errorf("get user revision: panel returned no response")
	}
	if r.StatusCode() < http.StatusOK || r.StatusCode() >= http.StatusMultipleChoices {
		return "", &userRevisionHTTPError{Status: r.StatusCode()}
	}
	var body UserRevisionBody
	if err := json.Unmarshal(r.Body(), &body); err != nil {
		return "", fmt.Errorf("decode user revision: %w", err)
	}
	revision := strings.TrimSpace(body.Revision)
	if revision == "0" {
		return revision, nil
	}
	if len(revision) != 32 {
		return "", fmt.Errorf("decode user revision: invalid revision")
	}
	if _, err := hex.DecodeString(revision); err != nil {
		return "", fmt.Errorf("decode user revision: invalid revision")
	}
	return revision, nil
}

// UserRevisionPollInterval lets Redis-primary nodes retain a lightweight
// authorization check without creating the old two-second request storm.
func (c *Client) UserRevisionPollInterval() time.Duration {
	if c.userSourceMode() == "redis_primary" {
		return 15 * time.Second
	}
	return 2 * time.Second
}

// GetUserList keeps ZBoard authoritative. Redis is consulted only after the
// live panel request fails, and every fallback snapshot must pass the Agent
// token HMAC before it can change runtime credentials.
func (c *Client) GetUserList(ctx context.Context) ([]UserInfo, error) {
	if c.userSourceMode() == "redis_primary" {
		// Keep the lightweight panel authorization check even when Redis is the
		// preferred user source. Network failures may use Redis; explicit 401/403
		// responses must never be bypassed by a still-valid old snapshot.
		if _, revisionErr := c.GetUserRevision(ctx); revisionErr != nil {
			var statusError *userRevisionHTTPError
			if errors.As(revisionErr, &statusError) && (statusError.Status == http.StatusUnauthorized ||
				statusError.Status == http.StatusForbidden || statusError.Status == http.StatusGone) {
				return nil, revisionErr
			}
		}
		users, fallbackErr := c.getFallbackUserList(ctx)
		if fallbackErr == nil {
			c.userEtag = ""
			c.UserList = &UserListBody{Users: cloneUserList(users)}
			return cloneUserList(users), nil
		}
		users, panelErr := c.getUserListFromPanel(ctx)
		if panelErr == nil {
			markZBoardControlPlaneHealthy(c.APIHost, c.AgentID)
			return users, nil
		}
		return nil, fmt.Errorf("signed Redis snapshot unavailable: %v; live ZBoard fallback failed: %w", fallbackErr, panelErr)
	}
	users, err := c.getUserListFromPanel(ctx)
	if err == nil {
		markZBoardControlPlaneHealthy(c.APIHost, c.AgentID)
		return users, nil
	}
	var statusError *userListHTTPError
	if errors.As(err, &statusError) && (statusError.Status == http.StatusUnauthorized ||
		statusError.Status == http.StatusForbidden || statusError.Status == http.StatusGone) {
		return nil, err
	}
	if zboardControlPlaneRecentlyHealthy(c.APIHost, c.AgentID) {
		return nil, fmt.Errorf("%w; live ZBoard control plane is healthy, Redis fallback suppressed", err)
	}
	fallback, fallbackErr := c.getFallbackUserList(ctx)
	if fallbackErr != nil {
		return nil, fmt.Errorf("%w; signed Redis fallback unavailable: %v", err, fallbackErr)
	}
	c.userEtag = ""
	c.UserList = &UserListBody{Users: cloneUserList(fallback)}
	return cloneUserList(fallback), nil
}

func (c *Client) userSourceMode() string {
	c.fallbackMu.Lock()
	defer c.fallbackMu.Unlock()
	if c.fallbackConfig != nil && c.fallbackConfig.UserSourceMode == "redis_primary" {
		return "redis_primary"
	}
	return "web_primary"
}

func (c *Client) getUserListFromPanel(ctx context.Context) ([]UserInfo, error) {
	const path = "/api/v1/server/UniProxy/user"
	r, err := c.client.R().
		SetContext(ctx).
		SetHeader("If-None-Match", c.userEtag).
		SetHeader("X-Response-Format", "msgpack").
		SetDoNotParseResponse(true).
		Get(path)
	if err != nil {
		return nil, err
	}
	if r == nil || r.RawResponse == nil {
		return nil, fmt.Errorf("received nil response or raw response")
	}
	defer r.RawResponse.Body.Close()

	if r.StatusCode() == 304 {
		if c.UserList == nil || c.UserList.Users == nil {
			return nil, fmt.Errorf("get user list: panel returned not-modified before a complete user snapshot")
		}
		// Return the last complete desired state instead of a nil sentinel. The
		// controller may have failed after fetching the preceding 200 response
		// (for example while reading alive state); replaying this snapshot makes
		// revocations retry even though the panel correctly answers 304 next time.
		return cloneUserList(c.UserList.Users), nil
	}
	if r.StatusCode() < http.StatusOK || r.StatusCode() >= http.StatusMultipleChoices {
		return nil, &userListHTTPError{Status: r.StatusCode()}
	}
	if r.RawResponse.ContentLength > maxPanelUserResponseBytes {
		return nil, fmt.Errorf("decode user list error: response is too large")
	}
	body := &io.LimitedReader{R: r.RawResponse.Body, N: maxPanelUserResponseBytes + 1}
	// Keep an empty response distinguishable from a 304 response. A nil slice
	// means "not modified" to the node task, while a non-nil empty slice means
	// that the panel intentionally removed every user (for example, the last
	// banned device).
	userlist := &UserListBody{Users: make([]UserInfo, 0)}
	if strings.Contains(r.Header().Get("Content-Type"), "application/x-msgpack") {
		users, err := decodeMsgpackUserList(msgpack.NewDecoder(body))
		if err != nil {
			return nil, fmt.Errorf("decode user list error: %w", err)
		}
		userlist.Users = users
	} else {
		users, err := decodeJSONUserList(jsontext.NewDecoder(body))
		if err != nil {
			return nil, fmt.Errorf("decode user list error: %w", err)
		}
		userlist.Users = users
	}
	if body.N <= 0 {
		return nil, fmt.Errorf("decode user list error: response is too large")
	}
	if userlist.Users == nil {
		userlist.Users = make([]UserInfo, 0)
	}
	if err := validateUserList(userlist.Users); err != nil {
		return nil, err
	}
	etag := strings.TrimSpace(r.Header().Get("ETag"))
	if len(etag) > 512 || strings.IndexFunc(etag, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return nil, fmt.Errorf("get user list: panel returned an invalid ETag")
	}
	// Commit the validator and replay snapshot together only after the complete
	// body passed all bounds and semantic validation.
	c.userEtag = etag
	c.UserList = &UserListBody{Users: cloneUserList(userlist.Users)}
	return cloneUserList(userlist.Users), nil
}

type userListHTTPError struct {
	Status int
}

type userRevisionHTTPError struct {
	Status int
}

func (e *userRevisionHTTPError) Error() string {
	return fmt.Sprintf("get user revision: panel returned HTTP %d", e.Status)
}

func (e *userListHTTPError) Error() string {
	return fmt.Sprintf("get user list: panel returned HTTP %d", e.Status)
}

func cloneUserList(users []UserInfo) []UserInfo {
	cloned := make([]UserInfo, len(users))
	copy(cloned, users)
	return cloned
}

func decodeJSONUserList(decoder *jsontext.Decoder) ([]UserInfo, error) {
	token, err := decoder.ReadToken()
	if err != nil {
		return nil, err
	}
	if token.Kind() != '{' {
		return nil, fmt.Errorf("expected user-list object")
	}
	users := make([]UserInfo, 0)
	found := false
	fields := 0
	for decoder.PeekKind() != '}' {
		if fields >= 64 {
			return nil, fmt.Errorf("too many user-list fields")
		}
		fields++
		key, err := decoder.ReadToken()
		if err != nil {
			return nil, err
		}
		if key.Kind() != '"' || len(key.String()) > 64 {
			return nil, fmt.Errorf("invalid user-list field")
		}
		if key.String() != "users" {
			if err := decoder.SkipValue(); err != nil {
				return nil, err
			}
			continue
		}
		if found {
			return nil, fmt.Errorf("duplicate users field")
		}
		found = true
		arrayStart, err := decoder.ReadToken()
		if err != nil {
			return nil, err
		}
		if arrayStart.Kind() != '[' {
			return nil, fmt.Errorf(`expected "users" array`)
		}
		for decoder.PeekKind() != ']' {
			if len(users) >= maxPanelUsers {
				return nil, fmt.Errorf("too many users")
			}
			var user UserInfo
			if err := json.UnmarshalDecode(decoder, &user); err != nil {
				return nil, fmt.Errorf("decode user: %w", err)
			}
			users = append(users, user)
		}
		if _, err := decoder.ReadToken(); err != nil {
			return nil, err
		}
	}
	if _, err := decoder.ReadToken(); err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("missing users field")
	}
	if _, err := decoder.ReadToken(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("trailing JSON value")
		}
		return nil, err
	}
	return users, nil
}

func decodeMsgpackUserList(decoder *msgpack.Decoder) ([]UserInfo, error) {
	fieldCount, err := decoder.DecodeMapLen()
	if err != nil {
		return nil, err
	}
	if fieldCount < 0 || fieldCount > 64 {
		return nil, fmt.Errorf("invalid user-list object")
	}

	var users []UserInfo
	found := false
	for index := 0; index < fieldCount; index++ {
		key, err := decoder.DecodeString()
		if err != nil {
			return nil, err
		}
		if len(key) > 64 {
			return nil, fmt.Errorf("invalid user-list field")
		}
		if key != "users" {
			if err := decoder.Skip(); err != nil {
				return nil, err
			}
			continue
		}
		if found {
			return nil, fmt.Errorf("duplicate users field")
		}
		found = true
		userCount, err := decoder.DecodeArrayLen()
		if err != nil {
			return nil, err
		}
		if userCount < 0 || userCount > maxPanelUsers {
			return nil, fmt.Errorf("too many users")
		}
		users = make([]UserInfo, 0, userCount)
		for userIndex := 0; userIndex < userCount; userIndex++ {
			var user UserInfo
			if err := decoder.Decode(&user); err != nil {
				return nil, err
			}
			users = append(users, user)
		}
	}
	if !found {
		return nil, fmt.Errorf("missing users field")
	}
	if _, err := decoder.PeekCode(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("trailing msgpack value")
		}
		return nil, err
	}
	return users, nil
}

func validateUserList(users []UserInfo) error {
	seenUUID := make(map[string]struct{}, len(users))
	for index, user := range users {
		uuid := strings.TrimSpace(user.Uuid)
		if user.Id <= 0 || uuid == "" || len(uuid) > 512 {
			return fmt.Errorf("invalid user at index %d", index)
		}
		if user.SpeedLimit < 0 || user.SpeedLimit > 1000000000 || user.DeviceLimit < 0 || user.DeviceLimit > 1000000 {
			return fmt.Errorf("invalid limits for user at index %d", index)
		}
		if _, exists := seenUUID[uuid]; exists {
			return fmt.Errorf("duplicate user credential at index %d", index)
		}
		seenUUID[uuid] = struct{}{}
	}
	return nil
}

// ValidateUserListSnapshot applies the same semantic bounds to data restored
// from the root-owned offline runtime snapshot as to a live panel response.
func ValidateUserListSnapshot(users []UserInfo) error {
	if len(users) > maxPanelUsers {
		return fmt.Errorf("too many users")
	}
	return validateUserList(users)
}

// GetUserAlive will fetch the alive_ip count for users
func (c *Client) GetUserAlive(ctx context.Context) (map[int]int, error) {
	const path = "/api/v1/server/UniProxy/alivelist"
	r, err := c.client.R().
		SetContext(ctx).
		ForceContentType("application/json").
		Get(path)
	if err != nil {
		return nil, fmt.Errorf("get user alive list: %w", err)
	}
	if r == nil || r.RawResponse == nil {
		return nil, fmt.Errorf("get user alive list: panel returned no response")
	}
	if r.StatusCode() < http.StatusOK || r.StatusCode() >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("get user alive list: panel returned HTTP %d", r.StatusCode())
	}
	defer r.RawResponse.Body.Close()
	next := &AliveMap{}
	if err := json.Unmarshal(r.Body(), next); err != nil {
		return nil, fmt.Errorf("decode user alive list: %w", err)
	}
	if next.Alive == nil {
		next.Alive = make(map[int]int)
	}
	for uid, count := range next.Alive {
		if uid <= 0 || count < 0 {
			return nil, fmt.Errorf("decode user alive list: invalid entry")
		}
	}
	// Publish a new fallback snapshot only after a complete, successful
	// response. A transient 5xx or malformed body must not erase the previous
	// conservative device count and silently weaken per-user limits.
	c.AliveMap = next
	return next.Alive, nil
}

type UserTraffic struct {
	UID      int
	Upload   int64
	Download int64
}

type trafficReportAck struct {
	Data     bool   `json:"data"`
	ReportID string `json:"report_id"`
}

// ReportUserTraffic reports the user traffic
func (c *Client) ReportUserTraffic(ctx context.Context, reportID string, userTraffic []UserTraffic) error {
	// Probe capability before the first state-changing request. Sending an
	// immutable report to an older panel and discovering incompatibility only
	// from its response is too late: that panel may already have charged the
	// body without recording the report ID. Keep the durable spool intact
	// until ZBoard protocol 2 is deployed.
	if reportID != "" {
		if err := c.requireTrafficProtocol2(ctx); err != nil {
			return err
		}
	}
	data := aggregateUserTraffic(userTraffic)
	const path = "/api/v1/server/UniProxy/push"
	req := c.client.R().
		SetContext(ctx).
		SetBody(data).
		ForceContentType("application/json").
		SetHeader("X-V2Node-Traffic-Protocol", "2").
		SetHeader("X-ZNode-Traffic-Protocol", "2")
	if reportID != "" {
		req.SetHeader("X-V2Node-Traffic-Report-ID", reportID)
		req.SetHeader("X-ZNode-Traffic-Report-ID", reportID)
	}
	response, err := req.Post(path)
	if err != nil {
		return err
	}
	if response == nil || response.StatusCode() < http.StatusOK || response.StatusCode() >= http.StatusMultipleChoices {
		if response == nil {
			return fmt.Errorf("report user traffic: panel returned no response")
		}
		return fmt.Errorf("report user traffic: panel returned HTTP %d", response.StatusCode())
	}
	if reportID != "" {
		contentType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header().Get("Content-Type"), ";")[0]))
		if contentType != "application/json" && !strings.HasSuffix(contentType, "+json") {
			return fmt.Errorf("report user traffic: panel acknowledgement is not JSON")
		}
		var ack trafficReportAck
		if err := json.Unmarshal(response.Body(), &ack); err != nil {
			return fmt.Errorf("report user traffic: invalid panel acknowledgement: %w", err)
		}
		isProtocol2 := strings.TrimSpace(response.Header().Get("X-ZBoard-Traffic-Protocol")) == "2" || strings.TrimSpace(response.Header().Get("X-V2Node-Traffic-Protocol")) == "2"
		if isProtocol2 {
			if ack.Data && ack.ReportID == reportID {
				return nil
			}
			return fmt.Errorf("report user traffic: panel acknowledgement did not confirm report %s", reportID)
		}
		if ack.Data && (ack.ReportID == reportID || ack.ReportID == "") {
			return nil
		}
		return fmt.Errorf("report user traffic: panel acknowledgement did not confirm report %s", reportID)
	}
	return nil
}

func (c *Client) requireTrafficProtocol2(ctx context.Context) error {
	response, err := c.client.R().
		SetContext(ctx).
		SetHeader("Accept", "application/json").
		Get(trafficCapabilityPath)
	if err != nil {
		return fmt.Errorf("check traffic protocol capability: %w", err)
	}
	if response == nil {
		return fmt.Errorf("check traffic protocol capability: panel returned no response")
	}
	if response.StatusCode() == http.StatusNotFound || response.StatusCode() == http.StatusMethodNotAllowed || response.StatusCode() == http.StatusBadRequest {
		return nil
	}
	if response.StatusCode() < http.StatusOK || response.StatusCode() >= http.StatusMultipleChoices {
		return fmt.Errorf("check traffic protocol capability: panel returned HTTP %d", response.StatusCode())
	}
	return nil
}

// aggregateUserTraffic prevents traffic loss when a legacy panel sends more
// than one UUID with the same numeric user ID. Modern panels normally provide
// a unique synthetic ID per subscription/device, but summing here keeps the
// old wire format safe as well.
func aggregateUserTraffic(userTraffic []UserTraffic) map[int][]int64 {
	data := make(map[int][]int64, len(userTraffic))
	for i := range userTraffic {
		current := data[userTraffic[i].UID]
		if current == nil {
			current = []int64{0, 0}
		}
		current[0] += userTraffic[i].Upload
		current[1] += userTraffic[i].Download
		data[userTraffic[i].UID] = current
	}
	return data
}

func (c *Client) ReportNodeOnlineUsers(ctx context.Context, data *map[int][]string) error {
	const path = "/api/v1/server/UniProxy/alive"
	response, err := c.client.R().
		SetContext(ctx).
		SetBody(data).
		ForceContentType("application/json").
		Post(path)

	if err != nil {
		return err
	}
	if response == nil || response.StatusCode() < http.StatusOK || response.StatusCode() >= http.StatusMultipleChoices {
		if response == nil {
			return fmt.Errorf("report online users: panel returned no response")
		}
		return fmt.Errorf("report online users: panel returned HTTP %d", response.StatusCode())
	}

	return nil
}
