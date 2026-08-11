package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const queryStatsMethod = "/v2ray.core.app.stats.command.StatsService/QueryStats"

// These wire structs intentionally contain only the stable subset of the
// V2Ray StatsService protobuf contract used by both Xray and sing-box.
type queryStatsRequest struct {
	Pattern string `protobuf:"bytes,1,opt,name=pattern,proto3" json:"pattern,omitempty"`
	Reset_  bool   `protobuf:"varint,2,opt,name=reset,proto3" json:"reset,omitempty"`
}

func (m *queryStatsRequest) String() string {
	return fmt.Sprintf("pattern=%q reset=%t", m.Pattern, m.Reset_)
}
func (*queryStatsRequest) ProtoMessage() {}
func (m *queryStatsRequest) Reset()      { *m = queryStatsRequest{} }

type statMessage struct {
	Name  string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Value int64  `protobuf:"varint,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (m *statMessage) Reset()         { *m = statMessage{} }
func (m *statMessage) String() string { return fmt.Sprintf("%s=%d", m.Name, m.Value) }
func (*statMessage) ProtoMessage()    {}

type queryStatsResponse struct {
	Stat []*statMessage `protobuf:"bytes,1,rep,name=stat,proto3" json:"stat,omitempty"`
}

func (m *queryStatsResponse) Reset()         { *m = queryStatsResponse{} }
func (m *queryStatsResponse) String() string { return fmt.Sprintf("stats=%d", len(m.Stat)) }
func (*queryStatsResponse) ProtoMessage()    {}

type TrafficDelta struct {
	Upload   int64
	Download int64
}

type StatsClient struct {
	address     string
	dialTimeout time.Duration
	maxBytes    int
	mu          sync.Mutex
	conn        *grpc.ClientConn

	baselineGeneration uint64
	haveBaseline       bool
	baselineRevision   uint64
	baselines          map[string]int64
}

// TrafficSample is a cumulative stats observation that has not yet advanced
// the client's baseline. Call Commit only after every delta has been retained
// durably by the accounting layer. If retention fails, discard the sample; a
// later Poll will include the same bytes again because QueryStats is never
// reset by this client.
type TrafficSample struct {
	Deltas map[int]TrafficDelta

	owner           *StatsClient
	generation      uint64
	revision        uint64
	replaceBaseline bool
	observed        map[string]int64
}

func NewStatsClient(address string, dialTimeout time.Duration, maxBytes int64) (*StatsClient, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid stats address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("stats API must use a loopback IP")
	}
	if dialTimeout <= 0 {
		dialTimeout = 5 * time.Second
	}
	if maxBytes < 1<<20 || maxBytes > 64<<20 {
		return nil, errors.New("stats response limit must be between 1 MiB and 64 MiB")
	}
	return &StatsClient{address: address, dialTimeout: dialTimeout, maxBytes: int(maxBytes)}, nil
}

func (c *StatsClient) Poll(ctx context.Context, generation uint64, users map[string]int) (*TrafficSample, error) {
	conn, err := c.connection(ctx)
	if err != nil {
		return nil, err
	}

	request := &queryStatsRequest{Pattern: "user>>>", Reset_: false}
	response := new(queryStatsResponse)
	callCtx, callCancel := context.WithTimeout(ctx, c.dialTimeout)
	defer callCancel()
	if err := conn.Invoke(callCtx, queryStatsMethod, request, response); err != nil {
		c.invalidate(conn)
		return nil, fmt.Errorf("query stats API: %w", err)
	}

	// Collapse any duplicate rows before comparing with the previous
	// cumulative observation. The real services emit one row per name, but
	// treating duplicates deterministically avoids overcounting malformed
	// responses.
	observedCapacity := len(response.Stat)
	if userStats := len(users) * 2; observedCapacity > userStats {
		observedCapacity = userStats
	}
	observed := make(map[string]int64, observedCapacity)
	for _, stat := range response.Stat {
		if stat == nil {
			continue
		}
		name, _, ok := parseUserStatName(stat.Name)
		if !ok || stat.Value < 0 {
			continue
		}
		if _, known := users[name]; !known {
			continue
		}
		if previous, exists := observed[stat.Name]; !exists || stat.Value > previous {
			observed[stat.Name] = stat.Value
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	sameGeneration := c.haveBaseline && c.baselineGeneration == generation

	result := make(map[int]TrafficDelta, min(len(observed)/2, 1024))
	for statName, current := range observed {
		name, direction, _ := parseUserStatName(statName)
		uid := users[name]
		previous := int64(0)
		if sameGeneration {
			previous = c.baselines[statName]
		}
		difference := current
		if current >= previous {
			difference = current - previous
		}
		// current < previous means the engine-side counter was reset without
		// an observed generation transition (for example, process recovery).
		// Count the new cumulative value from zero in that case.
		if difference == 0 {
			continue
		}
		delta := result[uid]
		if direction == "uplink" {
			delta.Upload = saturatingAddInt64(delta.Upload, difference)
		} else {
			delta.Download = saturatingAddInt64(delta.Download, difference)
		}
		result[uid] = delta
	}
	return &TrafficSample{
		Deltas:          result,
		owner:           c,
		generation:      generation,
		revision:        c.baselineRevision,
		replaceBaseline: !sameGeneration,
		observed:        observed,
	}, nil
}

// Commit advances the cumulative baseline for sample. It returns false when
// sample belongs to another client or an intervening sample was committed.
// This makes accidental out-of-order commits fail closed instead of silently
// dropping traffic.
func (c *StatsClient) Commit(sample *TrafficSample) bool {
	if sample == nil || sample.owner != c {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if sample.revision != c.baselineRevision {
		return false
	}
	if sample.replaceBaseline {
		c.baselines = sample.observed
	} else {
		if c.baselines == nil {
			c.baselines = make(map[string]int64, len(sample.observed))
		}
		for name, value := range sample.observed {
			c.baselines[name] = value
		}
	}
	c.baselineGeneration = sample.generation
	c.haveBaseline = true
	c.baselineRevision++
	sample.owner = nil
	sample.observed = nil
	return true
}

func (c *StatsClient) connection(ctx context.Context) (*grpc.ClientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn, nil
	}
	dialCtx, cancel := context.WithTimeout(ctx, c.dialTimeout)
	defer cancel()
	conn, err := grpc.DialContext(dialCtx, c.address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(c.maxBytes)),
	)
	if err != nil {
		return nil, fmt.Errorf("connect stats API: %w", err)
	}
	c.conn = conn
	return conn, nil
}

func (c *StatsClient) invalidate(conn *grpc.ClientConn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == conn {
		_ = c.conn.Close()
		c.conn = nil
	}
}

func (c *StatsClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

func parseUserStatName(value string) (user, direction string, ok bool) {
	const prefix = "user>>>"
	if !strings.HasPrefix(value, prefix) {
		return "", "", false
	}
	remainder := value[len(prefix):]
	separator := strings.Index(remainder, ">>>")
	if separator <= 0 {
		return "", "", false
	}
	user = remainder[:separator]
	suffix := remainder[separator+3:]
	switch suffix {
	case "traffic>>>uplink":
		direction = "uplink"
	case "traffic>>>downlink":
		direction = "downlink"
	default:
		return "", "", false
	}
	return user, direction, true
}

func saturatingAddInt64(a, b int64) int64 {
	if b > 0 && a > int64(^uint64(0)>>1)-b {
		return int64(^uint64(0) >> 1)
	}
	return a + b
}

func ParseUIDUserName(value string) (int, bool) {
	if !strings.HasPrefix(value, "uid-") {
		return 0, false
	}
	id, err := strconv.Atoi(strings.TrimPrefix(value, "uid-"))
	return id, err == nil && id > 0
}
