package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	maxNodes = 16
)

var nodeNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// NodeEntry is the compact multi-node panel descriptor. It intentionally
// contains only panel identity and optional per-node local overrides; engine,
// runtime and network policy remain shared defaults in Config. The parser
// accepts both v3node's lower-case spelling and the original v2node spelling
// (ApiHost/NodeID/ApiKey/Timeout) so an existing Nodes array can be migrated
// without hand-editing every entry.
type NodeEntry struct {
	Name        string   `json:"name,omitempty"`
	APIHost     string   `json:"api_host,omitempty"`
	NodeID      int64    `json:"node_id"`
	APIKey      string   `json:"api_key,omitempty"`
	TokenFile   string   `json:"token_file,omitempty"`
	AllowHTTP   bool     `json:"allow_insecure_http,omitempty"`
	Timeout     Duration `json:"timeout,omitempty"`
	StateDir    string   `json:"state_dir,omitempty"`
	StatsListen string   `json:"stats_listen,omitempty"`
	ClashListen string   `json:"clash_listen,omitempty"`
}

// UnmarshalJSON accepts the v2node Nodes contract as well as the native
// lower-case v3node spelling. Unknown fields are rejected just like the rest
// of the local configuration, despite this type using a compatibility parser.
func (n *NodeEntry) UnmarshalJSON(data []byte) error {
	if n == nil {
		return errors.New("config.NodeEntry: nil receiver")
	}
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&fields); err != nil {
		return fmt.Errorf("node entry must be an object: %w", err)
	}
	if fields == nil {
		return errors.New("node entry must be an object")
	}
	known := map[string]struct{}{}
	for _, aliases := range [][]string{
		{"name", "Name"},
		{"api_host", "ApiHost", "APIHost", "url", "URL"},
		{"node_id", "NodeID", "nodeId"},
		{"api_key", "ApiKey", "APIKey", "token", "Token"},
		{"token_file", "TokenFile"},
		{"allow_insecure_http", "AllowInsecureHTTP"},
		{"timeout", "Timeout"},
		{"state_dir", "StateDir"},
		{"stats_listen", "StatsListen"},
		{"clash_listen", "ClashListen"},
	} {
		for _, alias := range aliases {
			known[alias] = struct{}{}
		}
	}
	for key := range fields {
		if _, ok := known[key]; !ok {
			return fmt.Errorf("node entry contains unknown field %q", key)
		}
	}
	readString := func(aliases ...string) (string, bool, error) {
		var found string
		var result string
		for _, alias := range aliases {
			value, ok := fields[alias]
			if !ok {
				continue
			}
			if found != "" {
				return "", false, fmt.Errorf("node entry contains conflicting fields %q and %q", found, alias)
			}
			found = alias
			if err := json.Unmarshal(value, &result); err != nil {
				return "", false, fmt.Errorf("node entry field %q must be a string", alias)
			}
		}
		return result, found != "", nil
	}
	readInt := func(aliases ...string) (int64, bool, error) {
		var found string
		var result int64
		for _, alias := range aliases {
			value, ok := fields[alias]
			if !ok {
				continue
			}
			if found != "" {
				return 0, false, fmt.Errorf("node entry contains conflicting fields %q and %q", found, alias)
			}
			found = alias
			if err := json.Unmarshal(value, &result); err != nil {
				var text string
				if string(value) == "null" || json.Unmarshal(value, &text) != nil {
					return 0, false, fmt.Errorf("node entry field %q must be an integer", alias)
				}
				parsed, parseErr := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
				if parseErr != nil {
					return 0, false, fmt.Errorf("node entry field %q must be an integer", alias)
				}
				result = parsed
			}
		}
		return result, found != "", nil
	}
	readBool := func(aliases ...string) (bool, bool, error) {
		var found string
		for _, alias := range aliases {
			value, ok := fields[alias]
			if !ok {
				continue
			}
			if found != "" {
				return false, false, fmt.Errorf("node entry contains conflicting fields %q and %q", found, alias)
			}
			found = alias
			var result bool
			if err := json.Unmarshal(value, &result); err != nil {
				return false, false, fmt.Errorf("node entry field %q must be a boolean", alias)
			}
			return result, true, nil
		}
		return false, false, nil
	}
	readDuration := func(aliases ...string) (Duration, bool, error) {
		var found string
		var result Duration
		for _, alias := range aliases {
			value, ok := fields[alias]
			if !ok {
				continue
			}
			if found != "" {
				return Duration{}, false, fmt.Errorf("node entry contains conflicting fields %q and %q", found, alias)
			}
			found = alias
			if err := json.Unmarshal(value, &result); err != nil {
				return Duration{}, false, fmt.Errorf("node entry field %q is invalid: %w", alias, err)
			}
		}
		return result, found != "", nil
	}
	var err error
	if n.Name, _, err = readString("name", "Name"); err != nil {
		return err
	}
	if n.APIHost, _, err = readString("api_host", "ApiHost", "APIHost", "url", "URL"); err != nil {
		return err
	}
	if n.NodeID, _, err = readInt("node_id", "NodeID", "nodeId"); err != nil {
		return err
	}
	if n.APIKey, _, err = readString("api_key", "ApiKey", "APIKey", "token", "Token"); err != nil {
		return err
	}
	if n.TokenFile, _, err = readString("token_file", "TokenFile"); err != nil {
		return err
	}
	if n.AllowHTTP, _, err = readBool("allow_insecure_http", "AllowInsecureHTTP"); err != nil {
		return err
	}
	if n.Timeout, _, err = readDuration("timeout", "Timeout"); err != nil {
		return err
	}
	if n.StateDir, _, err = readString("state_dir", "StateDir"); err != nil {
		return err
	}
	if n.StatsListen, _, err = readString("stats_listen", "StatsListen"); err != nil {
		return err
	}
	if n.ClashListen, _, err = readString("clash_listen", "ClashListen"); err != nil {
		return err
	}
	return nil
}

// NodeConfigs expands a legacy singleton or a multi-node descriptor list
// into isolated worker configurations. The returned configs are fully local:
// each has its own state directory and loopback management ports.
func (c Config) NodeConfigs() ([]Config, error) {
	if len(c.Nodes) == 0 {
		return []Config{c}, nil
	}
	if len(c.Nodes) > maxNodes {
		return nil, fmt.Errorf("nodes exceeds the maximum of %d", maxNodes)
	}
	result := make([]Config, 0, len(c.Nodes))
	usedKeys := make(map[string]struct{}, len(c.Nodes))
	usedIdentities := make(map[string]struct{}, len(c.Nodes))
	usedState := make(map[string]struct{}, len(c.Nodes))
	usedManagement := make(map[int]struct{}, len(c.Nodes)*2)
	for index, entry := range c.Nodes {
		if entry.APIHost == "" {
			return nil, fmt.Errorf("nodes[%d] api_host is required", index)
		}
		if entry.NodeID <= 0 {
			return nil, fmt.Errorf("nodes[%d] node_id must be positive", index)
		}
		identity := canonicalPanelURL(entry.APIHost) + "\x00" + strconv.FormatInt(entry.NodeID, 10)
		if _, exists := usedIdentities[identity]; exists {
			return nil, fmt.Errorf("nodes contains duplicate panel identity for node %d", entry.NodeID)
		}
		usedIdentities[identity] = struct{}{}
		key := nodeInstanceKey(entry)
		if entry.Name != "" {
			if !nodeNamePattern.MatchString(entry.Name) {
				return nil, fmt.Errorf("nodes[%d] name must match %s", index, nodeNamePattern.String())
			}
			key = entry.Name
		}
		if _, exists := usedKeys[key]; exists {
			return nil, fmt.Errorf("nodes contains duplicate instance name %q", key)
		}
		usedKeys[key] = struct{}{}
		stateDir := entry.StateDir
		if stateDir == "" {
			stateDir = targetPathJoin(c.Engine.StateDir, "nodes", key)
		}
		stateDir = cleanTargetPath(stateDir)
		if _, exists := usedState[stateDir]; exists {
			return nil, fmt.Errorf("nodes contains duplicate state directory %q", stateDir)
		}
		usedState[stateDir] = struct{}{}
		statsListen := entry.StatsListen
		if statsListen == "" {
			var offsetErr error
			statsListen, offsetErr = stableLoopbackAddress(c.Engine.StatsListen, key, 0)
			if offsetErr != nil {
				return nil, fmt.Errorf("nodes[%d] stats management port: %w", index, offsetErr)
			}
		}
		clashListen := entry.ClashListen
		if clashListen == "" {
			var offsetErr error
			clashListen, offsetErr = stableLoopbackAddress(c.Engine.ClashListen, key, 1)
			if offsetErr != nil {
				return nil, fmt.Errorf("nodes[%d] connections management port: %w", index, offsetErr)
			}
		}
		for _, address := range []string{statsListen, clashListen} {
			_, portText, err := net.SplitHostPort(address)
			if err != nil {
				continue
			}
			port, _ := strconv.Atoi(portText)
			if _, exists := usedManagement[port]; exists {
				return nil, fmt.Errorf("nodes contains duplicate management port %d", port)
			}
			usedManagement[port] = struct{}{}
		}
		panel := c.Panel
		panel.URL = strings.TrimRight(strings.TrimSpace(entry.APIHost), "/")
		panel.NodeID = entry.NodeID
		panel.Token = entry.APIKey
		panel.TokenFile = entry.TokenFile
		panel.AllowInsecureHTTP = entry.AllowHTTP
		worker := c
		worker.Panel = panel
		worker.Nodes = nil
		worker.Instance = key
		worker.Engine.StateDir = stateDir
		worker.Engine.StatsListen = statsListen
		worker.Engine.ClashListen = clashListen
		if entry.Timeout.Duration > 0 {
			worker.Runtime.HTTPTimeout = entry.Timeout
		}
		// NodeEntry tokens are resolved by Config.Load. Keep the expanded
		// worker independent of any shared token file after this point.
		if panel.Token != "" {
			worker.Panel.TokenFile = ""
		}
		result = append(result, worker)
	}
	return result, nil
}

// Instance is an internal stable worker key and is never serialized.
// It is populated by NodeConfigs for logging and state diagnostics.
func (c *Config) setInstance(value string) { c.Instance = value }

func nodeInstanceKey(entry NodeEntry) string {
	canonical := canonicalPanelURL(entry.APIHost)
	digest := sha256.Sum256([]byte(canonical + "\x00" + strconv.FormatInt(entry.NodeID, 10)))
	suffix := hex.EncodeToString(digest[:8])
	key := fmt.Sprintf("node-%d-%s", entry.NodeID, suffix)
	if len(key) <= 32 {
		return key
	}
	// Decimal int64 plus a 64-bit identity suffix can exceed the explicit-name
	// limit. Base36 keeps even the largest supported ID within 32 characters.
	return fmt.Sprintf("n-%s-%s", strconv.FormatInt(entry.NodeID, 36), suffix)
}

func canonicalPanelURL(value string) string {
	value = strings.TrimSpace(value)
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.TrimRight(strings.ToLower(value), "/")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host = net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	u.Host = host
	u.Path = strings.TrimRight(path.Clean("/"+strings.TrimSpace(u.EscapedPath())), "/")
	if u.Path == "" {
		u.Path = "/"
	}
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/")
}

func targetPathJoin(base string, elements ...string) string {
	if strings.HasPrefix(base, "/") {
		parts := append([]string{base}, elements...)
		return path.Join(parts...)
	}
	parts := append([]string{base}, elements...)
	return filepath.Join(parts...)
}

func cleanTargetPath(value string) string {
	if strings.HasPrefix(value, "/") {
		return path.Clean(value)
	}
	return filepath.Clean(value)
}

func stableLoopbackAddress(address, key string, lane int) (string, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return address, err
	}
	basePort, err := strconv.Atoi(portText)
	if err != nil || basePort < 1 || basePort > 65535 {
		return address, errors.New("management port is out of range")
	}
	// Management endpoints need to remain bound to an identity after Nodes is
	// reordered. Use a deterministic probe into the available suffix space;
	// NodeConfigs still rejects the exceptionally unlikely collision and asks
	// the operator for an explicit override.
	available := 65536 - basePort
	if available < 2 {
		return address, errors.New("management port leaves no room for multi-node allocation")
	}
	digest := sha256.Sum256([]byte(key))
	slot := (int(digest[0])<<8 | int(digest[1])) % (available / 2)
	port := basePort + slot*2 + lane
	if port > 65535 {
		return address, errors.New("management port allocation is out of range")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func (c Config) validateMulti() error {
	if len(c.Nodes) == 0 || len(c.Nodes) > maxNodes {
		return fmt.Errorf("nodes must contain between 1 and %d entries", maxNodes)
	}
	if c.Panel.URL != "" || c.Panel.NodeID != 0 || c.Panel.Token != "" || c.Panel.TokenFile != "" {
		return errors.New("panel must be omitted when nodes is configured")
	}
	identities := make(map[string]struct{}, len(c.Nodes))
	for _, entry := range c.Nodes {
		identity := canonicalPanelURL(entry.APIHost) + "\x00" + strconv.FormatInt(entry.NodeID, 10)
		if _, exists := identities[identity]; exists {
			return fmt.Errorf("nodes contains duplicate panel identity for node %d", entry.NodeID)
		}
		identities[identity] = struct{}{}
	}
	workers, err := c.NodeConfigs()
	if err != nil {
		return err
	}
	for _, worker := range workers {
		if err := worker.validateSingle(); err != nil {
			return fmt.Errorf("node %s: %w", worker.Instance, err)
		}
	}
	return nil
}

// ResolveNodeTokens loads every descriptor token before validation. This is
// called by Load and keeps token files out of worker goroutines and retries.
func (c *Config) resolveNodeTokens(path string) error {
	for index := range c.Nodes {
		entry := &c.Nodes[index]
		if entry.APIKey != "" && entry.TokenFile != "" {
			return fmt.Errorf("nodes[%d] sets both api_key and token_file", index)
		}
		if entry.TokenFile != "" && !filepath.IsAbs(entry.TokenFile) {
			entry.TokenFile = filepath.Join(filepath.Dir(path), entry.TokenFile)
		}
		if entry.TokenFile != "" {
			data, err := readNodeTokenFile(entry.TokenFile)
			if err != nil {
				return fmt.Errorf("read nodes[%d] token file: %w", index, err)
			}
			entry.APIKey = strings.TrimSpace(string(data))
			entry.TokenFile = ""
			clear(data)
		}
	}
	return nil
}

func readNodeTokenFile(tokenPath string) ([]byte, error) {
	info, err := os.Lstat(tokenPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("token path is not a regular file")
	}
	if info.Size() > maxTokenBytes {
		return nil, errors.New("token file is too large")
	}
	f, err := os.Open(tokenPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxTokenBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxTokenBytes {
		return nil, errors.New("token file is too large")
	}
	return data, nil
}

// NodeName returns the stable worker name, or "default" for legacy configs.
func (c Config) NodeName() string {
	if c.Instance == "" {
		return "default"
	}
	return c.Instance
}
