package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Duyvj/v3node/internal/config"
	"github.com/Duyvj/v3node/internal/engine"
	"github.com/Duyvj/v3node/internal/model"
)

type CompiledState struct {
	Node                 engine.NodeSpec
	Users                []engine.UserSpec
	PullInterval         time.Duration
	PushInterval         time.Duration
	DeviceOnlineMinBytes int64
	NodeReportMinBytes   int64
}

func CompileState(node model.NodeConfig, users []model.User, local config.Config) (CompiledState, error) {
	if err := node.Validate(); err != nil {
		return CompiledState{}, err
	}
	if net.ParseIP(node.ListenIP) == nil && node.ListenIP != "" {
		return CompiledState{}, fmt.Errorf("listen_ip %q is not an IP address", node.ListenIP)
	}
	if len(node.NetworkSettings) > 0 {
		var object map[string]any
		if err := json.Unmarshal(node.NetworkSettings, &object); err != nil {
			return CompiledState{}, fmt.Errorf("network_settings must be a JSON object: %w", err)
		}
	}
	for _, trusted := range node.TrustedXForwardedFor {
		if net.ParseIP(trusted) == nil {
			if _, err := netip.ParsePrefix(trusted); err != nil {
				return CompiledState{}, fmt.Errorf("trusted_x_forwarded_for contains invalid IP/CIDR %q", trusted)
			}
		}
	}

	spec := engine.NodeSpec{
		Protocol:             string(node.Protocol),
		Listen:               node.ListenIP,
		Port:                 uint16(node.ServerPort),
		Flow:                 node.Flow,
		Cipher:               node.Cipher,
		ServerKey:            node.ServerKey,
		Transport:            strings.ToLower(node.Network),
		TransportSettings:    append(json.RawMessage(nil), node.NetworkSettings...),
		TrustedXForwardedFor: append([]string(nil), node.TrustedXForwardedFor...),
		Encryption:           node.Encryption,
		CongestionControl:    node.CongestionControl,
		ZeroRTT:              node.ZeroRTTHandshake,
		PaddingScheme:        append([]string(nil), node.PaddingScheme...),
		UpMbps:               node.UpMbps,
		DownMbps:             node.DownMbps,
		Obfs:                 node.Obfs,
		ObfsPassword:         node.ObfsPassword,
		IgnoreClientBW:       node.IgnoreClientBandwidth,
	}
	if spec.Transport == "" {
		spec.Transport = "tcp"
	}
	encryptionSettings, err := json.Marshal(node.EncryptionSettings)
	if err != nil {
		return CompiledState{}, fmt.Errorf("encode encryption settings: %w", err)
	}
	spec.EncryptionSettings = encryptionSettings

	tls, err := compileTLS(node, local.Panel.NodeID)
	if err != nil {
		return CompiledState{}, err
	}
	spec.TLS = tls
	if (node.Protocol == model.ProtocolHysteria2 || node.Protocol == model.ProtocolTUIC || node.Protocol == model.ProtocolAnyTLS) && tls.Mode == "none" {
		return CompiledState{}, fmt.Errorf("protocol %s requires TLS", node.Protocol)
	}

	spec.Routes = make([]engine.RouteSpec, 0, len(node.Routes))
	for _, route := range node.Routes {
		if len(route.Match) > 100_000 {
			return CompiledState{}, fmt.Errorf("route %d has too many match entries", route.ID)
		}
		actionValue := ""
		if route.ActionValue != nil {
			actionValue = *route.ActionValue
		}
		spec.Routes = append(spec.Routes, engine.RouteSpec{
			ID:          route.ID,
			Match:       append([]string(nil), route.Match...),
			Action:      route.Action,
			ActionValue: actionValue,
		})
	}

	compiledUsers := make([]engine.UserSpec, 0, len(users))
	for _, user := range users {
		if err := user.Validate(); err != nil {
			return CompiledState{}, fmt.Errorf("user %d: %w", user.ID, err)
		}
		if user.SpeedLimit > 0 {
			return CompiledState{}, fmt.Errorf("user %d requests speed_limit, which this release cannot enforce safely", user.ID)
		}
		if user.DeviceLimit > local.Runtime.MaxIPsPerUser {
			return CompiledState{}, fmt.Errorf("user %d device_limit %d exceeds local max_ips_per_user %d", user.ID, user.DeviceLimit, local.Runtime.MaxIPsPerUser)
		}
		compiledUsers = append(compiledUsers, engine.UserSpec{
			ID:          user.ID,
			Credential:  user.UUID,
			SpeedLimit:  user.SpeedLimit,
			DeviceLimit: user.DeviceLimit,
		})
	}
	sort.Slice(compiledUsers, func(i, j int) bool { return compiledUsers[i].ID < compiledUsers[j].ID })
	if err := engine.ValidateSpec(spec, compiledUsers); err != nil {
		return CompiledState{}, err
	}

	base := node.BaseConfig
	pull := 30 * time.Second
	push := 30 * time.Second
	var deviceThreshold, reportThreshold int64
	if base != nil {
		pull = base.PullInterval.DurationClamped(local.Runtime.PullIntervalMin.Duration, local.Runtime.PullIntervalMax.Duration)
		push = base.PushInterval.DurationClamped(local.Runtime.PushIntervalMin.Duration, local.Runtime.PushIntervalMax.Duration)
		deviceThreshold = decimalKilobytes(base.DeviceOnlineMinTraffic)
		reportThreshold = decimalKilobytes(base.NodeReportMinTraffic)
	}
	return CompiledState{
		Node:                 spec,
		Users:                compiledUsers,
		PullInterval:         pull,
		PushInterval:         push,
		DeviceOnlineMinBytes: deviceThreshold,
		NodeReportMinBytes:   reportThreshold,
	}, nil
}

// ValidateBackendPolicies rejects policy combinations that the selected stock
// data plane cannot enforce. Limits must fail closed instead of being accepted
// and silently ignored.
func ValidateBackendPolicies(backend string, users []engine.UserSpec) error {
	if backend != "xray" {
		return nil
	}
	for _, user := range users {
		if user.DeviceLimit > 0 {
			return fmt.Errorf("user %d requests device_limit, which the stock Xray backend cannot enforce", user.ID)
		}
	}
	return nil
}

func compileTLS(node model.NodeConfig, nodeID int64) (engine.TLSSpec, error) {
	settings := node.TLSSettings
	result := engine.TLSSpec{
		Mode:             "none",
		ServerName:       settings.ServerName,
		ServerNames:      append([]string(nil), settings.EffectiveServerNames()...),
		ShortIDs:         append([]string(nil), settings.EffectiveShortIDs()...),
		PrivateKey:       settings.PrivateKey,
		MLDSA65Seed:      settings.MLDSA65Seed,
		Xver:             uint64(settings.Xver),
		CertificateFile:  settings.CertFile,
		KeyFile:          settings.KeyFile,
		RejectUnknownSNI: parsePanelBool(settings.RejectUnknownSNI),
	}
	if result.ServerName == "" {
		result.ServerName = node.ServerName
	}
	if result.ServerName == "" && len(result.ServerNames) > 0 {
		result.ServerName = result.ServerNames[0]
	}
	switch node.TLS {
	case model.SecurityNone:
		return result, nil
	case model.SecurityTLS:
		result.Mode = "tls"
		switch strings.ToLower(strings.TrimSpace(settings.CertMode)) {
		case "", "none", "file":
		case "dns", "http", "self":
			return engine.TLSSpec{}, fmt.Errorf("automatic certificate mode %q is not supported; provision certificate files and use cert_mode=file", settings.CertMode)
		default:
			return engine.TLSSpec{}, fmt.Errorf("unsupported certificate mode %q", settings.CertMode)
		}
		// Use deterministic per-node paths when the panel omits explicit
		// filenames. Certificate issuance remains operator-managed.
		if result.CertificateFile == "" {
			result.CertificateFile = path.Join("/etc/v3node", fmt.Sprintf("%s%d.cer", node.Protocol, nodeID))
		}
		if result.KeyFile == "" {
			result.KeyFile = path.Join("/etc/v3node", fmt.Sprintf("%s%d.key", node.Protocol, nodeID))
		}
		if !isAbsoluteTargetPath(result.CertificateFile) || !isAbsoluteTargetPath(result.KeyFile) {
			return engine.TLSSpec{}, errors.New("panel TLS certificate and key paths must be absolute")
		}
		return result, nil
	case model.SecurityReality:
		result.Mode = "reality"
		if result.Xver > 2 {
			return engine.TLSSpec{}, errors.New("Reality xver must be 0, 1, or 2")
		}
		destination := settings.Dest
		if strings.TrimSpace(destination) == "" {
			destination = result.ServerName
		}
		host, port, err := parseRealityDestination(destination, settings.ServerPort)
		if err != nil {
			return engine.TLSSpec{}, err
		}
		result.DestinationHost = host
		result.DestinationPort = port
		return result, nil
	default:
		return engine.TLSSpec{}, fmt.Errorf("unknown TLS mode %d", node.TLS)
	}
}

func isAbsoluteTargetPath(value string) bool {
	return filepath.IsAbs(value) || strings.HasPrefix(value, "/")
}

func parseRealityDestination(destination, fallbackPort string) (string, uint16, error) {
	destination = strings.TrimSpace(destination)
	if destination == "" {
		return "", 0, errors.New("Reality destination is empty")
	}
	if host, portText, err := net.SplitHostPort(destination); err == nil {
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, errors.New("Reality destination has an invalid port")
		}
		return host, uint16(port), nil
	}
	port := 443
	if fallbackPort != "" {
		parsed, err := strconv.Atoi(fallbackPort)
		if err != nil || parsed < 1 || parsed > 65535 {
			return "", 0, errors.New("Reality server_port is invalid")
		}
		port = parsed
	}
	return strings.Trim(destination, "[]"), uint16(port), nil
}

func parsePanelBool(value string) bool {
	parsed, _ := strconv.ParseBool(strings.TrimSpace(value))
	if parsed {
		return true
	}
	return value == "1"
}

func decimalKilobytes(value int) int64 {
	if value <= 0 {
		return 0
	}
	if int64(value) > math.MaxInt64/1000 {
		return math.MaxInt64
	}
	return int64(value) * 1000
}
