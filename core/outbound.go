package core

import (
	"fmt"

	"encoding/json"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// build default freedom outbund
func buildDefaultOutbound() (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "freedom"
	outboundDetourConfig.Tag = "Default"
	//sendthrough := "origin"
	//outboundDetourConfig.SendThrough = &sendthrough

	proxySetting := &conf.FreedomConfig{
		// Keep every connection on the same Vietnamese VPS IPv4 egress. A
		// configured-but-unusable IPv6 route otherwise makes applications that
		// prefer QUIC fail intermittently and can expose a different geo region.
		DomainStrategy: "UseIPv4",
		FinalRules:     privateDestinationFinalRules(),
	}
	var setting json.RawMessage
	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy config error: %s", err)
	}
	outboundDetourConfig.Settings = &setting
	return outboundDetourConfig.Build()
}

// privateDestinationFinalRules applies to every inbound protocol, including
// TUIC and AnyTLS. The upstream Freedom fallback currently protects only a
// fixed list of inbound names, so relying on it would let authenticated users
// reach loopback, RFC1918/link-local networks and cloud metadata endpoints.
// Freedom resolves domain destinations before applying finalRules, which also
// closes DNS-rebinding/hostnames that resolve to a private address.
func privateDestinationFinalRules() []*conf.FreedomFinalRuleConfig {
	// Keep this list self-contained instead of relying on geoip.dat. ZNode must
	// still start fail-closed when geodata has not been downloaded yet (for
	// example during first boot or in an isolated recovery environment). This
	// mirrors Xray's built-in private matcher.
	privateNetworks := conf.StringList{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.88.99.0/24",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/3",
		"::/127",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8",
	}
	return []*conf.FreedomFinalRuleConfig{{
		Action: "block",
		IP:     &privateNetworks,
	}}
}

func hardenFreedomOutbound(outbound *conf.OutboundDetourConfig) error {
	if outbound == nil {
		return nil
	}
	protocol := outbound.Protocol
	if protocol != "freedom" && protocol != "direct" {
		return nil
	}

	settings := &conf.FreedomConfig{}
	if outbound.Settings != nil && len(*outbound.Settings) > 0 {
		if err := json.Unmarshal(*outbound.Settings, settings); err != nil {
			return fmt.Errorf("decode freedom settings: %w", err)
		}
	}
	settings.FinalRules = append(privateDestinationFinalRules(), settings.FinalRules...)
	raw, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("encode hardened freedom settings: %w", err)
	}
	outbound.Settings = (*json.RawMessage)(&raw)
	return nil
}

// build block outbund
func buildBlockOutbound() (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "blackhole"
	outboundDetourConfig.Tag = "block"
	return outboundDetourConfig.Build()
}

// build dns outbound
func buildDnsOutbound() (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "dns"
	outboundDetourConfig.Tag = "dns_out"
	return outboundDetourConfig.Build()
}
