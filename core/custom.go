package core

import (
	"encoding/json"
	"fmt"
	"strings"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/router"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func hasOutboundWithTag(list []*core.OutboundHandlerConfig, tag string) bool {
	for _, o := range list {
		if o != nil && o.Tag == tag {
			return true
		}
	}
	return false
}

func resolveRouteOutbound(value *string, existing []*core.OutboundHandlerConfig) (string, *core.OutboundHandlerConfig, error) {
	if value == nil || strings.TrimSpace(*value) == "" {
		return "", nil, fmt.Errorf("route outbound is missing")
	}
	outbound := &coreConf.OutboundDetourConfig{}
	if err := json.Unmarshal([]byte(*value), outbound); err != nil {
		return "", nil, fmt.Errorf("decode route outbound: %w", err)
	}
	if strings.TrimSpace(outbound.Tag) == "" {
		return "", nil, fmt.Errorf("route outbound tag is missing")
	}
	if err := hardenFreedomOutbound(outbound); err != nil {
		return "", nil, fmt.Errorf("secure route outbound: %w", err)
	}
	if err := applyXHTTPStreamDefaults(outbound.StreamSetting); err != nil {
		return "", nil, fmt.Errorf("apply xhttp outbound defaults: %w", err)
	}
	if hasOutboundWithTag(existing, outbound.Tag) {
		return outbound.Tag, nil, nil
	}
	built, err := outbound.Build()
	if err != nil {
		return "", nil, fmt.Errorf("build route outbound %q: %w", outbound.Tag, err)
	}
	return outbound.Tag, built, nil
}

func GetCustomConfig(infos []*panel.NodeInfo) (*dns.Config, []*core.OutboundHandlerConfig, *router.Config, error) {
	// Prefer the stable IPv4 egress used by the panel's advertised VPS
	// address. Merely having a public IPv6 address on an interface does not
	// prove that the VPS has a working IPv6 route; broken/black-holed IPv6 is a
	// common cause of intermittent QUIC failures in TikTok and Meta apps.
	queryStrategy := "UseIPv4"
	coreDnsConfig := &coreConf.DNSConfig{
		Servers: []*coreConf.NameServerConfig{
			{
				Address: &coreConf.Address{
					Address: xnet.ParseAddress("localhost"),
				},
			},
		},
		QueryStrategy: queryStrategy,
	}
	//outbound
	defaultoutbound, err := buildDefaultOutbound()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("build default outbound: %w", err)
	}
	coreOutboundConfig := append([]*core.OutboundHandlerConfig{}, defaultoutbound)
	block, err := buildBlockOutbound()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("build block outbound: %w", err)
	}
	coreOutboundConfig = append(coreOutboundConfig, block)
	dnsOutbound, err := buildDnsOutbound()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("build DNS outbound: %w", err)
	}
	coreOutboundConfig = append(coreOutboundConfig, dnsOutbound)

	//route
	domainStrategy := "AsIs"
	dnsRule, _ := json.Marshal(map[string]interface{}{
		"port":        "53",
		"network":     "udp",
		"outboundTag": "dns_out",
	})
	coreRouterConfig := &coreConf.RouterConfig{
		RuleList:       []json.RawMessage{dnsRule},
		DomainStrategy: &domainStrategy,
	}

	for _, info := range infos {
		if info == nil || info.Common == nil {
			return nil, nil, nil, fmt.Errorf("custom routing received an empty node configuration")
		}
		if len(info.Common.Routes) == 0 {
			continue
		}
		for _, route := range info.Common.Routes {
			switch route.Action {
			case "dns":
				if route.ActionValue == nil {
					return nil, nil, nil, fmt.Errorf("node %d route %d: DNS server is missing", info.Id, route.Id)
				}
				server := &coreConf.NameServerConfig{
					Address: &coreConf.Address{
						Address: xnet.ParseAddress(*route.ActionValue),
					},
				}
				if len(route.Match) != 0 {
					server.Domains = route.Match
					server.SkipFallback = true
				}
				coreDnsConfig.Servers = append(coreDnsConfig.Servers, server)
			case "block":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"domain":      route.Match,
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "block_ip":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"ip":          route.Match,
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "block_port":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"port":        strings.Join(route.Match, ","),
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "protocol":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"protocol":    route.Match,
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "route":
				outboundTag, customOutbound, err := resolveRouteOutbound(route.ActionValue, coreOutboundConfig)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("node %d route %d: %w", info.Id, route.Id, err)
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"domain":      route.Match,
					"outboundTag": outboundTag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("node %d route %d: marshal domain route: %w", info.Id, route.Id, err)
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if customOutbound != nil {
					coreOutboundConfig = append(coreOutboundConfig, customOutbound)
				}
			case "route_ip":
				outboundTag, customOutbound, err := resolveRouteOutbound(route.ActionValue, coreOutboundConfig)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("node %d route %d: %w", info.Id, route.Id, err)
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"ip":          route.Match,
					"outboundTag": outboundTag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("node %d route %d: marshal IP route: %w", info.Id, route.Id, err)
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if customOutbound != nil {
					coreOutboundConfig = append(coreOutboundConfig, customOutbound)
				}
			case "default_out":
				outboundTag, customOutbound, err := resolveRouteOutbound(route.ActionValue, coreOutboundConfig)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("node %d route %d: %w", info.Id, route.Id, err)
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"network":     "tcp,udp",
					"outboundTag": outboundTag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("node %d route %d: marshal default route: %w", info.Id, route.Id, err)
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if customOutbound != nil {
					coreOutboundConfig = append(coreOutboundConfig, customOutbound)
				}
			default:
				return nil, nil, nil, fmt.Errorf("node %d route %d: unsupported action %q", info.Id, route.Id, route.Action)
			}
		}
	}
	DnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		return nil, nil, nil, err
	}
	RouterConfig, err := coreRouterConfig.Build()
	if err != nil {
		return nil, nil, nil, err
	}
	return DnsConfig, coreOutboundConfig, RouterConfig, nil
}
