package core

import (
	"encoding/json"
	"testing"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/xtls/xray-core/app/dns"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport/internet"
)

func TestDefaultEgressKeepsDNSAndFreedomOnIPv4(t *testing.T) {
	dnsConfig, outbounds, _, err := GetCustomConfig([]*panel.NodeInfo{{
		Id: 1, Tag: "node", Common: &panel.CommonNode{},
	}})
	if err != nil {
		t.Fatalf("build custom config: %v", err)
	}
	if dnsConfig.GetQueryStrategy() != dns.QueryStrategy_USE_IP4 {
		t.Fatalf("DNS query strategy = %s, want IPv4", dnsConfig.GetQueryStrategy())
	}
	if len(outbounds) == 0 || outbounds[0].ProxySettings == nil {
		t.Fatal("default freedom outbound is missing")
	}
	instance, err := outbounds[0].ProxySettings.GetInstance()
	if err != nil {
		t.Fatalf("decode freedom outbound: %v", err)
	}
	settings, ok := instance.(*freedom.Config)
	if !ok {
		t.Fatalf("default outbound settings type = %T", instance)
	}
	if settings.GetDomainStrategy() != internet.DomainStrategy_USE_IP4 {
		t.Fatalf("freedom domain strategy = %s, want IPv4", settings.GetDomainStrategy())
	}
}

func TestCustomRoutingRejectsMalformedOrUnsupportedRules(t *testing.T) {
	malformed := "{"
	for name, infos := range map[string][]*panel.NodeInfo{
		"nil node":       {nil},
		"missing common": {{Id: 1}},
		"malformed outbound": {{
			Id: 1, Tag: "node", Common: &panel.CommonNode{Routes: []panel.Route{{
				Id: 2, Action: "route", Match: []string{"example.com"}, ActionValue: &malformed,
			}}},
		}},
		"unknown action": {{
			Id: 1, Tag: "node", Common: &panel.CommonNode{Routes: []panel.Route{{
				Id: 3, Action: "future_fail_open_action",
			}}},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := GetCustomConfig(infos); err == nil {
				t.Fatal("unsafe routing configuration was silently ignored")
			}
		})
	}
}

func TestEveryFreedomOutboundBlocksPrivateDestinationsFirst(t *testing.T) {
	raw := json.RawMessage(`{"domainStrategy":"UseIPv4","finalRules":[{"action":"allow"}]}`)
	outbound := &coreConf.OutboundDetourConfig{
		Protocol: "freedom",
		Tag:      "custom-direct",
		Settings: &raw,
	}
	if err := hardenFreedomOutbound(outbound); err != nil {
		t.Fatalf("harden freedom outbound: %v", err)
	}

	var settings struct {
		FinalRules []struct {
			Action string   `json:"action"`
			IP     []string `json:"ip"`
		} `json:"finalRules"`
	}
	if err := json.Unmarshal(*outbound.Settings, &settings); err != nil {
		t.Fatalf("decode hardened settings: %v", err)
	}
	if len(settings.FinalRules) < 2 || settings.FinalRules[0].Action != "block" {
		t.Fatalf("private block is not the first final rule: %#v", settings.FinalRules)
	}
	want := map[string]bool{
		"10.0.0.0/8":     false,
		"127.0.0.0/8":    false,
		"169.254.0.0/16": false,
		"192.168.0.0/16": false,
		"::/127":         false,
		"fc00::/7":       false,
		"fe80::/10":      false,
	}
	for _, cidr := range settings.FinalRules[0].IP {
		if _, ok := want[cidr]; ok {
			want[cidr] = true
		}
	}
	for cidr, found := range want {
		if !found {
			t.Fatalf("private block is missing %s: %#v", cidr, settings.FinalRules[0].IP)
		}
	}
}
