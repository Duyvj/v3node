package core

import (
	"encoding/json"
	"testing"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/xtls/xray-core/app/proxyman"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func TestUnmarshalNetworkSettingsLegacyArray(t *testing.T) {
	var got coreConf.TCPConfig
	if err := unmarshalNetworkSettings(json.RawMessage(`[{"acceptProxyProtocol":true}]`), &got); err != nil {
		t.Fatalf("decode legacy network settings: %v", err)
	}
}

func TestUnmarshalNetworkSettingsEmptyArray(t *testing.T) {
	var got coreConf.TCPConfig
	if err := unmarshalNetworkSettings(json.RawMessage(`[]`), &got); err != nil {
		t.Fatalf("decode empty network settings: %v", err)
	}
}

func buildSniffingSettings(t *testing.T, routes []panel.Route) *proxyman.SniffingConfig {
	t.Helper()
	inbound, err := buildInbound(&panel.NodeInfo{
		Type:     "shadowsocks",
		Security: panel.None,
		Common: &panel.CommonNode{
			ListenIP:   "0.0.0.0",
			ServerPort: 443,
			Cipher:     "aes-128-gcm",
			Routes:     routes,
		},
	}, "test-inbound")
	if err != nil {
		t.Fatalf("build inbound: %v", err)
	}

	instance, err := inbound.ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatalf("decode receiver settings: %v", err)
	}
	receiver, ok := instance.(*proxyman.ReceiverConfig)
	if !ok {
		t.Fatalf("unexpected receiver settings type %T", instance)
	}
	return receiver.GetSniffingSettings()
}

func TestHysteriaObfsPasswordIsJSONEncoded(t *testing.T) {
	inbound := &coreConf.InboundDetourConfig{}
	password := `"}],"unexpected":true,"password":"still-data`
	err := buildHysteria2(&panel.NodeInfo{Common: &panel.CommonNode{
		Obfs:         "salamander",
		ObfsPassword: password,
	}}, inbound)
	if err != nil {
		t.Fatalf("build hysteria2: %v", err)
	}
	if inbound.StreamSetting == nil || inbound.StreamSetting.FinalMask == nil ||
		len(inbound.StreamSetting.FinalMask.Udp) != 1 ||
		inbound.StreamSetting.FinalMask.Udp[0].Settings == nil {
		t.Fatal("missing hysteria2 obfs settings")
	}

	var settings map[string]string
	if err := json.Unmarshal(*inbound.StreamSetting.FinalMask.Udp[0].Settings, &settings); err != nil {
		t.Fatalf("obfs settings are invalid JSON: %v", err)
	}
	if settings["password"] != password || len(settings) != 1 {
		t.Fatalf("obfs password escaped its JSON field: %#v", settings)
	}
}

func TestBuildInboundDisablesSniffingWithoutDomainRoutes(t *testing.T) {
	sniffing := buildSniffingSettings(t, nil)
	if sniffing == nil {
		t.Fatal("missing sniffing settings")
	}
	if sniffing.GetEnabled() {
		t.Fatal("ordinary nodes must not rewrite Meta or other CDN destinations")
	}
}

func TestBuildInboundUsesRouteOnlySniffingForDomainRoutes(t *testing.T) {
	sniffing := buildSniffingSettings(t, []panel.Route{{
		Action: "route",
		Match:  []string{"domain:tiktok.com"},
	}})
	if sniffing == nil || !sniffing.GetEnabled() {
		t.Fatal("domain routes require content sniffing")
	}
	if !sniffing.GetRouteOnly() {
		t.Fatal("sniffing must not replace the client destination through the VPS resolver")
	}

	overrides := make(map[string]bool, len(sniffing.GetDestinationOverride()))
	for _, protocol := range sniffing.GetDestinationOverride() {
		overrides[protocol] = true
	}
	for _, protocol := range []string{"http", "tls", "quic"} {
		if !overrides[protocol] {
			t.Fatalf("missing %s destination override: %v", protocol, sniffing.GetDestinationOverride())
		}
	}
}

func TestBuildInboundRejectsUnknownSecurityMode(t *testing.T) {
	if _, err := buildInbound(&panel.NodeInfo{
		Type:     "vmess",
		Security: 99,
		Common:   &panel.CommonNode{ListenIP: "127.0.0.1", ServerPort: 443},
	}, "node"); err == nil {
		t.Fatal("unknown transport security mode fell back to plaintext")
	}
}

func TestBuildInboundAcceptsLegacyArrayNetworkSettings(t *testing.T) {
	if _, err := buildInbound(&panel.NodeInfo{
		Type:     "vmess",
		Security: panel.None,
		Common: &panel.CommonNode{
			ListenIP:        "0.0.0.0",
			ServerPort:      443,
			Network:         "tcp",
			NetworkSettings: json.RawMessage(`[{"acceptProxyProtocol":false}]`),
		},
	}, "legacy-array"); err != nil {
		t.Fatalf("legacy array network settings must build an inbound: %v", err)
	}
}

func TestForwardedClientIPAllowsConfiguredPublicOrLoopbackListener(t *testing.T) {
	proxySettings := json.RawMessage(`{"acceptProxyProtocol":true}`)
	for name, mutate := range map[string]func(*panel.CommonNode){
		"proxy protocol": func(common *panel.CommonNode) {
			common.NetworkSettings = proxySettings
		},
		"forwarded header": func(common *panel.CommonNode) {
			common.TrustedXForwardedFor = []string{"CF-Connecting-IP"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			common := &panel.CommonNode{
				ListenIP:        "0.0.0.0",
				ServerPort:      443,
				Network:         "tcp",
				NetworkSettings: json.RawMessage(`{}`),
			}
			mutate(common)
			if _, err := buildInbound(&panel.NodeInfo{
				Type: "vmess", Security: panel.None, Common: common,
			}, "public-listener"); err != nil {
				t.Fatalf("configured public listener was rejected: %v", err)
			}

			common.ListenIP = "127.0.0.1"
			if _, err := buildInbound(&panel.NodeInfo{
				Type: "vmess", Security: panel.None, Common: common,
			}, "loopback-listener"); err != nil {
				t.Fatalf("trusted local proxy setup was rejected: %v", err)
			}
		})
	}
}
