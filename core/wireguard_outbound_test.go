package core

import (
	"encoding/json"
	"testing"

	coreConf "github.com/xtls/xray-core/infra/conf"
)

func TestWireGuardOutboundIsRegistered(t *testing.T) {
	raw := []byte(`{
		"tag":"wg_out",
		"protocol":"wireguard",
		"settings":{
			"secretKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			"address":["10.0.0.2/32"],
			"peers":[{
				"endpoint":"127.0.0.1:51820",
				"publicKey":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
				"allowedIPs":["0.0.0.0/0"]
			}],
			"noKernelTun":true,
			"mtu":1280,
			"reserved":[0,0,0],
			"domainStrategy":"ForceIP"
		}
	}`)

	config := &coreConf.OutboundDetourConfig{}
	if err := json.Unmarshal(raw, config); err != nil {
		t.Fatalf("decode WireGuard outbound: %v", err)
	}
	if _, err := config.Build(); err != nil {
		t.Fatalf("build WireGuard outbound: %v", err)
	}
}
