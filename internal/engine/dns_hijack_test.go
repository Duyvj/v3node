package engine

import (
	"encoding/json"
	"testing"
)

func TestSingBoxRenderHijacksClientUDP53(t *testing.T) {
	got, err := (SingBoxRenderer{}).Render(
		baseNode(),
		[]UserSpec{{ID: 7, Credential: "48e90e76-2a72-46be-ac91-45d96486977a"}},
		baseOptions(),
	)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(got.Config, &document); err != nil {
		t.Fatal(err)
	}
	for _, rule := range document.Route.Rules {
		if rule["network"] == "udp" && rule["action"] == "hijack-dns" && numericListContains(rule["port"], 53) {
			return
		}
	}
	t.Fatalf("rendered route has no UDP/53 DNS hijack: %#v", document.Route.Rules)
}

func TestXrayRenderHijacksClientUDP53(t *testing.T) {
	got, err := (XrayRenderer{}).Render(
		baseNode(),
		[]UserSpec{{ID: 7, Credential: "48e90e76-2a72-46be-ac91-45d96486977a"}},
		baseOptions(),
	)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Outbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
		} `json:"outbounds"`
		Routing struct {
			Rules []map[string]any `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(got.Config, &document); err != nil {
		t.Fatal(err)
	}
	foundOutbound := false
	for _, outbound := range document.Outbounds {
		if outbound.Tag == DNSOutTag && outbound.Protocol == "dns" {
			foundOutbound = true
		}
	}
	if !foundOutbound {
		t.Fatalf("rendered config has no protected DNS outbound: %#v", document.Outbounds)
	}
	if len(document.Routing.Rules) < 2 {
		t.Fatalf("rendered route has too few rules: %#v", document.Routing.Rules)
	}
	rule := document.Routing.Rules[1]
	if rule["network"] == "udp" && rule["port"] == "53" && rule["outboundTag"] == DNSOutTag && stringListContains(rule["inboundTag"], InboundTag) {
		return
	}
	t.Fatalf("rendered route has no UDP/53 DNS hijack: %#v", document.Routing.Rules)
}

func stringListContains(value any, expected string) bool {
	items, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		if item == expected {
			return true
		}
	}
	return false
}

func numericListContains(value any, expected float64) bool {
	items, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		if item == expected {
			return true
		}
	}
	return false
}
