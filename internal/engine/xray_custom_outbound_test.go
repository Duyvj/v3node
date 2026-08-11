package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateSpecCustomOutboundMatchRequirements(t *testing.T) {
	user := []UserSpec{{ID: 1, Credential: "48e90e76-2a72-46be-ac91-45d96486977a"}}
	custom := `{"tag":"regional","protocol":"freedom","settings":{}}`
	for _, action := range []string{"route", "route_ip"} {
		node := baseNode()
		node.Routes = []RouteSpec{{ID: 10, Action: action, ActionValue: custom}}
		if err := ValidateSpec(node, user); err == nil {
			t.Fatalf("accepted matcherless %s", action)
		}
	}

	node := baseNode()
	node.Routes = []RouteSpec{{ID: 11, Action: "default_out", ActionValue: custom}}
	if err := ValidateSpec(node, user); err != nil {
		t.Fatalf("rejected matcherless default_out: %v", err)
	}
}

func TestSelectCustomOutboundUsesXray(t *testing.T) {
	node := baseNode()
	node.Routes = []RouteSpec{{
		ID: 1, Action: "default_out",
		ActionValue: `{"tag":"regional","protocol":"freedom","settings":{}}`,
	}}
	renderer, err := Select("auto", node)
	if err != nil {
		t.Fatal(err)
	}
	if renderer.Name() != "xray" {
		t.Fatalf("custom outbound selected %s, want xray", renderer.Name())
	}
	if _, err := Select("sing-box", node); err == nil {
		t.Fatal("forced sing-box accepted an Xray custom outbound")
	}
}

func TestXrayCustomOutboundRendersOnceAndRulesReferenceTag(t *testing.T) {
	node := baseNode()
	node.Routes = []RouteSpec{
		{
			ID:          1,
			Action:      "route",
			Match:       []string{"domain:example.com"},
			ActionValue: `{"tag":"regional","protocol":"freedom","settings":{"level":1}}`,
		},
		{
			ID:          2,
			Action:      "route_ip",
			Match:       []string{"203.0.113.0/24"},
			ActionValue: `{ "settings": { "level": 1.0 }, "protocol": "freedom", "tag": "regional" }`,
		},
	}

	got, err := (XrayRenderer{}).Render(
		node,
		[]UserSpec{{ID: 1, Credential: "48e90e76-2a72-46be-ac91-45d96486977a"}},
		baseOptions(),
	)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Outbounds []map[string]any `json:"outbounds"`
		Routing   struct {
			Rules []map[string]any `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(got.Config, &document); err != nil {
		t.Fatal(err)
	}
	outboundCount := 0
	for _, outbound := range document.Outbounds {
		if outbound["tag"] == "regional" {
			outboundCount++
		}
	}
	if outboundCount != 1 {
		t.Fatalf("regional outbound rendered %d times: %#v", outboundCount, document.Outbounds)
	}
	ruleCount := 0
	for _, rule := range document.Routing.Rules {
		if rule["outboundTag"] == "regional" {
			ruleCount++
		}
	}
	if ruleCount != 2 {
		t.Fatalf("regional outbound referenced by %d rules: %#v", ruleCount, document.Routing.Rules)
	}
}

func TestXrayCustomOutboundRejectsConflictingTagDefinitions(t *testing.T) {
	node := baseNode()
	node.Routes = []RouteSpec{
		{ID: 1, Action: "default_out", ActionValue: `{"tag":"regional","protocol":"freedom","settings":{"level":1}}`},
		{ID: 2, Action: "default_out", ActionValue: `{"tag":"regional","protocol":"freedom","settings":{"level":2}}`},
	}
	if _, err := (XrayRenderer{}).Render(
		node,
		[]UserSpec{{ID: 1, Credential: "48e90e76-2a72-46be-ac91-45d96486977a"}},
		baseOptions(),
	); err == nil {
		t.Fatal("accepted conflicting definitions for one custom outbound tag")
	}
}

func TestParseXrayCustomOutboundRejectsProtectedTags(t *testing.T) {
	for _, tag := range []string{
		DirectTag,
		BlockTag,
		DNSOutTag,
		InboundTag,
		"management-api",
		"management-api-in",
	} {
		raw := `{"tag":` + strconvQuote(tag) + `,"protocol":"freedom","settings":{}}`
		if _, _, err := parseXrayCustomOutbound(7, raw); err == nil {
			t.Fatalf("accepted protected tag %q", tag)
		}
	}
}

func TestParseXrayCustomOutboundValidation(t *testing.T) {
	valid := `{"tag":"regional","protocol":"freedom","settings":{},"targetStrategy":"UseIPv4"}`
	outbound, tag, err := parseXrayCustomOutbound(8, valid)
	if err != nil {
		t.Fatalf("rejected valid custom outbound: %v", err)
	}
	if tag != "regional" || outbound["targetStrategy"] != "UseIPv4" {
		t.Fatalf("parsed outbound = %#v, tag = %q", outbound, tag)
	}

	for name, raw := range map[string]string{
		"empty":            "",
		"malformed":        `{`,
		"array":            `[]`,
		"null":             `null`,
		"trailing object":  valid + `{}`,
		"trailing garbage": valid + ` trailing`,
		"unknown field":    `{"tag":"regional","protocol":"freedom","unexpected":true}`,
		"missing tag":      `{"protocol":"freedom","settings":{}}`,
		"invalid tag":      `{"tag":"not valid","protocol":"freedom","settings":{}}`,
		"missing protocol": `{"tag":"regional","settings":{}}`,
		"invalid protocol": `{"tag":"regional","protocol":"not valid","settings":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseXrayCustomOutbound(8, raw); err == nil {
				t.Fatalf("accepted invalid custom outbound %q", raw)
			}
		})
	}

	exactLimit := valid + strings.Repeat(" ", (256<<10)-len(valid))
	if _, _, err := parseXrayCustomOutbound(8, exactLimit); err != nil {
		t.Fatalf("rejected outbound at 256 KiB limit: %v", err)
	}
	if _, _, err := parseXrayCustomOutbound(8, exactLimit+" "); err == nil {
		t.Fatal("accepted outbound larger than 256 KiB")
	}
}

func strconvQuote(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
