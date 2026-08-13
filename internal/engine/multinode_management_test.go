package engine

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestProtectedManagementEndpointsDeduplicateCrossNodeAddresses(t *testing.T) {
	cidrs, ports, err := protectedManagementEndpoints(
		"127.0.0.1:10085",
		"127.0.0.1:10086",
		"127.0.0.1:10085",
		"[::1]:11085",
	)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"127.0.0.1/32", "::1/128"}; !reflect.DeepEqual(cidrs, want) {
		t.Fatalf("CIDRs = %#v, want %#v", cidrs, want)
	}
	if want := []int{10085, 10086, 11085}; !reflect.DeepEqual(ports, want) {
		t.Fatalf("ports = %#v, want %#v", ports, want)
	}
}

func TestRenderersBlockEveryNodeManagementEndpoint(t *testing.T) {
	protected := []string{"127.0.0.1:11085", "[::1]:12086"}
	wantPorts := map[int]bool{10085: true, 10086: true, 11085: true, 12086: true}
	opts := baseOptions()
	opts.ProtectedManagement = protected

	t.Run("sing-box", func(t *testing.T) {
		rendered, err := (SingBoxRenderer{}).Render(baseNode(), []UserSpec{{ID: 42, Credential: "9f248408-79be-4f4d-927c-51cba1418b4f"}}, opts)
		if err != nil {
			t.Fatal(err)
		}
		var document struct {
			Route struct {
				Rules []map[string]any `json:"rules"`
			} `json:"route"`
		}
		if err := json.Unmarshal(rendered.Config, &document); err != nil {
			t.Fatal(err)
		}
		if len(document.Route.Rules) < 2 {
			t.Fatalf("route rules = %#v", document.Route.Rules)
		}
		rule := document.Route.Rules[1]
		got := make(map[int]bool)
		for _, raw := range rule["port"].([]any) {
			got[int(raw.(float64))] = true
		}
		if !reflect.DeepEqual(got, wantPorts) || rule["action"] != "reject" {
			t.Fatalf("management rule = %#v", rule)
		}
	})

	t.Run("xray", func(t *testing.T) {
		node := baseNode()
		node.Transport = "xhttp"
		node.Flow = ""
		node.TransportSettings = json.RawMessage(`{"path":"/edge"}`)
		rendered, err := (XrayRenderer{}).Render(node, []UserSpec{{ID: 42, Credential: "9f248408-79be-4f4d-927c-51cba1418b4f"}}, opts)
		if err != nil {
			t.Fatal(err)
		}
		var document struct {
			Routing struct {
				Rules []map[string]any `json:"rules"`
			} `json:"routing"`
		}
		if err := json.Unmarshal(rendered.Config, &document); err != nil {
			t.Fatal(err)
		}
		if len(document.Routing.Rules) < 3 {
			t.Fatalf("routing rules = %#v", document.Routing.Rules)
		}
		rule := document.Routing.Rules[2]
		if rule["port"] != "10085,10086,11085,12086" || rule["outboundTag"] != BlockTag {
			t.Fatalf("management rule = %#v", rule)
		}
	})
}
