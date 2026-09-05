package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Duyvj/v3node/conf"
)

func TestReportNodeStatusSendsResourceTelemetryToAssignedNode(t *testing.T) {
	want := NodeStatus{
		Timestamp:     1_700_000_000,
		Hostname:      "vps-a",
		OS:            "linux",
		Arch:          "amd64",
		CPUCores:      4,
		CPUPercent:    17.5,
		MemoryPercent: 42,
		DiskPercent:   63,
		NetworkRXMbps: 81.25,
		NetworkTXMbps: 12.5,
		UptimeSeconds: 900,
		TLSEnabled:    false,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v1/server/UniProxy/status" {
			t.Errorf("unexpected telemetry request: %s %s", request.Method, request.URL.Path)
		}
		query := request.URL.Query()
		if query.Get("node_type") != "v2node" || query.Get("node_id") != "31" || query.Get("agent_id") != "" {
			t.Errorf("unexpected telemetry query: %v", query)
		}
		if request.Header.Get("X-ZNode-Agent-ID") != "agent-a" || request.Header.Get("X-ZNode-Agent-Token") != "secret" {
			t.Errorf("agent credentials were not sent")
		}
		if request.Header.Get("X-ZNode-Type") != conf.RequiredPanelType || query.Get("type") != conf.RequiredPanelType {
			t.Errorf("ZBoard identity was not sent")
		}
		var got NodeStatus
		if err := json.NewDecoder(request.Body).Decode(&got); err != nil {
			t.Errorf("decode telemetry body: %v", err)
		}
		if got.CPUPercent != want.CPUPercent || got.MemoryPercent != want.MemoryPercent || got.DiskPercent != want.DiskPercent {
			t.Errorf("resource percentages changed in transit: %+v", got)
		}
		if got.NetworkRXMbps != want.NetworkRXMbps || got.NetworkTXMbps != want.NetworkTXMbps {
			t.Errorf("network rates changed in transit: %+v", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := New(&conf.NodeConfig{
		APIHost: server.URL,
		NodeID:  31,
		Key:     "secret",
		AgentID: "agent-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ReportNodeStatus(context.Background(), want); err != nil {
		t.Fatal(err)
	}
}

func TestReportNodeStatusReturnsPanelFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))
	defer server.Close()

	client, err := New(&conf.NodeConfig{APIHost: server.URL, NodeID: 9, Key: "agent-token", AgentID: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ReportNodeStatus(context.Background(), NodeStatus{}); err == nil {
		t.Fatal("expected a panel HTTP error")
	}
}
