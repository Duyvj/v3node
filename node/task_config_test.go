package node

import (
	"testing"
	"time"

	panel "github.com/Duyvj/v3node/api/v2board"
)

func reportingTestNode() *panel.NodeInfo {
	return &panel.NodeInfo{
		Id:           7,
		Type:         "vless",
		Security:     panel.Reality,
		PushInterval: 15 * time.Second,
		PullInterval: 15 * time.Second,
		Tag:          "node-7",
		Common: &panel.CommonNode{
			PanelType:  "zboard",
			Protocol:   "vless",
			ListenIP:   "0.0.0.0",
			ServerPort: 443,
			BaseConfig: &panel.BaseConfig{
				PushInterval:           15,
				PullInterval:           15,
				NodeReportMinTraffic:   200,
				DeviceOnlineMinTraffic: 200,
			},
		},
	}
}

func TestReportingThresholdChangeDoesNotRequireXrayReload(t *testing.T) {
	current := reportingTestNode()
	next := reportingTestNode()
	next.Common.BaseConfig.NodeReportMinTraffic = 0
	next.Common.BaseConfig.DeviceOnlineMinTraffic = 0

	if !reportingThresholdOnlyChange(current, next) {
		t.Fatal("report-only threshold update was classified as an Xray runtime change")
	}

	controller := &Controller{info: current}
	controller.applyReportingThresholds(next)
	if current.Common.BaseConfig.NodeReportMinTraffic != 0 || current.Common.BaseConfig.DeviceOnlineMinTraffic != 0 {
		t.Fatalf("report thresholds were not hot-applied: %+v", current.Common.BaseConfig)
	}
}

func TestRuntimeOrScheduleChangeStillRequiresReload(t *testing.T) {
	for name, mutate := range map[string]func(*panel.NodeInfo){
		"listener": func(info *panel.NodeInfo) { info.Common.ServerPort = 8443 },
		"protocol": func(info *panel.NodeInfo) { info.Type, info.Common.Protocol = "trojan", "trojan" },
		"push interval": func(info *panel.NodeInfo) {
			info.PushInterval = 30 * time.Second
			info.Common.BaseConfig.PushInterval = 30
		},
	} {
		t.Run(name, func(t *testing.T) {
			current := reportingTestNode()
			next := reportingTestNode()
			mutate(next)
			if reportingThresholdOnlyChange(current, next) {
				t.Fatal("runtime-affecting change incorrectly bypassed reload")
			}
		})
	}
}
