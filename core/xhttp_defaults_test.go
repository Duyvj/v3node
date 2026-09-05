package core

import (
	"encoding/json"
	"testing"

	coreConf "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/splithttp"
)

func TestXHTTPAntiTSPUDefaultsUseThreeConnections(t *testing.T) {
	config := &coreConf.SplitHTTPConfig{}
	if err := applyXHTTPAntiTSPUDefaults(config); err != nil {
		t.Fatalf("apply xhttp defaults: %v", err)
	}
	if config.Xmux.MaxConnections.From != 3 || config.Xmux.MaxConnections.To != 3 {
		t.Fatalf("maxConnections = %#v, want 3-3", config.Xmux.MaxConnections)
	}
	if config.Xmux.HMaxRequestTimes.From != 600 || config.Xmux.HMaxRequestTimes.To != 900 {
		t.Fatalf("hMaxRequestTimes = %#v, want 600-900", config.Xmux.HMaxRequestTimes)
	}
	if config.Xmux.HMaxReusableSecs.From != 1800 || config.Xmux.HMaxReusableSecs.To != 3000 {
		t.Fatalf("hMaxReusableSecs = %#v, want 1800-3000", config.Xmux.HMaxReusableSecs)
	}
	built, err := config.Build()
	if err != nil {
		t.Fatalf("build xhttp config: %v", err)
	}
	xhttp, ok := built.(*splithttp.Config)
	if !ok {
		t.Fatalf("built xhttp config type = %T", built)
	}
	connections := xhttp.GetXmux().GetMaxConnections()
	if connections.GetFrom() != 3 || connections.GetTo() != 3 {
		t.Fatalf("built maxConnections = %v, want 3-3", connections)
	}
}

func TestXHTTPAntiTSPUDefaultsPreserveExplicitXmux(t *testing.T) {
	config := &coreConf.SplitHTTPConfig{Xmux: coreConf.XmuxConfig{
		MaxConcurrency: coreConf.Int32Range{From: 16, To: 32},
	}}
	if err := applyXHTTPAntiTSPUDefaults(config); err != nil {
		t.Fatalf("apply xhttp defaults: %v", err)
	}
	if config.Xmux.MaxConnections != (coreConf.Int32Range{}) {
		t.Fatalf("explicit xmux gained maxConnections: %#v", config.Xmux.MaxConnections)
	}
}

func TestXHTTPAntiTSPUDefaultsApplyInsideExtra(t *testing.T) {
	config := &coreConf.SplitHTTPConfig{Extra: json.RawMessage(`{"futureOption":{"enabled":true}}`)}
	if err := applyXHTTPAntiTSPUDefaults(config); err != nil {
		t.Fatalf("apply xhttp defaults: %v", err)
	}

	var extra coreConf.SplitHTTPConfig
	if err := json.Unmarshal(config.Extra, &extra); err != nil {
		t.Fatalf("decode resulting extra: %v", err)
	}
	if extra.Xmux.MaxConnections.From != 3 || extra.Xmux.MaxConnections.To != 3 {
		t.Fatalf("extra maxConnections = %#v, want 3-3", extra.Xmux.MaxConnections)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(config.Extra, &raw); err != nil {
		t.Fatalf("decode resulting raw extra: %v", err)
	}
	if _, ok := raw["futureOption"]; !ok {
		t.Fatal("unknown future xhttp option was dropped")
	}
}

func TestXHTTPAntiTSPUDefaultsNormalizeEmptyArrayExtra(t *testing.T) {
	config := &coreConf.SplitHTTPConfig{Extra: json.RawMessage(`[]`)}
	if err := applyXHTTPAntiTSPUDefaults(config); err != nil {
		t.Fatalf("apply xhttp defaults to empty array: %v", err)
	}

	var extra coreConf.SplitHTTPConfig
	if err := json.Unmarshal(config.Extra, &extra); err != nil {
		t.Fatalf("decode normalized extra: %v", err)
	}
	if extra.Xmux.MaxConnections.From != 3 || extra.Xmux.MaxConnections.To != 3 {
		t.Fatalf("normalized maxConnections = %#v, want 3-3", extra.Xmux.MaxConnections)
	}
}

func TestXHTTPAntiTSPUDefaultsReachDownloadSettings(t *testing.T) {
	download := &coreConf.SplitHTTPConfig{}
	config := &coreConf.SplitHTTPConfig{
		Xmux: coreConf.XmuxConfig{MaxConcurrency: coreConf.Int32Range{From: 4, To: 4}},
		DownloadSettings: &coreConf.StreamConfig{
			SplitHTTPSettings: download,
		},
	}
	if err := applyXHTTPAntiTSPUDefaults(config); err != nil {
		t.Fatalf("apply xhttp defaults: %v", err)
	}
	if download.Xmux.MaxConnections.From != 3 || download.Xmux.MaxConnections.To != 3 {
		t.Fatalf("download maxConnections = %#v, want 3-3", download.Xmux.MaxConnections)
	}
}
