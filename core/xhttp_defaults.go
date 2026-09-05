package core

import (
	"encoding/json"
	"fmt"
	"strings"

	coreConf "github.com/xtls/xray-core/infra/conf"
)

// applyXHTTPAntiTSPUDefaults backports Xray-core commit 18e28390. The pinned
// ZNode core fork still defaults an empty XHTTP xmux configuration to six
// connections; current upstream uses three to reduce TSPU exposure.
//
// Keep this identical to the upstream defaulting rule: only a completely
// empty xmux block receives defaults. Explicit operator settings always win.
func applyXHTTPAntiTSPUDefaults(config *coreConf.SplitHTTPConfig) error {
	if config == nil {
		return nil
	}

	// Xray treats "extra" as the effective SplitHTTP configuration, so the
	// default must be applied inside it rather than to the ignored outer xmux.
	if config.Extra != nil {
		raw, err := applyXHTTPRawDefaults(config.Extra)
		if err != nil {
			return err
		}
		config.Extra = raw
		return nil
	}

	if config.Xmux == (coreConf.XmuxConfig{}) {
		config.Xmux.MaxConnections = xhttpRange(3, 3)
		config.Xmux.HMaxRequestTimes = xhttpRange(600, 900)
		config.Xmux.HMaxReusableSecs = xhttpRange(1800, 3000)
	}

	return applyXHTTPStreamDefaults(config.DownloadSettings)
}

func applyXHTTPRawDefaults(raw json.RawMessage) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(string(raw))
	// PHP's json_encode serializes an empty associative array as [] while
	// Xray's SplitHTTP extra block is an object. Treat that harmless legacy
	// representation as an empty object so one malformed field cannot stop
	// every inbound from starting.
	if trimmed == "null" || trimmed == "[]" {
		raw = json.RawMessage(`{}`)
	}
	var config coreConf.SplitHTTPConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("decode xhttp extra: %w", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, fmt.Errorf("decode xhttp extra object: %w", err)
	}
	if object == nil {
		return nil, fmt.Errorf("decode xhttp extra object: expected an object")
	}

	if config.Extra != nil {
		patched, err := applyXHTTPRawDefaults(config.Extra)
		if err != nil {
			return nil, err
		}
		object["extra"] = patched
	} else {
		if config.Xmux == (coreConf.XmuxConfig{}) {
			xmux := make(map[string]json.RawMessage)
			if existing, ok := object["xmux"]; ok && strings.TrimSpace(string(existing)) != "null" {
				if err := json.Unmarshal(existing, &xmux); err != nil {
					return nil, fmt.Errorf("decode xhttp xmux: %w", err)
				}
			}
			xmux["maxConnections"] = json.RawMessage(`3`)
			xmux["hMaxRequestTimes"] = json.RawMessage(`"600-900"`)
			xmux["hMaxReusableSecs"] = json.RawMessage(`"1800-3000"`)
			encoded, err := json.Marshal(xmux)
			if err != nil {
				return nil, fmt.Errorf("encode xhttp xmux: %w", err)
			}
			object["xmux"] = encoded
		}
		if download, ok := object["downloadSettings"]; ok && strings.TrimSpace(string(download)) != "null" {
			patched, err := applyXHTTPStreamRawDefaults(download)
			if err != nil {
				return nil, err
			}
			object["downloadSettings"] = patched
		}
	}

	patched, err := json.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("encode xhttp extra: %w", err)
	}
	return patched, nil
}

func applyXHTTPStreamRawDefaults(raw json.RawMessage) (json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, fmt.Errorf("decode xhttp download settings: %w", err)
	}
	if object == nil {
		return nil, fmt.Errorf("decode xhttp download settings: expected an object")
	}
	for _, key := range []string{"xhttpSettings", "splithttpSettings"} {
		settings, ok := object[key]
		if !ok || strings.TrimSpace(string(settings)) == "null" {
			continue
		}
		patched, err := applyXHTTPRawDefaults(settings)
		if err != nil {
			return nil, err
		}
		object[key] = patched
	}
	patched, err := json.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("encode xhttp download settings: %w", err)
	}
	return patched, nil
}

func applyXHTTPStreamDefaults(stream *coreConf.StreamConfig) error {
	if stream == nil {
		return nil
	}
	if err := applyXHTTPAntiTSPUDefaults(stream.XHTTPSettings); err != nil {
		return err
	}
	if stream.SplitHTTPSettings != stream.XHTTPSettings {
		if err := applyXHTTPAntiTSPUDefaults(stream.SplitHTTPSettings); err != nil {
			return err
		}
	}
	return nil
}

func xhttpRange(from, to int32) coreConf.Int32Range {
	// Int32Range.Build reads From/To while MarshalJSON reads Left/Right. Keep
	// both pairs populated because XHTTP's "extra" block is rewritten as JSON.
	return coreConf.Int32Range{Left: from, Right: to, From: from, To: to}
}
