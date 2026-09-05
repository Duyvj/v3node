package panel

import (
	"encoding/json"
	"testing"
)

func TestEncSettingsAcceptsObject(t *testing.T) {
	var got EncSettings
	if err := json.Unmarshal([]byte(`{"mode":"xtls","ticket":"abc","server_padding":"pad","private_key":"key"}`), &got); err != nil {
		t.Fatalf("decode object: %v", err)
	}
	if got.Mode != "xtls" || got.Ticket != "abc" || got.ServerPadding != "pad" || got.PrivateKey != "key" {
		t.Fatalf("unexpected object: %#v", got)
	}
}

func TestEncSettingsAcceptsLegacyArray(t *testing.T) {
	var got EncSettings
	if err := json.Unmarshal([]byte(`[{"mode":"xtls","ticket":"legacy"}]`), &got); err != nil {
		t.Fatalf("decode array: %v", err)
	}
	if got.Mode != "xtls" || got.Ticket != "legacy" {
		t.Fatalf("unexpected array: %#v", got)
	}
}

func TestEncSettingsAcceptsEmptyLegacyValues(t *testing.T) {
	for _, input := range []string{`[]`, `null`} {
		var got EncSettings
		if err := json.Unmarshal([]byte(input), &got); err != nil {
			t.Fatalf("decode %s: %v", input, err)
		}
		if got != (EncSettings{}) {
			t.Fatalf("expected zero value for %s, got %#v", input, got)
		}
	}
}

