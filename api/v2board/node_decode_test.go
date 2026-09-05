package panel

import (
	"encoding/json"
	"testing"
	"time"
)

func TestTlsSettingsXverAcceptsNumberAndString(t *testing.T) {
	for _, payload := range []string{`{"xver":0}`, `{"xver":"2"}`} {
		var settings TlsSettings
		if err := json.Unmarshal([]byte(payload), &settings); err != nil {
			t.Fatalf("decode %s: %v", payload, err)
		}
	}
}

func TestPanelIntervalsAreBoundedAndNeverPanicOnMissingValues(t *testing.T) {
	for name, test := range map[string]struct {
		value any
		want  time.Duration
	}{
		"missing": {value: nil, want: time.Minute},
		"zero":    {value: 0, want: 5 * time.Second},
		"string":  {value: "15", want: 15 * time.Second},
		"large":   {value: float64(999999), want: time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			if got := intervalToTime(test.value); got != test.want {
				t.Fatalf("intervalToTime(%v) = %s, want %s", test.value, got, test.want)
			}
		})
	}
}

func TestBlankTLSCertModeDefaultsToSelfSigned(t *testing.T) {
	if mode := effectiveCertMode(Tls, ""); mode != "self" {
		t.Fatalf("expected self cert mode, got %q", mode)
	}
	if mode := effectiveCertMode(None, ""); mode != "" {
		t.Fatalf("expected blank mode without TLS, got %q", mode)
	}
	if mode := effectiveCertMode(Tls, "file"); mode != "file" {
		t.Fatalf("expected explicit mode to be preserved, got %q", mode)
	}
}

func TestDNSCredentialsAllowOnlyZBoardCloudflareVariables(t *testing.T) {
	provider, credentials, err := parseDNSCredentials("cloudflare", "CF_DNS_API_TOKEN=secret-value")
	if err != nil {
		t.Fatal(err)
	}
	if provider != "cloudflare" || credentials["CF_DNS_API_TOKEN"] != "secret-value" {
		t.Fatalf("unexpected parsed credentials: %q %#v", provider, credentials)
	}

	for name, input := range map[string]struct {
		provider string
		raw      string
	}{
		"command provider": {provider: "exec", raw: "EXEC_PATH=/tmp/run"},
		"arbitrary env":    {provider: "cloudflare", raw: "LD_PRELOAD=/tmp/evil.so"},
		"control byte":     {provider: "cloudflare", raw: "CF_DNS_API_TOKEN=line1\nline2"},
		"duplicate":        {provider: "cloudflare", raw: "CF_DNS_API_TOKEN=a,CF_DNS_API_TOKEN=b"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseDNSCredentials(input.provider, input.raw); err == nil {
				t.Fatal("unsafe DNS credential settings were accepted")
			}
		})
	}
}
