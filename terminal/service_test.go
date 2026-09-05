package terminal

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDecodeChunkRejectsInvalidAndOversizedPayloads(t *testing.T) {
	if _, err := decodeChunk("not base64!"); err == nil {
		t.Fatal("invalid base64 was accepted")
	}
	over := base64.StdEncoding.EncodeToString(make([]byte, maxChunk+1))
	if _, err := decodeChunk(over); err == nil {
		t.Fatal("oversized chunk was accepted")
	}
	got, err := decodeChunk(base64.StdEncoding.EncodeToString([]byte("exit\n")))
	if err != nil || string(got) != "exit\n" {
		t.Fatalf("valid chunk decode = %q, %v", got, err)
	}
	if _, err := decodeChunk(strings.Repeat("A", base64.StdEncoding.EncodedLen(maxChunk)+1)); err == nil {
		t.Fatal("encoded length over limit was accepted")
	}
}

func TestTerminalUsesFixedShellAndSanitizedEnvironment(t *testing.T) {
	if shell := shellPath(); shell != "/bin/bash" && shell != "/bin/sh" {
		t.Fatalf("unexpected shell path %q", shell)
	}
	joined := strings.Join(sanitizedEnv(), "\n")
	for _, forbidden := range []string{"AGENTTOKEN", "ZNODE", "PASSWORD", "SECRET"} {
		if strings.Contains(strings.ToUpper(joined), forbidden) {
			t.Fatalf("sanitized environment leaked %s", forbidden)
		}
	}
}

func TestClaimBackoffIsCappedAndActiveRetryStaysFast(t *testing.T) {
	if got := nextBackoff(claimInterval, maxClaimInterval); got != time.Second {
		t.Fatalf("first idle backoff = %s", got)
	}
	if got := nextBackoff(maxClaimInterval, maxClaimInterval); got != maxClaimInterval {
		t.Fatalf("capped idle backoff = %s", got)
	}
	if exchangeInterval >= claimInterval {
		t.Fatalf("active exchange interval %s must remain below idle claim interval %s", exchangeInterval, claimInterval)
	}
}

func TestRelayActivityFollowsBrowserHeartbeat(t *testing.T) {
	now := time.Now()
	if !relaySessionActive(map[string]string{"last_activity": strconv.FormatInt(now.Unix(), 10)}, now) {
		t.Fatal("fresh browser heartbeat did not keep the relay active")
	}
	stale := now.Add(-idleLifetime - time.Second)
	if relaySessionActive(map[string]string{"last_activity": strconv.FormatInt(stale.Unix(), 10)}, now) {
		t.Fatal("stale browser heartbeat kept the relay active")
	}
	if relaySessionActive(map[string]string{"last_activity": "invalid"}, now) {
		t.Fatal("invalid browser heartbeat kept the relay active")
	}
}
