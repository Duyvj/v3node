package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Duyvj/v3node/internal/engine"
)

func TestRuntimeStatePersistsEngineGenerationHash(t *testing.T) {
	hash := sha256.Sum256([]byte("engine generation"))
	state := RuntimeState{
		Version:           runtimeStateVersion,
		Backend:           "sing-box",
		EngineUsers:       map[string]int{"uid-1": 1},
		Policies:          map[int]UserPolicy{1: {}},
		PullIntervalNanos: int64(30 * time.Second),
		PushIntervalNanos: int64(30 * time.Second),
	}
	state.ConfigSHA256 = hex.EncodeToString(hash[:])
	path := filepath.Join(t.TempDir(), "runtime.json")
	if err := SaveRuntimeState(path, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRuntimeState(path, 10, 15*time.Second, time.Hour, 15*time.Second, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, err := loaded.ConfigHash()
	if err != nil || got != hash {
		t.Fatalf("config hash = %x, error %v; want %x", got, err, hash)
	}
}

func TestRuntimeStateRejectsMissingGenerationHash(t *testing.T) {
	state := RuntimeState{
		Version:           runtimeStateVersion,
		Backend:           "xray",
		EngineUsers:       map[string]int{},
		Policies:          map[int]UserPolicy{},
		PullIntervalNanos: int64(30 * time.Second),
		PushIntervalNanos: int64(30 * time.Second),
	}
	if err := state.Validate(10, 15*time.Second, time.Hour, 15*time.Second, time.Hour); err == nil {
		t.Fatal("expected missing generation hash to be rejected")
	}
}

func TestRuntimeStateOmitsZeroPoliciesAndUsesCompactJSON(t *testing.T) {
	hash := sha256.Sum256([]byte("compact generation"))
	compiled := CompiledState{
		Users: []engine.UserSpec{
			{ID: 1},
			{ID: 2, DeviceLimit: 3},
		},
		PullInterval: 30 * time.Second,
		PushInterval: 30 * time.Second,
	}
	state := RuntimeStateFromCompiled("sing-box", compiled, map[string]int{"uid-1": 1, "uid-2": 2}, hash)
	if len(state.Policies) != 1 || state.Policies[2].DeviceLimit != 3 {
		t.Fatalf("unexpected compact policies: %#v", state.Policies)
	}
	path := filepath.Join(t.TempDir(), "runtime.json")
	if err := SaveRuntimeState(path, state); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatalf("runtime state is not newline terminated: %q", data)
	}
	if bytes.Contains(data, []byte("\n  \"")) {
		t.Fatalf("runtime state unexpectedly uses indented JSON: %s", data)
	}
}
