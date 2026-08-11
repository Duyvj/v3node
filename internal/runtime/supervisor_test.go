package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const helperProcessEnv = "V3NODE_RUNTIME_HELPER_PROCESS"

type helperConfig struct {
	Generation string `json:"generation"`
	Events     string `json:"events"`
	Mode       string `json:"mode,omitempty"`
}

// TestMain turns the package test binary into a small, portable stand-in for
// sing-box and Xray when Supervisor starts it with their normal CLI arguments.
// This exercises exec, process lifecycle, and the on-disk transaction without
// requiring either engine to be installed on the test host.
func TestMain(m *testing.M) {
	if os.Getenv(helperProcessEnv) == "1" {
		os.Exit(runHelperProcess(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func runHelperProcess(args []string) int {
	configPath, checking := helperConfigPath(args)
	if configPath == "" {
		return 2
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return 3
	}
	var cfg helperConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return 4
	}
	if checking {
		return 0
	}
	if cfg.Events == "" || cfg.Generation == "" {
		return 5
	}
	f, err := os.OpenFile(cfg.Events, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return 6
	}
	_, writeErr := fmt.Fprintf(f, "%s:%d\n", cfg.Generation, os.Getpid())
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return 7
	}
	if cfg.Mode == "exit" {
		return 8
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	defer signal.Stop(interrupt)
	<-interrupt
	return 0
}

func helperConfigPath(args []string) (path string, checking bool) {
	for i, arg := range args {
		switch arg {
		case "-c", "-config":
			if i+1 < len(args) {
				path = args[i+1]
			}
		case "check", "-test":
			checking = true
		}
	}
	return path, checking
}

func TestSupervisorApplyFirstNoOpAndUpdate(t *testing.T) {
	dir := t.TempDir()
	events := filepath.Join(dir, "starts.log")
	s, binary := newTestSupervisor(t, dir, nil)

	first := marshalHelperConfig(t, helperConfig{Generation: "first", Events: events})
	if err := s.Apply(context.Background(), "sing-box", binary, first); err != nil {
		t.Fatalf("apply first configuration: %v", err)
	}
	assertFileContent(t, filepath.Join(dir, "engine.json"), first)
	waitForGenerations(t, events, "first")
	firstCmd := s.cmd
	if firstCmd == nil || !s.Healthy() {
		t.Fatal("first engine generation is not healthy")
	}
	firstGeneration := s.Generation()
	if firstGeneration == 0 {
		t.Fatal("first engine process has a zero generation")
	}

	if err := s.Apply(context.Background(), "sing-box", binary, first); err != nil {
		t.Fatalf("apply identical configuration: %v", err)
	}
	if s.cmd != firstCmd {
		t.Fatal("identical configuration restarted the engine")
	}
	if s.Generation() != firstGeneration {
		t.Fatal("identical configuration changed the process generation")
	}
	assertGenerations(t, events, "first")

	second := marshalHelperConfig(t, helperConfig{Generation: "second", Events: events})
	if err := s.Apply(context.Background(), "sing-box", binary, second); err != nil {
		t.Fatalf("apply updated configuration: %v", err)
	}
	if s.cmd == firstCmd {
		t.Fatal("updated configuration did not replace the engine process")
	}
	if s.Generation() == firstGeneration {
		t.Fatal("updated process did not change the engine generation")
	}
	if !s.Healthy() {
		t.Fatal("updated engine generation is not healthy")
	}
	assertFileContent(t, filepath.Join(dir, "engine.json"), second)
	assertFileContent(t, filepath.Join(dir, "engine.previous.json"), first)
	waitForGenerations(t, events, "first", "second")
}

func TestSupervisorRollsBackFailedCandidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode string
	}{
		{name: "exits during startup", mode: "exit"},
		{name: "fails health probe", mode: "health"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			events := filepath.Join(dir, "starts.log")
			probe := func(context.Context) error {
				data, err := os.ReadFile(filepath.Join(dir, "engine.json"))
				if err != nil {
					return err
				}
				var cfg helperConfig
				if err := json.Unmarshal(data, &cfg); err != nil {
					return err
				}
				if cfg.Mode == "health" {
					return errors.New("injected unhealthy candidate")
				}
				return nil
			}
			s, binary := newTestSupervisor(t, dir, probe)

			accepted := marshalHelperConfig(t, helperConfig{Generation: "accepted", Events: events})
			if err := s.Apply(context.Background(), "sing-box", binary, accepted); err != nil {
				t.Fatalf("apply accepted configuration: %v", err)
			}
			acceptedGeneration := s.Generation()
			candidate := marshalHelperConfig(t, helperConfig{
				Generation: "candidate-" + tc.mode,
				Events:     events,
				Mode:       tc.mode,
			})
			err := s.Apply(context.Background(), "sing-box", binary, candidate)
			if err == nil || !strings.Contains(err.Error(), "previous configuration restored") {
				t.Fatalf("apply failed candidate: got %v, want rollback error", err)
			}

			assertFileContent(t, filepath.Join(dir, "engine.json"), accepted)
			assertFileContent(t, filepath.Join(dir, "engine.failed.json"), candidate)
			if _, err := os.Stat(filepath.Join(dir, "engine.previous.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("previous file remains after rollback: %v", err)
			}
			waitForGenerations(t, events, "accepted", "candidate-"+tc.mode, "accepted")
			if !s.Healthy() {
				t.Fatal("previous generation is not running after rollback")
			}
			if s.Generation() == acceptedGeneration {
				t.Fatal("rollback restart did not change the process generation")
			}
			if s.hash != sha256.Sum256(accepted) || s.backend != "sing-box" || s.binary != binary {
				t.Fatal("accepted runtime metadata changed after rollback")
			}

			rollbackCmd := s.cmd
			if err := s.Apply(context.Background(), "sing-box", binary, accepted); err != nil {
				t.Fatalf("re-apply accepted configuration after rollback: %v", err)
			}
			if s.cmd != rollbackCmd {
				t.Fatal("accepted configuration restarted after successful rollback")
			}
			assertGenerations(t, events, "accepted", "candidate-"+tc.mode, "accepted")
		})
	}
}

func TestSupervisorRestoresGenerationMatchingRuntimeMetadata(t *testing.T) {
	dir := t.TempDir()
	events := filepath.Join(dir, "starts.log")
	accepted := marshalHelperConfig(t, helperConfig{Generation: "accepted", Events: events})
	candidate := marshalHelperConfig(t, helperConfig{Generation: "uncommitted", Events: events})
	if err := os.WriteFile(filepath.Join(dir, "engine.json"), candidate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "engine.previous.json"), accepted, 0o600); err != nil {
		t.Fatal(err)
	}
	s, binary := newTestSupervisor(t, dir, nil)
	if err := s.StartExisting(context.Background(), "xray", binary, sha256.Sum256(accepted)); err != nil {
		t.Fatalf("restore committed generation: %v", err)
	}
	assertFileContent(t, filepath.Join(dir, "engine.json"), accepted)
	assertFileContent(t, filepath.Join(dir, "engine.failed.json"), candidate)
	waitForGenerations(t, events, "accepted")
}

func TestSupervisorStartExistingStopAndClose(t *testing.T) {
	dir := t.TempDir()
	events := filepath.Join(dir, "starts.log")
	config := marshalHelperConfig(t, helperConfig{Generation: "existing", Events: events})
	if err := os.WriteFile(filepath.Join(dir, "engine.json"), config, 0o600); err != nil {
		t.Fatalf("write existing configuration: %v", err)
	}
	s, binary := newTestSupervisor(t, dir, nil)

	if err := s.StartExisting(context.Background(), "xray", binary, sha256.Sum256(config)); err != nil {
		t.Fatalf("start existing configuration: %v", err)
	}
	waitForGenerations(t, events, "existing")
	firstCmd := s.cmd
	if !s.Healthy() || s.hash != sha256.Sum256(config) || s.backend != "xray" || s.binary != binary {
		t.Fatal("existing engine did not populate healthy runtime state")
	}
	if err := s.StartExisting(context.Background(), "xray", binary, sha256.Sum256(config)); err != nil {
		t.Fatalf("start an already-running existing configuration: %v", err)
	}
	if s.cmd != firstCmd {
		t.Fatal("StartExisting restarted an already-running engine")
	}
	assertGenerations(t, events, "existing")

	if err := s.Stop(context.Background()); err != nil {
		t.Fatalf("stop existing engine: %v", err)
	}
	if s.Healthy() {
		t.Fatal("engine remains healthy after Stop")
	}
	if err := s.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop should be idempotent: %v", err)
	}
	if err := s.StartExisting(context.Background(), "xray", binary, sha256.Sum256(config)); err != nil {
		t.Fatalf("restart existing configuration: %v", err)
	}
	waitForGenerations(t, events, "existing", "existing")

	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("close supervisor: %v", err)
	}
	if s.Healthy() {
		t.Fatal("engine remains healthy after Close")
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("second Close should be idempotent: %v", err)
	}
	if err := s.StartExisting(context.Background(), "xray", binary, sha256.Sum256(config)); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("StartExisting after Close: got %v, want closed error", err)
	}
	if err := s.Apply(context.Background(), "xray", binary, config); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("Apply after Close: got %v, want closed error", err)
	}
}

func TestEngineEnvironmentLocatesXrayAssets(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "xray")
	t.Setenv("XRAY_LOCATION_ASSET", "")
	if got := environmentValue(engineEnvironment("xray", binary), "XRAY_LOCATION_ASSET"); got != filepath.Dir(binary) {
		t.Fatalf("derived XRAY_LOCATION_ASSET = %q", got)
	}
	t.Setenv("XRAY_LOCATION_ASSET", "/custom/xray-assets")
	if got := environmentValue(engineEnvironment("xray", binary), "XRAY_LOCATION_ASSET"); got != "/custom/xray-assets" {
		t.Fatalf("configured XRAY_LOCATION_ASSET = %q", got)
	}
	if got := engineEnvironment("sing-box", binary); got != nil {
		t.Fatalf("sing-box environment override = %#v", got)
	}
}

func environmentValue(environment []string, wanted string) string {
	for _, entry := range environment {
		key, value, found := strings.Cut(entry, "=")
		if found && strings.EqualFold(key, wanted) {
			return value
		}
	}
	return ""
}

func newTestSupervisor(t *testing.T, dir string, probe HealthProbe) (*Supervisor, string) {
	t.Helper()
	t.Setenv(helperProcessEnv, "1")
	binary, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test executable: %v", err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatalf("make test executable path absolute: %v", err)
	}
	s, err := NewSupervisor(SupervisorOptions{
		Directory:   dir,
		StopTimeout: 250 * time.Millisecond,
		Stdout:      io.Discard,
		Stderr:      io.Discard,
		HealthProbe: probe,
	})
	if err != nil {
		t.Fatalf("create supervisor: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := s.Close(ctx); err != nil {
			t.Errorf("close supervisor: %v", err)
		}
	})
	return s, binary
}

func marshalHelperConfig(t *testing.T, cfg helperConfig) []byte {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal helper configuration: %v", err)
	}
	return data
}

func assertFileContent(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Base(path), err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s = %q, want %q", filepath.Base(path), got, want)
	}
}

func waitForGenerations(t *testing.T, path string, want ...string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if got, err := readGenerations(path); err == nil && equalStrings(got, want) {
			return
		}
		if time.Now().After(deadline) {
			got, err := readGenerations(path)
			t.Fatalf("engine starts = %v (error %v), want %v", got, err, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertGenerations(t *testing.T, path string, want ...string) {
	t.Helper()
	got, err := readGenerations(path)
	if err != nil {
		t.Fatalf("read engine starts: %v", err)
	}
	if !equalStrings(got, want) {
		t.Fatalf("engine starts = %v, want %v", got, want)
	}
}

func readGenerations(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		generation, _, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			return nil, fmt.Errorf("malformed start event %q", line)
		}
		result = append(result, generation)
	}
	return result, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
