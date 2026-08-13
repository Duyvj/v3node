package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Duyvj/v3node/internal/app"
	"github.com/Duyvj/v3node/internal/config"
	"github.com/Duyvj/v3node/internal/engine"
)

func writeMultiCheckConfig(t *testing.T, nodes int) string {
	t.Helper()
	directory := t.TempDir()
	cfg := config.Defaults()
	cfg.Panel = config.PanelConfig{}
	cfg.Engine.StateDir = filepath.Join(directory, "state")
	cfg.Nodes = make([]config.NodeEntry, nodes)
	for index := range cfg.Nodes {
		cfg.Nodes[index] = config.NodeEntry{
			Name:        "node-" + string(rune('a'+index)),
			APIHost:     "https://panel-" + string(rune('a'+index)) + ".example",
			NodeID:      int64(index + 1),
			APIKey:      "test-token",
			StateDir:    filepath.Join(directory, "state", string(rune('a'+index))),
			StatsListen: "127.0.0.1:" + []string{"11001", "12001", "13001"}[index],
			ClashListen: "127.0.0.1:" + []string{"11002", "12002", "13002"}[index],
		}
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunCheckDetectsPortCollisionBeforeValidationSideEffects(t *testing.T) {
	path := writeMultiCheckConfig(t, 2)
	validated := 0
	fetch := func(_ context.Context, cfg config.Config, _ io.Writer) (checkCandidate, error) {
		return checkCandidate{
			config:   cfg,
			compiled: app.CompiledState{Node: engine.NodeSpec{Protocol: "vless", Port: 443}},
		}, nil
	}
	validate := func(context.Context, checkCandidate, io.Writer, io.Writer, bool) error {
		validated++
		return nil
	}
	err := runCheckWith([]string{"--config", path, "--render-only"}, io.Discard, io.Discard, fetch, validate)
	if err == nil || !strings.Contains(err.Error(), "both use public port 443") {
		t.Fatalf("collision error = %v", err)
	}
	if validated != 0 {
		t.Fatalf("validated %d candidates before collision preflight completed", validated)
	}
}

func TestRunCheckRejectsPublicManagementPortCollision(t *testing.T) {
	path := writeMultiCheckConfig(t, 2)
	validated := 0
	fetch := func(_ context.Context, cfg config.Config, _ io.Writer) (checkCandidate, error) {
		port := uint16(4000 + cfg.Panel.NodeID)
		if cfg.Panel.NodeID == 1 {
			port = 12002
		}
		if err := app.ValidatePublicManagementPort(int(port), cfg.ProtectedManagement); err != nil {
			return checkCandidate{}, err
		}
		return checkCandidate{config: cfg, compiled: app.CompiledState{Node: engine.NodeSpec{Protocol: "vless", Port: port}}}, nil
	}
	validate := func(context.Context, checkCandidate, io.Writer, io.Writer, bool) error {
		validated++
		return nil
	}
	err := runCheckWith([]string{"--config", path, "--render-only"}, io.Discard, io.Discard, fetch, validate)
	if err == nil || !strings.Contains(err.Error(), "conflicts with protected management") {
		t.Fatalf("management collision error = %v", err)
	}
	if validated != 0 {
		t.Fatalf("validated %d candidates after management collision", validated)
	}
}

func TestRunCheckGivesEachNodeAndValidationAFreshTimeout(t *testing.T) {
	path := writeMultiCheckConfig(t, 2)
	var fetchDeadlines, validationDeadlines []time.Time
	fetch := func(ctx context.Context, cfg config.Config, _ io.Writer) (checkCandidate, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			return checkCandidate{}, errors.New("missing node fetch deadline")
		}
		fetchDeadlines = append(fetchDeadlines, deadline)
		time.Sleep(100 * time.Millisecond)
		return checkCandidate{
			config:   cfg,
			compiled: app.CompiledState{Node: engine.NodeSpec{Protocol: "vless", Port: uint16(4000 + cfg.Panel.NodeID)}},
		}, nil
	}
	validate := func(ctx context.Context, _ checkCandidate, _ io.Writer, _ io.Writer, _ bool) error {
		deadline, ok := ctx.Deadline()
		if !ok {
			return errors.New("missing node validation deadline")
		}
		validationDeadlines = append(validationDeadlines, deadline)
		return nil
	}
	if err := runCheckWith([]string{"--config", path, "--timeout", "500ms", "--render-only"}, io.Discard, io.Discard, fetch, validate); err != nil {
		t.Fatal(err)
	}
	if len(fetchDeadlines) != 2 || len(validationDeadlines) != 2 {
		t.Fatalf("fetch deadlines = %v, validation deadlines = %v", fetchDeadlines, validationDeadlines)
	}
	if advance := fetchDeadlines[1].Sub(fetchDeadlines[0]); advance < 75*time.Millisecond {
		t.Fatalf("second node inherited the first node's timeout budget: deadline advanced only %s", advance)
	}
	if advance := validationDeadlines[0].Sub(fetchDeadlines[1]); advance <= 0 {
		t.Fatalf("validation inherited the fetch deadline: advance %s", advance)
	}
}

func TestRunCheckRejectsNonPositiveTimeout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := runCheckWith([]string{"--timeout", "0s"}, &stdout, &stderr, nil, nil); err == nil || !strings.Contains(err.Error(), "must be positive") {
		t.Fatalf("zero timeout error = %v", err)
	}
}
