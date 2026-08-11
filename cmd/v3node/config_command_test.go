package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRunConfigValidatesThenRestartsAndKeepsBoundedBackup(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	original := []byte("old configuration\n")
	edited := []byte("new configuration\n")
	if err := os.WriteFile(configPath, original, 0o640); err != nil {
		t.Fatal(err)
	}
	var events []string
	deps := testConfigDeps()
	deps.editor = func(_ context.Context, executable, path string, _ io.Reader, _, _ io.Writer) error {
		events = append(events, "editor:"+executable)
		return os.WriteFile(path, edited, 0o640)
	}
	deps.check = func(args []string, _, _ io.Writer) error {
		events = append(events, "check:"+strings.Join(args, " "))
		return nil
	}
	deps.service = func(action string, args []string, _ io.Reader, _, _ io.Writer) error {
		events = append(events, "service:"+action)
		if len(args) != 0 {
			t.Fatalf("service args = %#v", args)
		}
		return nil
	}
	var stdout, stderr bytes.Buffer
	if err := runConfigWithDeps([]string{"--config", configPath}, strings.NewReader(""), &stdout, &stderr, deps); err != nil {
		t.Fatalf("config: %v (%s)", err, stderr.String())
	}
	expectedEvents := []string{
		"editor:/usr/bin/test-editor",
		"check:--config " + configPath,
		"service:restart",
	}
	if !reflect.DeepEqual(events, expectedEvents) {
		t.Fatalf("events = %#v, want %#v", events, expectedEvents)
	}
	assertFileContents(t, configPath, edited)
	assertFileContents(t, configPath+".bak", original)
}

func TestRunConfigValidationFailureRestoresWithoutRestart(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	original := []byte("old configuration\n")
	secret := "new-secret-token"
	if err := os.WriteFile(configPath, original, 0o640); err != nil {
		t.Fatal(err)
	}
	deps := testConfigDeps()
	deps.editor = func(_ context.Context, _, path string, _ io.Reader, _, _ io.Writer) error {
		return os.WriteFile(path, []byte(secret), 0o640)
	}
	deps.check = func([]string, io.Writer, io.Writer) error { return errors.New("invalid configuration") }
	deps.service = func(string, []string, io.Reader, io.Writer, io.Writer) error {
		t.Fatal("service restarted after failed validation")
		return nil
	}
	var stdout, stderr bytes.Buffer
	err := runConfigWithDeps([]string{"--config", configPath}, strings.NewReader(""), &stdout, &stderr, deps)
	if err == nil || !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("error = %v", err)
	}
	assertFileContents(t, configPath, original)
	if strings.Contains(stdout.String()+stderr.String()+err.Error(), secret) {
		t.Fatal("secret appeared in command output")
	}
}

func TestRunConfigRestartFailureRestoresAndRestartsOldConfig(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	original := []byte("old configuration\n")
	if err := os.WriteFile(configPath, original, 0o640); err != nil {
		t.Fatal(err)
	}
	deps := testConfigDeps()
	deps.editor = func(_ context.Context, _, path string, _ io.Reader, _, _ io.Writer) error {
		return os.WriteFile(path, []byte("new configuration\n"), 0o640)
	}
	restarts := 0
	deps.service = func(action string, _ []string, _ io.Reader, _, _ io.Writer) error {
		if action != "restart" {
			t.Fatalf("action = %q", action)
		}
		restarts++
		if restarts == 1 {
			return errors.New("restart rejected")
		}
		return nil
	}
	err := runConfigWithDeps([]string{"--config", configPath}, strings.NewReader(""), io.Discard, io.Discard, deps)
	if err == nil || !strings.Contains(err.Error(), "restart edited configuration") {
		t.Fatalf("error = %v", err)
	}
	if restarts != 2 {
		t.Fatalf("restart calls = %d, want 2", restarts)
	}
	assertFileContents(t, configPath, original)
}

func TestRunConfigRejectsUnsafeEditorBeforeEditing(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	if err := os.WriteFile(configPath, []byte("original\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	deps := testConfigDeps()
	deps.getenv = func(name string) string {
		if name == "SUDO_EDITOR" {
			return "/usr/bin/vi --cmd unsafe"
		}
		return ""
	}
	deps.editor = func(context.Context, string, string, io.Reader, io.Writer, io.Writer) error {
		t.Fatal("unsafe editor was executed")
		return nil
	}
	err := runConfigWithDeps([]string{"--config", configPath}, strings.NewReader(""), io.Discard, io.Discard, deps)
	if err == nil || !strings.Contains(err.Error(), "SUDO_EDITOR") {
		t.Fatalf("error = %v", err)
	}
	if _, err := os.Stat(configPath + ".bak"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup created before editor refusal: %v", err)
	}
}

func TestReadRegularConfigRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxEditableConfigBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readRegularConfig(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v", err)
	}
}

func testConfigDeps() configCommandDeps {
	return configCommandDeps{
		goos:   "linux",
		getenv: func(string) string { return "/usr/bin/test-editor" },
		editor: func(context.Context, string, string, io.Reader, io.Writer, io.Writer) error { return nil },
		check:  func([]string, io.Writer, io.Writer) error { return nil },
		service: func(string, []string, io.Reader, io.Writer, io.Writer) error {
			return nil
		},
	}
}
