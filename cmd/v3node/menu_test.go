package main

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestRunCLINoArgsNonTTYPrintsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if status := runCLI(nil, strings.NewReader(""), &stdout, &stderr, false); status != 2 {
		t.Fatalf("status = %d, want 2", status)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "Usage: v3node") {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestInteractiveMenuDispatchesOnlyListedBareCommands(t *testing.T) {
	var calls [][]string
	var stdout, stderr bytes.Buffer
	status := runInteractiveMenu(strings.NewReader("not-a-command\n13\n14\n"), &stdout, &stderr, func(args []string) int {
		calls = append(calls, append([]string(nil), args...))
		return 0
	})
	if status != 0 {
		t.Fatalf("status = %d", status)
	}
	if expected := [][]string{{"version"}}; !reflect.DeepEqual(calls, expected) {
		t.Fatalf("calls = %#v, want %#v", calls, expected)
	}
	if !strings.Contains(stderr.String(), "choose a listed") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestInteractiveMenuBoundsInput(t *testing.T) {
	input := strings.Repeat("x", maxMenuInputBytes+1) + "\n"
	if status := runInteractiveMenu(strings.NewReader(input), io.Discard, io.Discard, func([]string) int { return 0 }); status != 2 {
		t.Fatalf("status = %d, want 2", status)
	}
}

func TestInteractiveMenuConfirmsUninstall(t *testing.T) {
	var calls [][]string
	input := "uninstall\nno\nuninstall\nyes\nexit\n"
	status := runInteractiveMenu(strings.NewReader(input), io.Discard, io.Discard, func(args []string) int {
		calls = append(calls, append([]string(nil), args...))
		return 0
	})
	if status != 0 {
		t.Fatalf("status = %d", status)
	}
	if expected := [][]string{{"uninstall"}}; !reflect.DeepEqual(calls, expected) {
		t.Fatalf("calls = %#v, want %#v", calls, expected)
	}
}

func TestInteractiveMenuPromptsForGenerateArguments(t *testing.T) {
	var calls [][]string
	input := "generate\nhttps://panel.example.com\n42\n/etc/v3node/source.token\nexit\n"
	status := runInteractiveMenu(strings.NewReader(input), io.Discard, io.Discard, func(args []string) int {
		calls = append(calls, append([]string(nil), args...))
		return 0
	})
	if status != 0 {
		t.Fatalf("status = %d", status)
	}
	expected := [][]string{{
		"generate", "--panel-url", "https://panel.example.com", "--node-id", "42",
		"--token-source", "/etc/v3node/source.token",
	}}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("calls = %#v, want %#v", calls, expected)
	}
}

func TestInteractiveMenuPromptsForMultipleGenerateNodeIDs(t *testing.T) {
	var calls [][]string
	input := "generate\nhttps://panel.example.com\n42, 43 44\n/etc/v3node/source.token\nexit\n"
	status := runInteractiveMenu(strings.NewReader(input), io.Discard, io.Discard, func(args []string) int {
		calls = append(calls, append([]string(nil), args...))
		return 0
	})
	if status != 0 {
		t.Fatalf("status = %d", status)
	}
	expected := [][]string{{
		"generate", "--panel-url", "https://panel.example.com",
		"--node-id", "42", "--node-id", "43", "--node-id", "44",
		"--token-source", "/etc/v3node/source.token",
	}}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("calls = %#v, want %#v", calls, expected)
	}
}
