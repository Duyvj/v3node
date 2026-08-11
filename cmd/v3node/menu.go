package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	maxMenuSelections = 100
	maxMenuInputBytes = 4096
)

type interactiveMenuEntry struct {
	name        string
	description string
	confirm     bool
}

var interactiveMenuEntries = []interactiveMenuEntry{
	{name: "start", description: "start the service"},
	{name: "stop", description: "stop the service"},
	{name: "restart", description: "restart the service"},
	{name: "status", description: "show service status"},
	{name: "enable", description: "enable service start at boot"},
	{name: "disable", description: "disable service start at boot"},
	{name: "log", description: "show recent service logs"},
	{name: "generate", description: "generate local configuration"},
	{name: "config", description: "edit and validate local configuration"},
	{name: "update", description: "install a verified release"},
	{name: "uninstall", description: "run the safe uninstaller", confirm: true},
	{name: "tune", description: "show host tuning status"},
	{name: "version", description: "print build information"},
	{name: "exit", description: "leave the menu"},
}

func readerIsTerminal(reader io.Reader) bool {
	file, ok := reader.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func runInteractiveMenu(stdin io.Reader, stdout, stderr io.Writer, dispatch func([]string) int) int {
	fmt.Fprintln(stdout, "v3node command menu")
	for index, entry := range interactiveMenuEntries {
		fmt.Fprintf(stdout, "%2d) %-9s %s\n", index+1, entry.name, entry.description)
	}
	for selection := 0; selection < maxMenuSelections; selection++ {
		fmt.Fprint(stdout, "Select a command: ")
		line, err := readBoundedMenuLine(stdin)
		if err != nil {
			if errors.Is(err, io.EOF) {
				if line == "" {
					return 0
				}
				err = nil
			} else {
				fmt.Fprintf(stderr, "v3node: menu input failed: %v\n", err)
				return 2
			}
		}
		entry, ok := resolveMenuEntry(line)
		if !ok {
			fmt.Fprintln(stderr, "v3node: choose a listed number or command")
			continue
		}
		if entry.name == "exit" {
			return 0
		}
		if entry.confirm {
			fmt.Fprintf(stdout, "Type yes to run %s: ", entry.name)
			confirmation, readErr := readBoundedMenuLine(stdin)
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				fmt.Fprintf(stderr, "v3node: menu confirmation failed: %v\n", readErr)
				return 2
			}
			if !strings.EqualFold(strings.TrimSpace(confirmation), "yes") {
				fmt.Fprintf(stdout, "%s cancelled\n", entry.name)
				continue
			}
		}
		commandArgs := []string{entry.name}
		if entry.name == "generate" {
			generatedArgs, promptErr := promptGenerateArgs(stdin, stdout)
			if promptErr != nil {
				fmt.Fprintf(stderr, "v3node: generate prompt failed: %v\n", promptErr)
				return 2
			}
			commandArgs = append(commandArgs, generatedArgs...)
		}
		if status := dispatch(commandArgs); status != 0 {
			fmt.Fprintf(stderr, "v3node: %s exited with status %d\n", entry.name, status)
		}
	}
	fmt.Fprintln(stderr, "v3node: menu selection limit reached")
	return 2
}

func promptGenerateArgs(stdin io.Reader, stdout io.Writer) ([]string, error) {
	read := func(prompt string) (string, error) {
		fmt.Fprint(stdout, prompt)
		value, err := readBoundedMenuLine(stdin)
		if err != nil && !(errors.Is(err, io.EOF) && value != "") {
			return "", err
		}
		return strings.TrimSpace(value), nil
	}
	panelURL, err := read("Panel HTTPS URL: ")
	if err != nil {
		return nil, err
	}
	nodeID, err := read("Node ID: ")
	if err != nil {
		return nil, err
	}
	tokenSource, err := read("Token source file (blank to create later): ")
	if err != nil {
		return nil, err
	}
	if panelURL == "" || nodeID == "" {
		return nil, errors.New("panel URL and node ID are required")
	}
	args := []string{"--panel-url", panelURL, "--node-id", nodeID}
	if tokenSource != "" {
		args = append(args, "--token-source", tokenSource)
	}
	return args, nil
}

func resolveMenuEntry(input string) (interactiveMenuEntry, bool) {
	input = strings.ToLower(strings.TrimSpace(input))
	if number, err := strconv.Atoi(input); err == nil && number >= 1 && number <= len(interactiveMenuEntries) {
		return interactiveMenuEntries[number-1], true
	}
	for _, entry := range interactiveMenuEntries {
		if input == entry.name {
			return entry, true
		}
	}
	return interactiveMenuEntry{}, false
}

func readBoundedMenuLine(reader io.Reader) (string, error) {
	var line []byte
	buffer := []byte{0}
	for {
		count, err := reader.Read(buffer)
		if count > 0 {
			switch buffer[0] {
			case '\n':
				return strings.TrimSuffix(string(line), "\r"), nil
			default:
				if len(line) == maxMenuInputBytes {
					return "", errors.New("selection is too long")
				}
				line = append(line, buffer[0])
			}
		}
		if err != nil {
			return string(line), err
		}
		if count == 0 {
			return string(line), io.ErrNoProgress
		}
	}
}
