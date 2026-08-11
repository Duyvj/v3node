package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	"github.com/Duyvj/v3node/internal/config"
)

const maxEditableConfigBytes = 1 << 20

type configCommandDeps struct {
	goos    string
	getenv  func(string) string
	editor  func(context.Context, string, string, io.Reader, io.Writer, io.Writer) error
	check   func([]string, io.Writer, io.Writer) error
	service func(string, []string, io.Reader, io.Writer, io.Writer) error
}

func defaultConfigCommandDeps() configCommandDeps {
	return configCommandDeps{
		goos:   runtime.GOOS,
		getenv: os.Getenv,
		editor: func(ctx context.Context, executable, path string, stdin io.Reader, stdout, stderr io.Writer) error {
			return executeAdminCommand(ctx, stdin, stdout, stderr, executable, path)
		},
		check:   runConfigCheck,
		service: runServiceCommand,
	}
}

func runConfigCheck(args []string, stdout, stderr io.Writer) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return runCheck(args, stdout, stderr)
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate v3node executable: %w", err)
	}
	commandArgs := []string{"-u", "v3node", "--", executable, "check"}
	commandArgs = append(commandArgs, args...)
	if err := executeAdminCommand(context.Background(), nil, stdout, stderr, "/usr/sbin/runuser", commandArgs...); err != nil {
		return fmt.Errorf("validate as v3node service user: %w", err)
	}
	return nil
}

func runConfig(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runConfigWithDeps(args, stdin, stdout, stderr, defaultConfigCommandDeps())
}

func runConfigWithDeps(args []string, stdin io.Reader, stdout, stderr io.Writer, deps configCommandDeps) error {
	if deps.goos != "linux" {
		return errors.New("configuration editing is supported only on Linux")
	}
	flags := flag.NewFlagSet("config", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", config.DefaultPath(), "absolute local JSON configuration path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("config does not accept positional arguments")
	}
	if !isAbsoluteAdminPath(*configPath) {
		return errors.New("config path must be absolute")
	}

	editor, err := selectConfigEditor(deps.getenv)
	if err != nil {
		return err
	}
	original, mode, err := readRegularConfig(*configPath)
	if err != nil {
		return fmt.Errorf("inspect configuration: %w", err)
	}
	backupPath := *configPath + ".bak"
	if err := writeAdminFiles([]adminFileWrite{{path: backupPath, data: original, mode: mode.Perm()}}, true, false); err != nil {
		return fmt.Errorf("preserve configuration backup: %w", err)
	}

	if err := deps.editor(context.Background(), editor, *configPath, stdin, stdout, stderr); err != nil {
		return restoreAfterConfigFailure(*configPath, original, mode, fmt.Errorf("editor failed: %w", err))
	}
	if _, _, err := readRegularConfig(*configPath); err != nil {
		return restoreAfterConfigFailure(*configPath, original, mode, fmt.Errorf("edited configuration is unsafe: %w", err))
	}
	if err := os.Chmod(*configPath, mode.Perm()); err != nil {
		return restoreAfterConfigFailure(*configPath, original, mode, fmt.Errorf("restore configuration mode: %w", err))
	}
	if err := setServiceGroup(*configPath); err != nil {
		return restoreAfterConfigFailure(*configPath, original, mode, fmt.Errorf("restore configuration ownership: %w", err))
	}
	if err := deps.check([]string{"--config", *configPath}, stdout, stderr); err != nil {
		return restoreAfterConfigFailure(*configPath, original, mode, fmt.Errorf("validation failed: %w", err))
	}
	if err := deps.service("restart", nil, stdin, stdout, stderr); err != nil {
		restartErr := fmt.Errorf("restart edited configuration: %w", err)
		if restoreErr := restoreConfig(*configPath, original, mode); restoreErr != nil {
			return errors.Join(restartErr, fmt.Errorf("restore configuration: %w", restoreErr))
		}
		if recoveryErr := deps.service("restart", nil, stdin, stdout, stderr); recoveryErr != nil {
			return errors.Join(restartErr, fmt.Errorf("restart restored configuration: %w", recoveryErr))
		}
		return restartErr
	}
	fmt.Fprintf(stdout, "configuration validated and service restarted; backup: %s\n", backupPath)
	return nil
}

func selectConfigEditor(getenv func(string) string) (string, error) {
	for _, name := range []string{"SUDO_EDITOR", "VISUAL", "EDITOR"} {
		if value := getenv(name); value != "" {
			if !safeEditorExecutable(value) {
				return "", fmt.Errorf("%s must name one absolute editor executable without arguments", name)
			}
			return value, nil
		}
	}
	return "/usr/bin/editor", nil
}

func safeEditorExecutable(value string) bool {
	if len(value) == 0 || len(value) > 4096 || strings.TrimSpace(value) != value || !isAbsoluteAdminPath(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsSpace(character) || strings.ContainsRune(";&|<>`$(){}[]!*?~\x00", character) {
			return false
		}
	}
	cleaned := filepath.Clean(value)
	if strings.HasPrefix(value, "/") {
		cleaned = path.Clean(value)
	}
	return cleaned == value
}

func readRegularConfig(path string) ([]byte, os.FileMode, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, 0, errors.New("configuration is not a regular file")
	}
	if before.Size() > maxEditableConfigBytes {
		return nil, 0, fmt.Errorf("configuration exceeds %d bytes", maxEditableConfigBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, 0, errors.New("configuration changed while opening it")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxEditableConfigBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if len(data) > maxEditableConfigBytes {
		return nil, 0, fmt.Errorf("configuration exceeds %d bytes", maxEditableConfigBytes)
	}
	return data, before.Mode(), nil
}

func restoreAfterConfigFailure(path string, original []byte, mode os.FileMode, cause error) error {
	if err := restoreConfig(path, original, mode); err != nil {
		return errors.Join(cause, fmt.Errorf("restore configuration: %w", err))
	}
	return cause
}

func restoreConfig(path string, original []byte, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			if err := os.Remove(path); err != nil {
				return err
			}
		} else if !info.Mode().IsRegular() {
			return errors.New("edited configuration path is not replaceable")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeAdminFiles([]adminFileWrite{{path: path, data: original, mode: mode.Perm()}}, true, false); err != nil {
		return err
	}
	// The standard installed config is root:v3node 0640. Atomic replacement
	// creates a root-owned temporary file, so restore the service-readable group
	// before attempting to restart the previous generation.
	return setServiceGroup(path)
}
