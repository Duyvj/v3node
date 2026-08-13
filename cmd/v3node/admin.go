package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Duyvj/v3node/internal/config"
	"github.com/Duyvj/v3node/internal/updater"
)

const (
	serviceName       = "v3node.service"
	systemctlPath     = "/usr/bin/systemctl"
	journalctlPath    = "/usr/bin/journalctl"
	bashPath          = "/usr/bin/bash"
	uninstallerPath   = "/usr/local/sbin/v3node-uninstall"
	tuningHelperPath  = "/usr/local/lib/v3node/v3node-tune"
	xrayBinaryPath    = "/usr/local/lib/v3node/xray"
	maxGeneratedToken = 16 << 10
)

var executeAdminCommand = func(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}

var renameAdminFile = os.Rename

func runServiceCommand(action string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if runtime.GOOS != "linux" {
		return errors.New("service management is supported only on Linux")
	}
	if len(args) != 0 {
		return fmt.Errorf("v3node %s does not accept arguments", action)
	}
	commandArgs, err := serviceCommandArgs(action)
	if err != nil {
		return err
	}
	if err := executeAdminCommand(context.Background(), stdin, stdout, stderr, systemctlPath, commandArgs...); err != nil {
		return fmt.Errorf("systemctl %s: %w", action, err)
	}
	return nil
}

func serviceCommandArgs(action string) ([]string, error) {
	switch action {
	case "start", "stop", "restart", "enable", "disable":
		return []string{action, serviceName}, nil
	case "status":
		return []string{"status", serviceName, "--no-pager", "--full"}, nil
	default:
		return nil, fmt.Errorf("unsupported service action %q", action)
	}
}

func runLogs(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if runtime.GOOS != "linux" {
		return errors.New("journal logs are supported only on Linux")
	}
	flags := flag.NewFlagSet("log", flag.ContinueOnError)
	flags.SetOutput(stderr)
	lines := flags.Int("lines", 100, "number of recent journal lines")
	follow := flags.Bool("follow", false, "continue following new journal entries")
	since := flags.String("since", "", "journalctl-compatible start time")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *lines < 1 || *lines > 100_000 {
		return errors.New("log requires --lines between 1 and 100000 and no positional arguments")
	}
	commandArgs := []string{"-u", serviceName, "-n", strconv.Itoa(*lines), "--no-pager"}
	if *since != "" {
		if len(*since) > 128 || strings.ContainsAny(*since, "\r\n") {
			return errors.New("log --since is invalid")
		}
		commandArgs = append(commandArgs, "--since", *since)
	}
	if *follow {
		commandArgs = append(commandArgs, "--follow")
	}
	if err := executeAdminCommand(context.Background(), stdin, stdout, stderr, journalctlPath, commandArgs...); err != nil {
		return fmt.Errorf("journalctl: %w", err)
	}
	return nil
}

func runUninstall(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	for _, argument := range args {
		switch argument {
		case "--purge", "--remove-tuning", "--help", "-h":
		default:
			return fmt.Errorf("unsupported uninstall option %q", argument)
		}
	}
	if err := executeAdminCommand(context.Background(), stdin, stdout, stderr, uninstallerPath, args...); err != nil {
		return fmt.Errorf("uninstall: %w", err)
	}
	return nil
}

func runX25519(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if runtime.GOOS != "linux" {
		return errors.New("x25519 generation is supported only on Linux")
	}
	for _, argument := range args {
		if len(argument) > 4096 || strings.ContainsAny(argument, "\x00\r\n") {
			return errors.New("x25519 contains an invalid argument")
		}
	}
	commandArgs := append([]string{"x25519"}, args...)
	if err := executeAdminCommand(context.Background(), stdin, stdout, stderr, xrayBinaryPath, commandArgs...); err != nil {
		return fmt.Errorf("generate x25519 key pair: %w", err)
	}
	return nil
}

func runUpdate(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if runtime.GOOS != "linux" {
		return errors.New("self-update is supported only on Linux")
	}
	if os.Geteuid() != 0 {
		return errors.New("self-update requires root; run sudo v3node update")
	}
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	flags.SetOutput(stderr)
	requested := flags.String("version", "", "release tag or version; default is the newest published release")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 1 {
		return errors.New("update accepts at most one positional version")
	}
	if flags.NArg() == 1 {
		if *requested != "" {
			return errors.New("set the update version either positionally or with --version, not both")
		}
		*requested = flags.Arg(0)
	}
	downloadCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	result, err := updater.DownloadInstaller(downloadCtx, updater.Options{
		Version:           *requested,
		UserAgent:         "v3node/" + version,
		IncludePrerelease: strings.Contains(version, "-"),
	})
	cancel()
	if err != nil {
		return err
	}
	defer os.Remove(result.Path)
	fmt.Fprintf(stdout, "verified release %s; running transactional installer\n", result.Tag)
	if err := executeAdminCommand(context.Background(), stdin, stdout, stderr, bashPath, result.Path); err != nil {
		return fmt.Errorf("install release %s: %w", result.Tag, err)
	}
	return nil
}

func runGenerate(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("generate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", config.DefaultPath(), "destination local JSON configuration")
	panelURL := flags.String("panel-url", "", "V2Board-compatible panel base URL")
	var nodeIDs nodeIDFlags
	flags.Var(&nodeIDs, "node-id", "positive panel node ID; repeat for multiple nodes")
	tokenFile := flags.String("token-file", "/etc/v3node/panel.token", "installed panel token path")
	tokenSource := flags.String("token-source", "", "copy token from this file without exposing it in argv")
	allowHTTP := flags.Bool("allow-insecure-http", false, "allow an HTTP panel URL")
	force := flags.Bool("force", false, "replace an existing generated config/token")
	skipOwnership := flags.Bool("skip-ownership", false, "leave ownership unchanged for installer staging")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("generate does not accept positional arguments")
	}
	parsed, err := url.Parse(*panelURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("generate --panel-url must be an absolute base URL without credentials, query, or fragment")
	}
	if parsed.Scheme != "https" && !(*allowHTTP && parsed.Scheme == "http") {
		return errors.New("generate --panel-url must use HTTPS unless --allow-insecure-http is set")
	}
	if len(nodeIDs) == 0 {
		return errors.New("generate --node-id must be positive")
	}
	for _, nodeID := range nodeIDs {
		if nodeID <= 0 {
			return errors.New("generate --node-id must be positive")
		}
	}
	if duplicate := duplicateNodeID(nodeIDs); duplicate != 0 {
		return fmt.Errorf("generate --node-id %d was supplied more than once", duplicate)
	}
	if len(nodeIDs) > 16 {
		return errors.New("generate supports at most 16 node IDs")
	}
	if !isAbsoluteAdminPath(*configPath) || !isAbsoluteAdminPath(*tokenFile) {
		return errors.New("generate config and token paths must be absolute")
	}
	if sameAdminPath(*configPath, *tokenFile) {
		return errors.New("generate config and token paths must be different")
	}

	var token []byte
	if *tokenSource != "" {
		token, err = readTokenSource(*tokenSource)
		if err != nil {
			return err
		}
	}

	generated := config.Defaults()
	cleanPanelURL := strings.TrimRight(*panelURL, "/")
	var document any
	if len(nodeIDs) == 1 {
		// Keep the original single-node document shape byte-for-byte compatible.
		generated.Panel = config.PanelConfig{
			URL:               cleanPanelURL,
			NodeID:            nodeIDs[0],
			TokenFile:         *tokenFile,
			AllowInsecureHTTP: *allowHTTP,
		}
		validation := generated
		validation.Panel.TokenFile = ""
		validation.Panel.Token = "validation-placeholder"
		if err := validation.Validate(); err != nil {
			return fmt.Errorf("generated configuration is invalid: %w", err)
		}
		document = generated
	} else {
		nodes, buildErr := buildGeneratedNodes(cleanPanelURL, nodeIDs, *tokenFile, generated.Engine)
		if buildErr != nil {
			return fmt.Errorf("generate multi-node configuration: %w", buildErr)
		}
		generated.Nodes = make([]config.NodeEntry, 0, len(nodes))
		for _, node := range nodes {
			generated.Nodes = append(generated.Nodes, config.NodeEntry{
				Name:        node.Name,
				APIHost:     node.APIHost,
				NodeID:      node.NodeID,
				TokenFile:   node.TokenFile,
				AllowHTTP:   node.AllowHTTP,
				StateDir:    node.StateDir,
				StatsListen: node.StatsListen,
				ClashListen: node.ClashListen,
			})
		}
		validation := generated
		for index := range validation.Nodes {
			validation.Nodes[index].TokenFile = ""
			validation.Nodes[index].APIKey = "validation-placeholder"
		}
		if err := validation.Validate(); err != nil {
			return fmt.Errorf("generated configuration is invalid: %w", err)
		}
		multiDocument := generatedMultiConfig{
			Nodes:   nodes,
			Engine:  generated.Engine,
			Runtime: generated.Runtime,
			Network: generated.Network,
		}
		document = multiDocument
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("encode generated configuration: %w", err)
	}
	data = append(data, '\n')

	if err := prepareGeneratedConfigDirectory(filepath.Dir(*configPath), *skipOwnership); err != nil {
		return err
	}
	writes := []adminFileWrite{{path: *configPath, data: data, mode: 0o640}}
	if *tokenSource != "" {
		writes = append(writes, adminFileWrite{path: *tokenFile, data: token, mode: 0o640})
	}
	if err := writeAdminFiles(writes, *force, !*skipOwnership); err != nil {
		return fmt.Errorf("commit generated files: %w", err)
	}
	if len(nodeIDs) == 1 {
		fmt.Fprintf(stdout, "generated %s for node %d\n", *configPath, nodeIDs[0])
	} else {
		fmt.Fprintf(stdout, "generated %s for %d nodes\n", *configPath, len(nodeIDs))
	}
	if *tokenSource == "" {
		fmt.Fprintf(stdout, "create %s as root:v3node mode 0640 before running check\n", *tokenFile)
	}
	fmt.Fprintf(stdout, "next: sudo -u v3node v3node check --config %s\n", *configPath)
	return nil
}

type nodeIDFlags []int64

func (values *nodeIDFlags) String() string {
	if values == nil || len(*values) == 0 {
		return ""
	}
	parts := make([]string, 0, len(*values))
	for _, value := range *values {
		parts = append(parts, strconv.FormatInt(value, 10))
	}
	return strings.Join(parts, ",")
}

func (values *nodeIDFlags) Set(value string) error {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return errors.New("node ID must be an integer")
	}
	*values = append(*values, parsed)
	return nil
}

func duplicateNodeID(values []int64) int64 {
	seen := make(map[int64]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return value
		}
		seen[value] = struct{}{}
	}
	return 0
}

type generatedMultiConfig struct {
	Nodes   []generatedNode      `json:"nodes"`
	Engine  config.EngineConfig  `json:"engine"`
	Runtime config.RuntimeConfig `json:"runtime"`
	Network config.NetworkConfig `json:"network"`
}

type generatedNode struct {
	Name        string `json:"name"`
	APIHost     string `json:"api_host"`
	NodeID      int64  `json:"node_id"`
	TokenFile   string `json:"token_file"`
	AllowHTTP   bool   `json:"allow_insecure_http,omitempty"`
	StateDir    string `json:"state_dir"`
	StatsListen string `json:"stats_listen"`
	ClashListen string `json:"clash_listen"`
}

func buildGeneratedNodes(panelURL string, nodeIDs []int64, tokenFile string, engine config.EngineConfig) ([]generatedNode, error) {
	nodes := make([]generatedNode, 0, len(nodeIDs))
	descriptors := make([]config.NodeEntry, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		// A repeated --node-id list does not identify which entry, if any,
		// owned a previous singleton checkpoint. Never guess: replaying the
		// singleton's traffic or last-known-good state under the wrong panel
		// node is worse than leaving that legacy state untouched.
		node := generatedNode{
			APIHost:   panelURL,
			NodeID:    nodeID,
			TokenFile: tokenFile,
			AllowHTTP: strings.HasPrefix(strings.ToLower(panelURL), "http://"),
		}
		nodes = append(nodes, node)
		descriptors = append(descriptors, config.NodeEntry{
			Name:        node.Name,
			APIHost:     node.APIHost,
			NodeID:      node.NodeID,
			APIKey:      "validation-placeholder",
			AllowHTTP:   node.AllowHTTP,
			StateDir:    node.StateDir,
			StatsListen: node.StatsListen,
			ClashListen: node.ClashListen,
		})
	}
	// Resolve every derived endpoint now and persist it in the generated JSON.
	// This makes the node-to-state mapping independent of descriptor order and
	// of future changes to config expansion defaults.
	isolation := config.Config{Nodes: descriptors, Engine: engine}
	workers, err := isolation.NodeConfigs()
	if err != nil {
		return nil, err
	}
	for index := range nodes {
		nodes[index].Name = workers[index].NodeName()
		nodes[index].StateDir = workers[index].Engine.StateDir
		nodes[index].StatsListen = workers[index].Engine.StatsListen
		nodes[index].ClashListen = workers[index].Engine.ClashListen
	}
	return nodes, nil
}

func readTokenSource(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open token source: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxGeneratedToken+1))
	if err != nil {
		return nil, fmt.Errorf("read token source: %w", err)
	}
	if len(data) > maxGeneratedToken {
		return nil, errors.New("token source is too large")
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("token source is empty")
	}
	return append(data, '\n'), nil
}

type adminFileWrite struct {
	path string
	data []byte
	mode os.FileMode
}

type stagedAdminFile struct {
	write       adminFileWrite
	temporary   string
	backup      string
	hadOriginal bool
	committed   bool
}

func writeAdminFiles(writes []adminFileWrite, replace, serviceOwnership bool) error {
	staged := make([]stagedAdminFile, len(writes))
	for i, write := range writes {
		hadOriginal, err := validateAdminDestination(write.path, replace)
		if err != nil {
			return fmt.Errorf("validate %s: %w", write.path, err)
		}
		staged[i] = stagedAdminFile{write: write, hadOriginal: hadOriginal}
	}
	defer func() {
		for i := range staged {
			if staged[i].temporary != "" {
				_ = os.Remove(staged[i].temporary)
			}
		}
	}()
	for i := range staged {
		name, err := stageAdminFile(staged[i].write, serviceOwnership)
		if err != nil {
			return fmt.Errorf("stage %s: %w", staged[i].write.path, err)
		}
		staged[i].temporary = name
	}
	if err := commitAdminFiles(staged); err != nil {
		return err
	}
	return nil
}

func validateAdminDestination(path string, replace bool) (bool, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return false, errors.New("destination is not a regular file")
		}
		if !replace {
			return false, errors.New("destination already exists; use --force to replace it")
		}
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return false, nil
}

func stageAdminFile(write adminFileWrite, serviceOwnership bool) (string, error) {
	directory := filepath.Dir(write.path)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return "", err
	}
	temporary, err := os.CreateTemp(directory, ".v3node-generate-*")
	if err != nil {
		return "", err
	}
	name := temporary.Name()
	defer func() {
		_ = temporary.Close()
	}()
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(name)
		}
	}()
	if err := temporary.Chmod(write.mode); err != nil {
		return "", err
	}
	if _, err := temporary.Write(write.data); err != nil {
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if serviceOwnership {
		if err := setServiceGroup(name); err != nil {
			return "", err
		}
	}
	remove = false
	return name, nil
}

func commitAdminFiles(staged []stagedAdminFile) error {
	for i := range staged {
		if staged[i].hadOriginal {
			backup, err := unusedAdminPath(filepath.Dir(staged[i].write.path), ".v3node-backup-*")
			if err != nil {
				return rollbackAdminFiles(staged, i-1, fmt.Errorf("prepare backup for %s: %w", staged[i].write.path, err))
			}
			if err := renameAdminFile(staged[i].write.path, backup); err != nil {
				return rollbackAdminFiles(staged, i-1, fmt.Errorf("back up %s: %w", staged[i].write.path, err))
			}
			staged[i].backup = backup
		}
		if err := renameAdminFile(staged[i].temporary, staged[i].write.path); err != nil {
			return rollbackAdminFiles(staged, i, fmt.Errorf("install %s: %w", staged[i].write.path, err))
		}
		staged[i].temporary = ""
		staged[i].committed = true
	}
	for i := range staged {
		if staged[i].backup != "" {
			if err := os.Remove(staged[i].backup); err != nil {
				return fmt.Errorf("remove backup for %s: %w", staged[i].write.path, err)
			}
			staged[i].backup = ""
		}
	}
	return nil
}

func rollbackAdminFiles(staged []stagedAdminFile, last int, cause error) error {
	var rollbackErrs []error
	for i := last; i >= 0; i-- {
		if staged[i].committed {
			if err := os.Remove(staged[i].write.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("remove new %s: %w", staged[i].write.path, err))
				continue
			}
			staged[i].committed = false
		}
		if staged[i].backup != "" {
			if err := renameAdminFile(staged[i].backup, staged[i].write.path); err != nil {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("restore %s: %w", staged[i].write.path, err))
				continue
			}
			staged[i].backup = ""
		}
	}
	if len(rollbackErrs) == 0 {
		return cause
	}
	return errors.Join(cause, fmt.Errorf("rollback generated files: %w", errors.Join(rollbackErrs...)))
}

func unusedAdminPath(directory, pattern string) (string, error) {
	file, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return "", err
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	if err := os.Remove(name); err != nil {
		return "", err
	}
	return name, nil
}

func prepareGeneratedConfigDirectory(directory string, skipOwnership bool) error {
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return fmt.Errorf("create generated config directory: %w", err)
	}
	if skipOwnership || runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return nil
	}
	if err := setServiceGroup(directory); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0o750); err != nil {
		return fmt.Errorf("set mode 0750 on %s: %w", directory, err)
	}
	return nil
}

func setServiceGroup(path string) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return nil
	}
	group, err := user.LookupGroup("v3node")
	if err != nil {
		return fmt.Errorf("look up v3node group: %w", err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return fmt.Errorf("parse v3node group ID: %w", err)
	}
	if err := os.Chown(path, 0, gid); err != nil {
		return fmt.Errorf("set root:v3node ownership on %s: %w", path, err)
	}
	return nil
}

func isAbsoluteAdminPath(value string) bool {
	return filepath.IsAbs(value) || (runtime.GOOS == "windows" && strings.HasPrefix(value, "/"))
}

func sameAdminPath(first, second string) bool {
	first = filepath.Clean(first)
	second = filepath.Clean(second)
	pathsEqual := func(left, right string) bool {
		if runtime.GOOS == "windows" {
			return strings.EqualFold(left, right)
		}
		return left == right
	}
	if pathsEqual(first, second) {
		return true
	}
	firstInfo, firstErr := os.Stat(first)
	secondInfo, secondErr := os.Stat(second)
	if firstErr == nil && secondErr == nil && os.SameFile(firstInfo, secondInfo) {
		return true
	}
	firstDirectory, firstErr := filepath.EvalSymlinks(filepath.Dir(first))
	secondDirectory, secondErr := filepath.EvalSymlinks(filepath.Dir(second))
	return firstErr == nil && secondErr == nil && pathsEqual(
		filepath.Join(firstDirectory, filepath.Base(first)),
		filepath.Join(secondDirectory, filepath.Base(second)),
	)
}
