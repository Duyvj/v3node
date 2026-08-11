package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/Duyvj/v3node/internal/app"
	"github.com/Duyvj/v3node/internal/config"
	"github.com/Duyvj/v3node/internal/engine"
	"github.com/Duyvj/v3node/internal/panel"
	noderuntime "github.com/Duyvj/v3node/internal/runtime"
)

var (
	version = "dev"
	commit  = "none"
	builtAt = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	switch args[0] {
	case "run":
		if err := runServer(args[1:], stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "v3node: %v\n", err)
			return 1
		}
		return 0
	case "check":
		if err := runCheck(args[1:], stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "v3node: check failed: %v\n", err)
			return 1
		}
		return 0
	case "diagnose":
		if err := runDiagnose(args[1:], stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "v3node: diagnose failed: %v\n", err)
			return 1
		}
		return 0
	case "tune":
		if err := runTune(args[1:], stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "v3node: tune failed: %v\n", err)
			return 1
		}
		return 0
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "v3node %s (commit %s, built %s, %s/%s)\n", version, commit, builtAt, runtime.GOOS, runtime.GOARCH)
		return 0
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "v3node: unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, "Usage: v3node <command> [options]")
	fmt.Fprintln(writer, "Commands:")
	fmt.Fprintln(writer, "  run       run the panel controller and protocol engine")
	fmt.Fprintln(writer, "  check     fetch, compile, and validate panel configuration")
	fmt.Fprintln(writer, "  diagnose  inspect local configuration without printing secrets")
	fmt.Fprintln(writer, "  tune      show or explicitly apply conservative host tuning")
	fmt.Fprintln(writer, "  version   print build information")
}

func configFlagSet(name string, stderr io.Writer) (*flag.FlagSet, *string) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", config.DefaultPath(), "local JSON configuration path")
	return flags, path
}

func runServer(args []string, stdout, stderr io.Writer) error {
	flags, configPath := configFlagSet("run", stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		if total := app.HostMemoryBytes(); total > 0 {
			debug.SetMemoryLimit(int64(config.EffectiveGOMEMLIMIT(total)))
		}
	}
	logger := log.New(stderr, "v3node: ", log.LstdFlags|log.LUTC|log.Lmsgprefix)
	panelClient, err := newPanelClient(cfg)
	if err != nil {
		return err
	}
	defer panelClient.Close()
	supervisor, err := noderuntime.NewSupervisor(noderuntime.SupervisorOptions{
		Directory:   filepath.Join(cfg.Engine.StateDir, "engine"),
		StopTimeout: cfg.Engine.StopTimeout.Duration,
		Stdout:      stdout,
		Stderr:      stderr,
		Logger:      logger,
		HealthProbe: func(ctx context.Context) error {
			var lastErr error
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", cfg.Engine.StatsListen)
				if err == nil {
					return connection.Close()
				}
				lastErr = err
				select {
				case <-ctx.Done():
					return fmt.Errorf("stats API is not listening: %w", lastErr)
				case <-ticker.C:
				}
			}
		},
	})
	if err != nil {
		return err
	}
	controller, err := app.NewController(app.ControllerOptions{
		Config:     cfg,
		Panel:      panelClient,
		Supervisor: supervisor,
		Logger:     logger,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return controller.Run(ctx)
}

func runCheck(args []string, stdout, stderr io.Writer) error {
	flags, configPath := configFlagSet("check", stderr)
	timeout := flags.Duration("timeout", 30*time.Second, "total online validation timeout")
	renderOnly := flags.Bool("render-only", false, "skip the engine binary check")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	client, err := newPanelClient(cfg)
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	node, changed, err := client.GetNodeConfig(ctx)
	if err != nil {
		return err
	}
	if !changed || node == nil {
		return errors.New("panel returned no node configuration")
	}
	users, changed, err := client.GetUsers(ctx)
	if err != nil {
		return err
	}
	if !changed {
		return errors.New("panel returned no user configuration")
	}
	compiled, err := app.CompileState(*node, users, cfg)
	if err != nil {
		return err
	}
	renderer, err := engine.Select(cfg.Engine.Backend, compiled.Node)
	if err != nil {
		return err
	}
	if err := app.ValidateBackendPolicies(renderer.Name(), compiled.Users); err != nil {
		return err
	}
	apiSecret, err := app.LoadOrCreateAPISecret(cfg.Engine.StateDir)
	if err != nil {
		return err
	}
	rendered, err := renderer.Render(compiled.Node, compiled.Users, engine.Options{
		LogLevel:        cfg.Runtime.LogLevel,
		StatsListen:     cfg.Engine.StatsListen,
		ClashListen:     cfg.Engine.ClashListen,
		ClashSecret:     apiSecret,
		AddressStrategy: cfg.Network.AddressStrategy,
		DNSServers:      cfg.Network.DNSServers,
		BlockPrivate:    cfg.Network.BlockPrivate != nil && *cfg.Network.BlockPrivate,
	})
	if err != nil {
		return err
	}
	if !*renderOnly {
		binary := cfg.Engine.SingBoxBinary
		if rendered.Backend == "xray" {
			binary = cfg.Engine.XrayBinary
		}
		if err := noderuntime.CheckEngineConfig(ctx, rendered.Backend, binary, rendered.Config, stderr); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "OK: backend=%s protocol=%s users=%d config_bytes=%d\n", rendered.Backend, compiled.Node.Protocol, len(compiled.Users), len(rendered.Config))
	return nil
}

func runDiagnose(args []string, stdout, stderr io.Writer) error {
	flags, configPath := configFlagSet("diagnose", stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "local_config=ok\nnode_id=%d\nengine_mode=%s\n", cfg.Panel.NodeID, cfg.Engine.Backend)
	for name, path := range map[string]string{"sing-box": cfg.Engine.SingBoxBinary, "xray": cfg.Engine.XrayBinary} {
		status := "missing"
		if info, statErr := os.Stat(path); statErr == nil && !info.IsDir() {
			status = "present"
		}
		fmt.Fprintf(stdout, "engine_%s=%s\n", name, status)
	}
	fmt.Fprintf(stdout, "stats_api=%s\nconnections_api=%s\n", cfg.Engine.StatsListen, cfg.Engine.ClashListen)
	fmt.Fprintf(stdout, "state_dir=%s\nmax_users=%d\nmax_online_ips=%d\n", cfg.Engine.StateDir, cfg.Runtime.MaxUsers, cfg.Runtime.MaxOnlineIPs)
	if total := app.HostMemoryBytes(); total > 0 {
		fmt.Fprintf(stdout, "host_memory_bytes=%d\ncontroller_soft_heap_bytes=%d\n", total, config.EffectiveGOMEMLIMIT(total))
	}
	fmt.Fprintln(stdout, "secrets=redacted")
	return nil
}

func runTune(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("tune", flag.ContinueOnError)
	flags.SetOutput(stderr)
	apply := flags.Bool("apply", false, "apply the reviewed host tuning profile")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*apply {
		fmt.Fprintln(stdout, "No host settings changed.")
		fmt.Fprintln(stdout, "Use 'v3node tune --apply' only after reviewing deploy/v3node-tune.")
		return nil
	}
	if runtime.GOOS != "linux" {
		return errors.New("host tuning is supported only on Linux")
	}
	script := "/usr/local/lib/v3node/v3node-tune"
	cmd := exec.Command(script, "--apply")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run %s: %w", script, err)
	}
	return nil
}

func newPanelClient(cfg config.Config) (*panel.Client, error) {
	if cfg.Panel.NodeID > int64(maxInt()) {
		return nil, errors.New("panel node_id exceeds platform integer range")
	}
	return panel.New(panel.Config{
		BaseURL:                cfg.Panel.URL,
		Token:                  cfg.Panel.Token,
		NodeID:                 int(cfg.Panel.NodeID),
		NodeType:               "v2node",
		Timeout:                cfg.Runtime.HTTPTimeout.Duration,
		MaxResponseBytes:       cfg.Runtime.MaxPanelPayloadBytes,
		MaxConfigResponseBytes: cfg.Runtime.MaxConfigBytes,
		MaxUserResponseBytes:   cfg.Runtime.MaxUserResponseBytes,
		MaxUsers:               cfg.Runtime.MaxUsers,
		MaxOnlineIPsPerUser:    cfg.Runtime.MaxIPsPerUser,
		AllowHTTP:              cfg.Panel.AllowInsecureHTTP,
		UserAgent:              "v3node/" + version,
		TLSCAFile:              cfg.Panel.TLSCAFile,
	})
}

func maxInt() int {
	return int(^uint(0) >> 1)
}

func init() {
	if seconds, err := strconv.ParseInt(builtAt, 10, 64); err == nil {
		builtAt = time.Unix(seconds, 0).UTC().Format(time.RFC3339)
	}
}
