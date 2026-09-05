package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/Duyvj/v3node/agent"
	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/Duyvj/v3node/conf"
	"github.com/Duyvj/v3node/core"
	"github.com/Duyvj/v3node/limiter"
	"github.com/Duyvj/v3node/node"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	config string
	watch  bool
)

var serverCommand = cobra.Command{
	Use:   "server",
	Short: "Run znode server",
	Run:   serverHandle,
	Args:  cobra.NoArgs,
}

func init() {
	serverCommand.PersistentFlags().
		StringVarP(&config, "config", "c",
			"/etc/znode/config.json", "config file path")
	serverCommand.PersistentFlags().
		BoolVarP(&watch, "watch", "w",
			true, "watch file path change")
	command.AddCommand(&serverCommand)
}

func serverHandle(_ *cobra.Command, _ []string) {
	showVersion()
	panel.SetClientVersion(version)
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: true,
		DisableQuote:     true,
		PadLevelText:     false,
	})
	if assetDirectory := configureAssetLocation(config); assetDirectory != "" {
		log.WithField("directory", assetDirectory).Info("Xray geodata loaded")
	} else {
		log.Warn("geoip.dat and geosite.dat were not found together; geoip:/geosite: routing rules may fail")
	}

	prepared, err := prepareInitialRuntime(config)
	if err != nil {
		log.WithField("err", err).Error("Prepare node runtime failed")
		return
	}
	if prepared.offline {
		log.WithFields(log.Fields{
			"err":   prepared.offlineCause,
			"nodes": len(prepared.config.NodeConfigs),
		}).Warn("Panel unavailable; starting last-known-good offline runtime")
	}
	applyLogConfig(prepared.config)
	applyResourceSettings(&prepared.config.ResourceConfig)
	stopMemScavenger := make(chan struct{})
	defer close(stopMemScavenger)
	startPeriodicMemoryRelease(prepared.config.ResourceConfig.PeriodicMemoryReleaseInterval, stopMemScavenger)

	if prepared.config.PprofPort != 0 {
		port := prepared.config.PprofPort
		go func() {
			log.Infof("Starting pprof server on :%d", port)
			if err := http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", port), nil); err != nil {
				log.WithField("err", err).Error("pprof server failed")
			}
		}()
	}

	limiter.Init()
	reloadCh := make(chan struct{}, 1)
	snapshotCh := make(chan struct{}, 1)
	fallbackCh := make(chan agent.FallbackUpdate, 1)
	running, err := startPreparedRuntime(prepared, reloadCh, snapshotCh)
	if err != nil {
		log.WithField("err", err).Error("Start runtime failed")
		return
	}
	defer func() {
		if err := shutdownRuntime(running, 30*time.Second); err != nil {
			log.WithField("err", err).Error("Terminal shutdown completed with incomplete accounting")
		}
	}()
	logRevokedAssignment(running.assignment)
	log.WithField("nodes", len(running.config.NodeConfigs)).Info("Nodes started")
	if err := persistRuntimeSnapshot(running.preparedRuntime); err != nil {
		log.WithField("err", err).Warn("Persist last-known-good runtime snapshot failed")
	}

	agentMonitor := agent.NewMonitor(reloadCh, fallbackCh)
	if err := agentMonitor.MarkApplied(running.config.AgentConfig, running.assignment); err != nil {
		log.WithField("err", err).Error("Start agent manifest monitor failed")
		return
	}
	agentMonitor.Start()
	defer agentMonitor.Close()

	if watch {
		// Do not let the watcher mutate the config used by the live core. The
		// reload path loads and validates a fresh snapshot first.
		watchConfig := conf.New()
		if err := watchConfig.Watch(config, func() {
			select {
			case reloadCh <- struct{}{}:
			default:
			}
		}); err != nil {
			log.WithField("err", err).Error("Start config watcher failed")
			return
		}
	}

	runtime.GC()
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(osSignals)

	for {
		select {
		case <-osSignals:
			log.Info("Shutdown signal received")
			return
		case <-reloadCh:
			log.Info("Reload signal received; reconciling assigned nodes")
			newRuntime, err := reloadRuntime(config, running, reloadCh)
			if err != nil {
				log.WithField("err", err).Error("Reload failed; keeping current runtime when possible")
				continue
			}
			running = newRuntime
			if err := persistRuntimeSnapshot(running.preparedRuntime); err != nil {
				log.WithField("err", err).Warn("Persist last-known-good runtime snapshot failed")
			}
			logRevokedAssignment(running.assignment)
			if err := agentMonitor.MarkApplied(running.config.AgentConfig, running.assignment); err != nil {
				log.WithField("err", err).Warn("Update agent manifest monitor failed")
			}
			log.WithField("nodes", len(running.config.NodeConfigs)).Info("Reload successful")
		case fallbackUpdate := <-fallbackCh:
			applyRuntimeFallbackConfig(running, fallbackUpdate)
			if err := persistRuntimeSnapshot(running.preparedRuntime); err != nil {
				log.WithField("err", err).Warn("Persist Redis fallback update failed")
			}
			log.Info("Applied Redis user fallback without reloading VPN inbounds")
		case <-snapshotCh:
			if err := persistRuntimeSnapshot(running.preparedRuntime); err != nil {
				log.WithField("err", err).Warn("Refresh last-known-good runtime snapshot failed")
			}
		}
	}
}

func applyRuntimeFallbackConfig(running *runningRuntime, update agent.FallbackUpdate) {
	if running == nil || running.preparedRuntime == nil {
		return
	}
	if running.nodes != nil {
		running.nodes.UpdateFallbackConfig(update.Config)
	}
	if running.config == nil {
		return
	}
	for index := range running.config.NodeConfigs {
		running.config.NodeConfigs[index].GlobalDeviceLimitConfig = cloneRuntimeFallbackConfig(update.Config)
	}
	running.assignment.FallbackRevision = update.Revision
	running.assignment.Revision = update.AggregateRevision
}

func cloneRuntimeFallbackConfig(source *conf.GlobalDeviceLimitConfig) *conf.GlobalDeviceLimitConfig {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.RedisSentinelAddrs = append([]string(nil), source.RedisSentinelAddrs...)
	if source.SyncEnabled != nil {
		enabled := *source.SyncEnabled
		cloned.SyncEnabled = &enabled
	}
	return &cloned
}

func logRevokedAssignment(assignment agent.Assignment) {
	if assignment.AuthorizationRevoked {
		log.Warn("Agent authorization was revoked; all assigned logical nodes are stopped until valid credentials are installed")
	}
}

type preparedRuntime struct {
	config       *conf.Conf
	nodes        *node.Node
	assignment   agent.Assignment
	offline      bool
	offlineCause error
}

type runningRuntime struct {
	*preparedRuntime
	core          *core.V2Core
	terminalNodes nodeTerminator
	terminalCore  coreCloser
}

type nodeTerminator interface {
	BeginTerminalCoreOperations()
	Shutdown(context.Context) error
	CloseCoreOperations(context.Context) error
}

type coreCloser interface{ Close() error }

func prepareRuntime(configPath string) (*preparedRuntime, error) {
	newConf := conf.New()
	if err := newConf.LoadFromPath(configPath); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	assignment, err := agent.Resolve(ctx, newConf)
	if err != nil {
		return nil, fmt.Errorf("resolve agent assignment: %w", err)
	}
	newNodes, err := node.NewContext(ctx, newConf.NodeConfigs)
	if err != nil {
		return nil, err
	}
	if err := newNodes.Prepare(ctx, newConf.NodeConfigs); err != nil {
		return nil, err
	}
	return &preparedRuntime{config: newConf, nodes: newNodes, assignment: assignment}, nil
}

func startPreparedRuntime(prepared *preparedRuntime, reloadCh chan struct{}, snapshotChannels ...chan struct{}) (*runningRuntime, error) {
	newCore := core.New(prepared.config)
	newCore.ReloadCh = reloadCh
	if len(snapshotChannels) > 0 {
		newCore.SnapshotCh = snapshotChannels[0]
	}
	if err := newCore.Start(prepared.nodes.NodeInfos); err != nil {
		return nil, err
	}
	if err := prepared.nodes.Start(prepared.config.NodeConfigs, newCore); err != nil {
		_ = prepared.nodes.Close()
		_ = newCore.Close()
		return nil, err
	}
	return &runningRuntime{preparedRuntime: prepared, core: newCore, terminalNodes: prepared.nodes, terminalCore: newCore}, nil
}

func reloadRuntime(configPath string, old *runningRuntime, reloadCh chan struct{}) (*runningRuntime, error) {
	// Manifest fetch, NodeInfo fetch and duplicate-port validation all happen
	// before the healthy old runtime is stopped.
	prepared, err := prepareRuntime(configPath)
	if err != nil {
		return nil, err
	}

	// The base core has no inbounds yet, so this is also safe to preflight while
	// old ports are still listening.
	newCore := core.New(prepared.config)
	newCore.ReloadCh = reloadCh
	if old != nil && old.core != nil {
		newCore.SnapshotCh = old.core.SnapshotCh
	}
	if err := newCore.Start(prepared.nodes.NodeInfos); err != nil {
		return nil, err
	}

	if err := old.nodes.Close(); err != nil {
		_ = newCore.Close()
		return nil, fmt.Errorf("close old nodes: %w", err)
	}
	if err := old.core.Close(); err != nil {
		_ = newCore.Close()
		if restoreErr := restorePreviousRuntime(old, reloadCh); restoreErr != nil {
			return nil, fmt.Errorf("close old core: %w; restore previous runtime: %v", err, restoreErr)
		}
		return nil, fmt.Errorf("close old core: %w; previous runtime restored", err)
	}
	if err := prepared.nodes.Start(prepared.config.NodeConfigs, newCore); err != nil {
		_ = prepared.nodes.Close()
		_ = newCore.Close()
		if restoreErr := restorePreviousRuntime(old, reloadCh); restoreErr != nil {
			return nil, fmt.Errorf("start replacement nodes: %w; restore previous runtime: %v", err, restoreErr)
		}
		return nil, fmt.Errorf("start replacement nodes: %w; previous runtime restored", err)
	}

	applyLogConfig(prepared.config)
	runtime.GC()
	return &runningRuntime{preparedRuntime: prepared, core: newCore, terminalNodes: prepared.nodes, terminalCore: newCore}, nil
}

// restorePreviousRuntime is the final rollback barrier for errors that can
// only surface after the old listeners have been released (for example a
// port being claimed by another process between preflight and replacement).
// The caller keeps its original runningRuntime pointer, so update its core in
// place after the previous controllers have been started again.
func restorePreviousRuntime(old *runningRuntime, reloadCh chan struct{}) error {
	if old == nil || old.preparedRuntime == nil {
		return fmt.Errorf("previous runtime is unavailable")
	}
	restored, err := startPreparedRuntime(old.preparedRuntime, reloadCh, old.core.SnapshotCh)
	if err != nil {
		return err
	}
	old.core = restored.core
	old.terminalCore = restored.core
	return nil
}

func (r *runningRuntime) Close() error {
	if r == nil {
		return nil
	}
	if r.nodes != nil {
		if err := r.nodes.Close(); err != nil {
			// Node.Close restores controllers that were already stopped. Never
			// close the core while any final traffic capture is not durable.
			return err
		}
	}
	if r.core != nil {
		if err := r.core.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Shutdown closes a runtime for process termination. It always tries the core
// close after the bounded node accounting attempt and never invokes the
// transactional Close path that can restore listeners for reload.
func (r *runningRuntime) Shutdown(ctx context.Context) error {
	if r == nil {
		return nil
	}
	var shutdownErr error
	terminator := r.terminalNodes
	if terminator == nil && r.nodes != nil {
		terminator = r.nodes
	}
	if terminator != nil {
		// Close admission for every controller before one slow terminal drain can
		// consume the shared deadline. Otherwise a later controller can begin a
		// raw-core operation after the runtime is already preparing to close it.
		terminator.BeginTerminalCoreOperations()
		shutdownErr = errors.Join(shutdownErr, terminator.Shutdown(ctx))
		shutdownErr = errors.Join(shutdownErr, terminator.CloseCoreOperations(ctx))
	}
	closer := r.terminalCore
	if closer == nil && r.core != nil {
		closer = r.core
	}
	if closer != nil {
		shutdownErr = errors.Join(shutdownErr, closer.Close())
	}
	return shutdownErr
}

func shutdownRuntime(r *runningRuntime, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return r.Shutdown(ctx)
}

func applyLogConfig(config *conf.Conf) {
	switch config.LogConfig.Level {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn", "warning":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	}
	if config.LogConfig.Output == "" {
		return
	}
	f, err := os.OpenFile(config.LogConfig.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.WithField("err", err).Error("Open log file failed, using current output instead")
		return
	}
	oldWriter, oldIsFile := log.StandardLogger().Out.(*os.File)
	log.SetOutput(f)
	if oldIsFile && oldWriter != os.Stdout && oldWriter != os.Stderr && oldWriter != f {
		_ = oldWriter.Close()
	}
}

func applyResourceSettings(r *conf.ResourceConfig) {
	if r == nil {
		return
	}
	if r.GOGC > 0 {
		oldGC := debug.SetGCPercent(r.GOGC)
		log.Infof("[Resource] GC percent set to %d%% (previous: %d%%)", r.GOGC, oldGC)
	}
	if r.MemLimitMB > 0 {
		limitBytes := int64(r.MemLimitMB) * 1024 * 1024
		oldLimit := debug.SetMemoryLimit(limitBytes)
		log.Infof("[Resource] Soft memory limit set to %d MB (previous: %d MB)", r.MemLimitMB, oldLimit/(1024*1024))
	}
	log.Infof("[Resource] Profile: %s, Pipe BufferSize: %d KB, ConnectionIdle: %ds, DisableSniffing: %t", r.Profile, r.BufferSize, r.ConnectionIdle, r.DisableSniffing)
}

func startPeriodicMemoryRelease(intervalSeconds int, stopCh <-chan struct{}) {
	if intervalSeconds <= 0 {
		return
	}
	ticker := time.NewTicker(time.Duration(intervalSeconds) * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				debug.FreeOSMemory()
			}
		}
	}()
}

