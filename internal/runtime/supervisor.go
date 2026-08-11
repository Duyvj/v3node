// Package runtime owns the lifecycle of the external protocol engine.
package runtime

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"time"
)

type Logger interface {
	Printf(format string, args ...any)
}

type HealthProbe func(context.Context) error

type Supervisor struct {
	mu          sync.Mutex
	dir         string
	stopTimeout time.Duration
	stdout      io.Writer
	stderr      io.Writer
	logger      Logger
	cmd         *exec.Cmd
	exited      chan error
	backend     string
	binary      string
	hash        [32]byte
	generation  uint64
	probe       HealthProbe
	closed      bool
}

type SupervisorOptions struct {
	Directory   string
	StopTimeout time.Duration
	Stdout      io.Writer
	Stderr      io.Writer
	Logger      Logger
	HealthProbe HealthProbe
}

func NewSupervisor(opts SupervisorOptions) (*Supervisor, error) {
	if opts.Directory == "" || !filepath.IsAbs(opts.Directory) {
		return nil, errors.New("engine config directory must be absolute")
	}
	if opts.StopTimeout <= 0 {
		opts.StopTimeout = 20 * time.Second
	}
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if err := os.MkdirAll(opts.Directory, 0o700); err != nil {
		return nil, fmt.Errorf("create engine config directory: %w", err)
	}
	return &Supervisor{
		dir:         opts.Directory,
		stopTimeout: opts.StopTimeout,
		stdout:      opts.Stdout,
		stderr:      opts.Stderr,
		logger:      opts.Logger,
		probe:       opts.HealthProbe,
	}, nil
}

func (s *Supervisor) Apply(ctx context.Context, backend, binary string, config []byte) error {
	if backend != "sing-box" && backend != "xray" {
		return fmt.Errorf("unsupported engine backend %q", backend)
	}
	if !filepath.IsAbs(binary) {
		return errors.New("engine binary path must be absolute")
	}
	if len(config) == 0 || len(config) > 64<<20 {
		return errors.New("engine config size is invalid")
	}
	newHash := sha256.Sum256(config)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("engine supervisor is closed")
	}
	if s.cmd != nil && s.backend == backend && s.binary == binary && s.hash == newHash && s.processAliveLocked() {
		return nil
	}

	stagePath, err := s.stage(config)
	if err != nil {
		return err
	}
	defer os.Remove(stagePath)
	if err := checkEngine(ctx, backend, binary, stagePath, s.stdout, s.stderr); err != nil {
		return err
	}

	currentPath := filepath.Join(s.dir, "engine.json")
	previousPath := filepath.Join(s.dir, "engine.previous.json")
	hadCurrent := false
	if _, err := os.Stat(currentPath); err == nil {
		hadCurrent = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect current engine config: %w", err)
	}
	// Prepare the complete on-disk transaction while the accepted process is
	// still serving. The engines read their configuration at startup, so these
	// renames cannot change the running generation.
	if hadCurrent {
		if err := os.Remove(previousPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale previous config: %w", err)
		}
		if err := os.Rename(currentPath, previousPath); err != nil {
			return fmt.Errorf("backup current engine config: %w", err)
		}
	}
	if err := os.Rename(stagePath, currentPath); err != nil {
		if hadCurrent {
			_ = os.Rename(previousPath, currentPath)
		}
		return fmt.Errorf("activate engine config: %w", err)
	}
	if err := syncDirectory(s.dir); err != nil {
		restoreErr := restoreConfigFiles(currentPath, previousPath, hadCurrent)
		return errors.Join(fmt.Errorf("sync engine config directory: %w", err), restoreErr)
	}

	previousBackend, previousBinary := s.backend, s.binary
	if err := s.stopLocked(ctx); err != nil {
		restoreErr := restoreConfigFiles(currentPath, previousPath, hadCurrent)
		if hadCurrent && previousBackend != "" && previousBinary != "" {
			if startErr := s.startLocked(previousBackend, previousBinary, currentPath); startErr != nil {
				return errors.Join(fmt.Errorf("stop previous engine: %w", err), restoreErr, fmt.Errorf("restart previous engine: %w", startErr))
			}
		}
		return errors.Join(fmt.Errorf("stop previous engine: %w", err), restoreErr)
	}

	if err := s.startLocked(backend, binary, currentPath); err == nil {
		if err := s.healthLocked(ctx); err == nil {
			s.backend = backend
			s.binary = binary
			s.hash = newHash
			return nil
		} else {
			s.logf("candidate engine failed health check: %v", err)
			_ = s.stopLocked(context.Background())
		}
	} else {
		s.logf("candidate engine failed to start: %v", err)
	}

	// Roll back only to a configuration that previously existed and had
	// already been accepted. A failed first install remains stopped.
	if !hadCurrent {
		return errors.New("candidate engine failed; no previous configuration is available")
	}
	failedPath := filepath.Join(s.dir, "engine.failed.json")
	_ = os.Remove(failedPath)
	_ = os.Rename(currentPath, failedPath)
	if err := os.Rename(previousPath, currentPath); err != nil {
		return fmt.Errorf("candidate failed and rollback config restore failed: %w", err)
	}
	if s.backend == "" || s.binary == "" {
		return errors.New("candidate engine failed and previous engine metadata is unavailable")
	}
	if err := s.startLocked(s.backend, s.binary, currentPath); err != nil {
		return fmt.Errorf("candidate engine failed and previous engine restart failed: %w", err)
	}
	return errors.New("candidate engine failed health check; previous configuration restored")
}

func restoreConfigFiles(currentPath, previousPath string, hadCurrent bool) error {
	failedPath := filepath.Join(filepath.Dir(currentPath), "engine.failed.json")
	var result error
	if err := os.Remove(failedPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		result = errors.Join(result, fmt.Errorf("remove stale failed config: %w", err))
	}
	if err := os.Rename(currentPath, failedPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		result = errors.Join(result, fmt.Errorf("retain failed config: %w", err))
	}
	if hadCurrent {
		if err := os.Rename(previousPath, currentPath); err != nil {
			result = errors.Join(result, fmt.Errorf("restore previous config: %w", err))
		}
	}
	if err := syncDirectory(filepath.Dir(currentPath)); err != nil {
		result = errors.Join(result, fmt.Errorf("sync restored config directory: %w", err))
	}
	return result
}

// StartExisting starts the last-known-good configuration without contacting
// the panel. The caller obtains backend and binary from its small runtime
// metadata file; the engine configuration itself remains the source of truth.
func (s *Supervisor) StartExisting(ctx context.Context, backend, binary string, expectedHash [sha256.Size]byte) error {
	if backend != "sing-box" && backend != "xray" {
		return fmt.Errorf("unsupported engine backend %q", backend)
	}
	if !filepath.IsAbs(binary) {
		return errors.New("engine binary path must be absolute")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("engine supervisor is closed")
	}
	path := filepath.Join(s.dir, "engine.json")
	previousPath := filepath.Join(s.dir, "engine.previous.json")
	config, currentErr := readEngineConfig(path)
	actualHash := sha256.Sum256(config)
	if currentErr != nil || actualHash != expectedHash {
		previous, previousErr := readEngineConfig(previousPath)
		if previousErr != nil || sha256.Sum256(previous) != expectedHash {
			if currentErr != nil {
				return fmt.Errorf("read last-known-good engine config: %w", currentErr)
			}
			return errors.New("runtime metadata does not match the current or previous engine generation")
		}
		if err := restoreConfigFiles(path, previousPath, true); err != nil {
			return fmt.Errorf("restore engine generation matching runtime metadata: %w", err)
		}
		config = previous
		actualHash = expectedHash
	}
	if err := checkEngine(ctx, backend, binary, path, s.stdout, s.stderr); err != nil {
		return err
	}
	if s.processAliveLocked() {
		if s.backend != backend || s.binary != binary || s.hash != expectedHash {
			return errors.New("running engine generation does not match runtime metadata")
		}
		return nil
	}
	if err := s.startLocked(backend, binary, path); err != nil {
		return fmt.Errorf("start last-known-good engine: %w", err)
	}
	if err := s.healthLocked(ctx); err != nil {
		_ = s.stopLocked(context.Background())
		return err
	}
	s.backend = backend
	s.binary = binary
	s.hash = actualHash
	return nil
}

func readEngineConfig(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	const maximum = int64(64 << 20)
	config, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if len(config) == 0 || int64(len(config)) > maximum {
		return nil, errors.New("engine config size is invalid")
	}
	return config, nil
}

func (s *Supervisor) stage(config []byte) (string, error) {
	f, err := os.CreateTemp(s.dir, ".engine-stage-*.json")
	if err != nil {
		return "", fmt.Errorf("create staged engine config: %w", err)
	}
	path := f.Name()
	cleanup := func(cause error) (string, error) {
		_ = f.Close()
		_ = os.Remove(path)
		return "", cause
	}
	if err := f.Chmod(0o600); err != nil {
		return cleanup(fmt.Errorf("protect staged engine config: %w", err))
	}
	if _, err := f.Write(config); err != nil {
		return cleanup(fmt.Errorf("write staged engine config: %w", err))
	}
	if err := f.Sync(); err != nil {
		return cleanup(fmt.Errorf("sync staged engine config: %w", err))
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close staged engine config: %w", err)
	}
	return path, nil
}

func checkEngine(ctx context.Context, backend, binary, configPath string, stdout, stderr io.Writer) error {
	var args []string
	switch backend {
	case "sing-box":
		args = []string{"check", "-c", configPath}
	case "xray":
		args = []string{"run", "-test", "-config", configPath}
	default:
		return fmt.Errorf("unsupported engine backend %q", backend)
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = engineEnvironment(backend, binary)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s configuration check failed: %w", backend, err)
	}
	return nil
}

// CheckEngineConfig validates rendered configuration without starting a
// listener. The temporary credential-bearing file is mode 0600 and removed
// before returning.
func CheckEngineConfig(ctx context.Context, backend, binary string, config []byte, output io.Writer) error {
	if !filepath.IsAbs(binary) {
		return errors.New("engine binary path must be absolute")
	}
	if len(config) == 0 || len(config) > 64<<20 {
		return errors.New("engine config size is invalid")
	}
	f, err := os.CreateTemp("", ".v3node-check-*.json")
	if err != nil {
		return fmt.Errorf("create temporary engine config: %w", err)
	}
	path := f.Name()
	defer os.Remove(path)
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(config); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if output == nil {
		output = io.Discard
	}
	return checkEngine(ctx, backend, binary, path, output, output)
}

func (s *Supervisor) startLocked(backend, binary, configPath string) error {
	var args []string
	switch backend {
	case "sing-box":
		args = []string{"run", "-c", configPath}
	case "xray":
		args = []string{"run", "-config", configPath}
	default:
		return fmt.Errorf("unsupported engine backend %q", backend)
	}
	cmd := exec.Command(binary, args...)
	cmd.Env = engineEnvironment(backend, binary)
	cmd.Stdout = s.stdout
	cmd.Stderr = s.stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	s.generation++
	if s.generation == 0 {
		s.generation = 1
	}
	exited := make(chan error, 1)
	s.cmd = cmd
	s.exited = exited
	go func() {
		exited <- cmd.Wait()
		close(exited)
	}()
	return nil
}

func engineEnvironment(backend, binary string) []string {
	if backend != "xray" {
		return nil
	}
	environment := os.Environ()
	for _, entry := range environment {
		key, value, found := strings.Cut(entry, "=")
		if found && strings.EqualFold(key, "XRAY_LOCATION_ASSET") && strings.TrimSpace(value) != "" {
			return environment
		}
	}
	filtered := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		key, _, found := strings.Cut(entry, "=")
		if found && strings.EqualFold(key, "XRAY_LOCATION_ASSET") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return append(filtered, "XRAY_LOCATION_ASSET="+filepath.Dir(binary))
}

func (s *Supervisor) healthLocked(ctx context.Context) error {
	timer := time.NewTimer(750 * time.Millisecond)
	defer timer.Stop()
	select {
	case err := <-s.exited:
		if err == nil {
			return errors.New("engine exited during startup")
		}
		return fmt.Errorf("engine exited during startup: %w", err)
	case <-timer.C:
	}
	if s.probe == nil {
		return nil
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.probe(probeCtx)
}

func (s *Supervisor) processAliveLocked() bool {
	if s.cmd == nil || s.exited == nil {
		return false
	}
	select {
	case <-s.exited:
		return false
	default:
		return true
	}
}

func (s *Supervisor) Healthy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.processAliveLocked()
}

// Generation identifies the most recently started engine process. It changes
// for candidate starts, rollbacks, and crash recovery even when the accepted
// configuration itself does not change. Process-local cumulative counters
// must key their baselines by this value.
func (s *Supervisor) Generation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation
}

func (s *Supervisor) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopLocked(ctx)
}

func (s *Supervisor) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return s.stopLocked(ctx)
}

func (s *Supervisor) stopLocked(ctx context.Context) error {
	if s.cmd == nil || s.cmd.Process == nil {
		s.cmd = nil
		s.exited = nil
		return nil
	}
	cmd := s.cmd
	exited := s.exited
	s.cmd = nil
	s.exited = nil
	_ = cmd.Process.Signal(os.Interrupt)
	timer := time.NewTimer(s.stopTimeout)
	defer timer.Stop()
	select {
	case err := <-exited:
		if err != nil {
			s.logf("engine stopped with error: %v", err)
		}
		return nil
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-exited
		return ctx.Err()
	case <-timer.C:
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("kill engine after timeout: %w", err)
		}
		<-exited
		return nil
	}
}

func (s *Supervisor) logf(format string, args ...any) {
	if s.logger != nil {
		s.logger.Printf(format, args...)
	}
}

func syncDirectory(path string) error {
	// Windows does not support flushing a directory handle with File.Sync;
	// it consistently returns access denied even after successful atomic
	// renames. The engine transaction still uses atomic same-directory renames,
	// while Unix hosts (including production VPSes) retain directory fsync.
	if goruntime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
