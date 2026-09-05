package agent

import (
	"context"
	"testing"
	"time"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/Duyvj/v3node/conf"
)

func TestManifestPollDelayBacksOffCapsAndJittersDeterministically(t *testing.T) {
	base := 15 * time.Second
	if got := manifestPollDelay(base, 0, 0); got != base {
		t.Fatalf("healthy delay = %s, want %s", got, base)
	}
	first := manifestPollDelay(base, 1, 0)
	second := manifestPollDelay(base, 2, 0)
	if first < base || first > 18*time.Second || second < 24*time.Second || second > 36*time.Second {
		t.Fatalf("unexpected retry delays: first=%s second=%s", first, second)
	}
	if first == manifestPollDelay(base, 1, uint64(2*(base/5))) {
		t.Fatal("different deterministic entropy did not jitter the retry")
	}
	if got := manifestPollDelay(base, 30, 0); got > manifestPollMaxBackoff {
		t.Fatalf("backoff exceeded cap: %s", got)
	}
}

func TestHealthyManifestPollDelayUsesBoundedDeterministicSpread(t *testing.T) {
	base := 15 * time.Second
	first := healthyManifestPollDelay(base, 1)
	second := healthyManifestPollDelay(base, 2)
	if first < base || first > 18*time.Second || second < base || second > 18*time.Second {
		t.Fatalf("healthy spread outside 0..20%% window: %s %s", first, second)
	}
	if first == second {
		t.Fatal("distinct agent entropy did not spread healthy polls")
	}
	if second-first < time.Millisecond {
		t.Fatalf("healthy poll spread is not operationally meaningful: %s", second-first)
	}
}

type fakeManifestFetcher struct {
	manifest *panel.AgentManifest
}

func (f *fakeManifestFetcher) GetManifest(context.Context) (*panel.AgentManifest, error) {
	return f.manifest, nil
}

func TestMonitorCoalescesUnappliedRevisionAndRetriesAfterCooldown(t *testing.T) {
	reloadCh := make(chan struct{}, 1)
	fetcher := &fakeManifestFetcher{manifest: &panel.AgentManifest{Revision: "rev-2", Nodes: []int{1}}}
	monitor := newMonitor(reloadCh, func(conf.AgentConfig) (manifestFetcher, error) {
		return fetcher, nil
	})
	defer monitor.Close()
	now := time.Unix(0, 0)
	monitor.now = func() time.Time { return now }

	config := conf.AgentConfig{Enable: true, APIHost: "https://panel.example", AgentID: "agent", AgentToken: "token", PollInterval: 15}
	if err := monitor.MarkApplied(config, Assignment{Revision: "rev-1"}); err != nil {
		t.Fatal(err)
	}
	if err := monitor.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reloadCh:
	default:
		t.Fatal("expected reload signal")
	}

	// A failed reload does not call MarkApplied, but it must not cause a full
	// reload every manifest poll.
	if err := monitor.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reloadCh:
		t.Fatal("same unapplied revision bypassed reload cooldown")
	default:
	}

	now = now.Add(manifestReloadRetryDelay(1, 0))
	if err := monitor.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reloadCh:
	default:
		t.Fatal("expected retry after reload cooldown")
	}

	if err := monitor.MarkApplied(config, Assignment{Revision: "rev-2"}); err != nil {
		t.Fatal(err)
	}
	if err := monitor.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reloadCh:
		t.Fatal("unexpected signal for applied revision")
	default:
	}
}

func TestMonitorSignalsNewRevisionImmediatelyAndMarkAppliedResetsRetry(t *testing.T) {
	reloadCh := make(chan struct{}, 2)
	fetcher := &fakeManifestFetcher{manifest: &panel.AgentManifest{Revision: "rev-2", Nodes: []int{1}}}
	monitor := newMonitor(reloadCh, func(conf.AgentConfig) (manifestFetcher, error) { return fetcher, nil })
	defer monitor.Close()
	now := time.Unix(0, 0)
	monitor.now = func() time.Time { return now }
	config := conf.AgentConfig{Enable: true, APIHost: "https://panel.example", AgentID: "agent", AgentToken: "token"}
	if err := monitor.MarkApplied(config, Assignment{Revision: "rev-1"}); err != nil {
		t.Fatal(err)
	}
	if err := monitor.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-reloadCh

	fetcher.manifest = &panel.AgentManifest{Revision: "rev-3", Nodes: []int{1}}
	if err := monitor.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reloadCh:
	default:
		t.Fatal("new revision did not signal immediately")
	}
	if err := monitor.MarkApplied(config, Assignment{Revision: "rev-3"}); err != nil {
		t.Fatal(err)
	}
	if err := monitor.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reloadCh:
		t.Fatal("MarkApplied did not reset pending reload state")
	default:
	}
}

func TestMonitorCoalescesFallbackRequiringFullReload(t *testing.T) {
	reloadCh := make(chan struct{}, 1)
	fetcher := &fakeManifestFetcher{manifest: &panel.AgentManifest{
		Revision: "all-2", NodeRevision: "nodes-1", FallbackRevision: "fallback-2",
		GlobalDeviceLimitConfig: &conf.GlobalDeviceLimitConfig{Enable: true},
	}}
	monitor := newMonitor(reloadCh, func(conf.AgentConfig) (manifestFetcher, error) { return fetcher, nil })
	defer monitor.Close()
	now := time.Unix(0, 0)
	monitor.now = func() time.Time { return now }
	config := conf.AgentConfig{Enable: true, APIHost: "https://panel.example", AgentID: "agent", AgentToken: "token"}
	if err := monitor.MarkApplied(config, Assignment{Revision: "all-1", NodeRevision: "nodes-1", FallbackRevision: "fallback-1"}); err != nil {
		t.Fatal(err)
	}
	if err := monitor.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-reloadCh
	if err := monitor.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reloadCh:
		t.Fatal("same full-reload fallback revision bypassed cooldown")
	default:
	}
	fetcher.manifest.FallbackRevision = "fallback-3"
	if err := monitor.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reloadCh:
	default:
		t.Fatal("new full-reload fallback revision did not signal immediately")
	}
}

func TestMonitorAppliesRedisFallbackWithoutReloadingNodes(t *testing.T) {
	reloadCh := make(chan struct{}, 1)
	fallbackCh := make(chan FallbackUpdate, 1)
	fetcher := &fakeManifestFetcher{manifest: &panel.AgentManifest{
		Revision:         "all-2",
		NodeRevision:     "nodes-1",
		FallbackRevision: "fallback-2",
		Nodes:            []int{1},
		GlobalDeviceLimitConfig: &conf.GlobalDeviceLimitConfig{
			RedisAddr: "redis.example:6379", UserFallbackEnabled: true,
		},
	}}
	monitor := newMonitorWithFallback(reloadCh, fallbackCh, func(conf.AgentConfig) (manifestFetcher, error) {
		return fetcher, nil
	})
	defer monitor.Close()

	config := conf.AgentConfig{Enable: true, APIHost: "https://panel.example", AgentID: "agent", AgentToken: "token"}
	if err := monitor.MarkApplied(config, Assignment{
		Revision: "all-1", NodeRevision: "nodes-1", FallbackRevision: "fallback-1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := monitor.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case update := <-fallbackCh:
		if update.Config == nil || update.Config.RedisAddr != "redis.example:6379" || !update.Config.UserFallbackEnabled ||
			update.Revision != "fallback-2" || update.AggregateRevision != "all-2" {
			t.Fatalf("unexpected fallback update: %+v", update)
		}
	default:
		t.Fatal("expected a hot Redis fallback update")
	}
	select {
	case <-reloadCh:
		t.Fatal("Redis-only update reloaded VPN nodes")
	default:
	}

	if err := monitor.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-fallbackCh:
		t.Fatal("already applied fallback was sent twice")
	default:
	}
}

func TestMonitorKeepsCurrentNodesUntilAuthorizationDenialIsPersistent(t *testing.T) {
	reloadCh := make(chan struct{}, 1)
	fetcher := &fakeManifestFetcher{manifest: &panel.AgentManifest{
		Revision:             "authorization-revoked:401",
		Nodes:                []int{},
		AuthorizationRevoked: true,
	}}
	monitor := newMonitor(reloadCh, func(conf.AgentConfig) (manifestFetcher, error) {
		return fetcher, nil
	})
	defer monitor.Close()

	config := conf.AgentConfig{Enable: true, APIHost: "https://panel.example", AgentID: "agent", AgentToken: "token", PollInterval: 15}
	if err := monitor.MarkApplied(config, Assignment{Revision: "healthy-revision"}); err != nil {
		t.Fatal(err)
	}

	for attempt := 1; attempt < authorizationRevocationThreshold; attempt++ {
		if err := monitor.pollOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		select {
		case <-reloadCh:
			t.Fatalf("transient authorization denial %d stopped healthy nodes", attempt)
		default:
		}
	}

	if err := monitor.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reloadCh:
	default:
		t.Fatal("persistent authorization revocation did not trigger reconciliation")
	}
}

func TestMonitorResetsAuthorizationDenialsAfterAHealthyManifest(t *testing.T) {
	reloadCh := make(chan struct{}, 1)
	fetcher := &fakeManifestFetcher{manifest: &panel.AgentManifest{
		Revision:             "authorization-revoked:403",
		Nodes:                []int{},
		AuthorizationRevoked: true,
	}}
	monitor := newMonitor(reloadCh, func(conf.AgentConfig) (manifestFetcher, error) {
		return fetcher, nil
	})
	defer monitor.Close()

	config := conf.AgentConfig{Enable: true, APIHost: "https://panel.example", AgentID: "agent", AgentToken: "token", PollInterval: 15}
	if err := monitor.MarkApplied(config, Assignment{Revision: "healthy-revision"}); err != nil {
		t.Fatal(err)
	}
	if err := monitor.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	fetcher.manifest = &panel.AgentManifest{Revision: "healthy-revision", Nodes: []int{1}}
	if err := monitor.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	fetcher.manifest = &panel.AgentManifest{
		Revision:             "authorization-revoked:403",
		Nodes:                []int{},
		AuthorizationRevoked: true,
	}
	for attempt := 1; attempt < authorizationRevocationThreshold; attempt++ {
		if err := monitor.pollOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		select {
		case <-reloadCh:
			t.Fatalf("denial counter was not reset after a healthy response (attempt %d)", attempt)
		default:
		}
	}
}
