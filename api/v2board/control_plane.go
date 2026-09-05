package panel

import (
	"strings"
	"sync"
	"time"
)

// Redis is a disaster-recovery source, not a read replica. A healthy Agent
// manifest heartbeat proves that ZBoard's authenticated control plane is still
// available even when one node endpoint has a transient 5xx/timeout. Keep the
// live panel authoritative throughout this grace window.
const zboardControlPlaneHealthyWindow = 45 * time.Second

var zboardControlPlaneHealth sync.Map

func markZBoardControlPlaneHealthy(apiHost, agentID string) {
	zboardControlPlaneHealth.Store(zboardControlPlaneHealthKey(apiHost, agentID), time.Now().UnixNano())
}

func zboardControlPlaneRecentlyHealthy(apiHost, agentID string) bool {
	value, ok := zboardControlPlaneHealth.Load(zboardControlPlaneHealthKey(apiHost, agentID))
	if !ok {
		return false
	}
	seen, ok := value.(int64)
	if !ok || seen <= 0 {
		return false
	}
	age := time.Since(time.Unix(0, seen))
	return age >= 0 && age <= zboardControlPlaneHealthyWindow
}

func zboardControlPlaneHealthKey(apiHost, agentID string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(apiHost), "/")) + "\x00" + strings.TrimSpace(agentID)
}
