package node

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Duyvj/v3node/conf"
)

func TestDeviceSyncEventDecodesPanelPayload(t *testing.T) {
	var event deviceSyncEvent
	if err := json.Unmarshal([]byte(`{"version":1,"action":"device.unbound","api_host":"https://panel.example"}`), &event); err != nil {
		t.Fatalf("decode sync event: %v", err)
	}
	if event.Version != 1 || event.Action != "device.unbound" || event.APIHost != "https://panel.example" {
		t.Fatalf("unexpected event: %+v", event)
	}
}

func TestDeviceSyncHubKeyIsSharedForIdenticalLogicalNodes(t *testing.T) {
	config := &conf.GlobalDeviceLimitConfig{
		Enable:       true,
		RedisNetwork: "tcp",
		RedisAddr:    "127.0.0.1:6379",
		RedisDB:      3,
		Timeout:      2,
		SyncChannel:  "v2board:device-sync",
	}
	first := deviceSyncKey(config)
	second := deviceSyncKey(config)
	if first != second {
		t.Fatal("identical logical nodes did not resolve to one shared Pub/Sub hub")
	}
	config.SyncChannel = "another-channel"
	if first == deviceSyncKey(config) {
		t.Fatal("different Pub/Sub channels unexpectedly shared one hub")
	}
}

func TestDeviceSyncHubFansOutOnlyToMatchingPanel(t *testing.T) {
	hub := &deviceSyncHub{subscribers: make(map[uint64]*deviceSyncSubscriber)}
	firstCalled := make(chan struct{}, 1)
	secondCalled := make(chan struct{}, 1)
	firstID := hub.addSubscriber("https://panel.example/", func() { firstCalled <- struct{}{} })
	secondID := hub.addSubscriber("https://other.example", func() { secondCalled <- struct{}{} })
	defer hub.removeSubscriber(firstID)
	defer hub.removeSubscriber(secondID)

	hub.dispatch(`{"version":1,"action":"device.unbound","api_host":"https://panel.example"}`)
	select {
	case <-firstCalled:
	case <-time.After(time.Second):
		t.Fatal("matching logical node did not receive the device sync event")
	}
	select {
	case <-secondCalled:
		t.Fatal("device sync event leaked to a logical node on another panel")
	case <-time.After(25 * time.Millisecond):
	}
}
