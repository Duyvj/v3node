package node

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/Duyvj/v3node/conf"
	vcore "github.com/Duyvj/v3node/core"
	"github.com/Duyvj/v3node/limiter"
)

func TestControllerPrepareAllowsEmptyUserList(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/user":
			_, _ = w.Write([]byte(`{"users":[]}`))
		case "/api/v1/server/UniProxy/alivelist":
			_, _ = w.Write([]byte(`{"alive":{}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	nodeConfig := &conf.NodeConfig{APIHost: server.URL, NodeID: 12, Key: "agent-token", AgentID: "agent-a"}
	client, err := panel.New(nodeConfig)
	if err != nil {
		t.Fatal(err)
	}
	info := &panel.NodeInfo{
		Id:           12,
		Tag:          "node-12",
		Type:         "vmess",
		PushInterval: time.Hour,
		PullInterval: time.Hour,
		Common: &panel.CommonNode{
			ListenIP:   "127.0.0.1",
			ServerPort: port,
		},
	}
	controller := NewController(client, nodeConfig, info)
	if err := controller.Prepare(context.Background()); err != nil {
		t.Fatalf("empty user list should be valid: %v", err)
	}
	if !controller.prepared || controller.userList == nil || len(controller.userList) != 0 {
		t.Fatalf("controller did not preserve an intentional empty user list: %+v", controller.userList)
	}

	limiter.Init()
	core := vcore.New(conf.New())
	core.ReloadCh = make(chan struct{}, 1)
	if err := core.Start([]*panel.NodeInfo{info}); err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	if err := controller.Start(core); err != nil {
		t.Fatalf("empty-user inbound should start and wait for user sync: %v", err)
	}
	if !controller.started {
		t.Fatal("empty-user controller did not start")
	}
	if err := controller.Close(); err != nil {
		t.Fatal(err)
	}
}
