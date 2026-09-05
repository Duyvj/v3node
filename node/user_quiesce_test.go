package node

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/Duyvj/v3node/conf"
	vcore "github.com/Duyvj/v3node/core"
	"github.com/Duyvj/v3node/limiter"
)

func TestQuiescedUserIsReactivatedAfterSpoolFailureAndPanelReadd(t *testing.T) {
	validSpoolDirectory := withTemporaryTrafficSpool(t)
	const credential = "00000000-0000-0000-0000-000000000001"
	var userState atomic.Int32
	userState.Store(1)

	panelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/v1/server/UniProxy/user":
			if userState.Load() == 0 {
				_, _ = w.Write([]byte(`{"users":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{"users":[{"id":7,"uuid":"` + credential + `","speed_limit":0,"device_limit":1}]}`))
		case "/api/v1/server/UniProxy/alivelist":
			_, _ = w.Write([]byte(`{"alive":{}}`))
		default:
			http.NotFound(w, request)
		}
	}))
	defer panelServer.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	nodeConfig := &conf.NodeConfig{
		APIHost: panelServer.URL, NodeID: 21, Key: "agent-token", AgentID: "agent-a",
	}
	client, err := panel.New(nodeConfig)
	if err != nil {
		t.Fatal(err)
	}
	info := &panel.NodeInfo{
		Id: 21, Tag: "node-21", Type: "vmess", PushInterval: time.Hour, PullInterval: time.Hour,
		Common: &panel.CommonNode{ListenIP: "127.0.0.1", ServerPort: port},
	}
	controller := NewController(client, nodeConfig, info)
	if err := controller.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}

	limiter.Init()
	core := vcore.New(conf.New())
	core.ReloadCh = make(chan struct{}, 1)
	if err := core.Start([]*panel.NodeInfo{info}); err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	if err := controller.Start(core); err != nil {
		t.Fatal(err)
	}
	defer controller.Close()

	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}
	trafficSpoolDirectory = blocked
	userState.Store(0)
	if err := controller.syncUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(controller.quiescedUsers) != 1 || len(controller.userList) != 1 {
		t.Fatalf("failed deletion did not retain retry state: quiesced=%#v active=%#v",
			controller.quiescedUsers, controller.userList)
	}

	trafficSpoolDirectory = validSpoolDirectory
	userState.Store(1)
	if err := controller.syncUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(controller.quiescedUsers) != 0 || len(controller.userList) != 1 || controller.userList[0].Uuid != credential {
		t.Fatalf("re-added user remained quiesced: quiesced=%#v active=%#v",
			controller.quiescedUsers, controller.userList)
	}
}
