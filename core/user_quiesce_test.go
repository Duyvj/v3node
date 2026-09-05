package core

import (
	"context"
	"net"
	"testing"
	"time"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/Duyvj/v3node/common/format"
	"github.com/Duyvj/v3node/conf"
)

func TestQuiesceUsersReturnsEveryInstalledBarrierAfterPartialRemoval(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	info := &panel.NodeInfo{
		Id: 1, Tag: "partial-delete", Type: "vmess",
		PushInterval: time.Hour, PullInterval: time.Hour,
		Common: &panel.CommonNode{ListenIP: "127.0.0.1", ServerPort: port},
	}
	instance := New(conf.New())
	if err := instance.Start([]*panel.NodeInfo{info}); err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	if err := instance.AddNode(info.Tag, info); err != nil {
		t.Fatal(err)
	}
	users := []panel.UserInfo{
		{Id: 1, Uuid: "00000000-0000-0000-0000-000000000001"},
		// This credential is intentionally absent from the runtime manager, so
		// removing it fails only after the first credential was removed.
		{Id: 2, Uuid: "00000000-0000-0000-0000-000000000002"},
		{Id: 3, Uuid: "00000000-0000-0000-0000-000000000003"},
	}
	if _, err := instance.AddUsers(&AddUsersParams{
		Tag: info.Tag, Users: users, NodeInfo: info,
	}); err != nil {
		t.Fatal(err)
	}
	manager, err := instance.GetUserManager(info.Tag)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RemoveUser(context.Background(), format.UserTag(info.Tag, users[1].Uuid)); err != nil {
		t.Fatal(err)
	}

	barriered, err := instance.QuiesceUsers(users, info.Tag)
	if err == nil {
		t.Fatal("partial runtime removal unexpectedly succeeded")
	}
	if len(barriered) != 3 || barriered[0].Uuid != users[0].Uuid ||
		barriered[1].Uuid != users[1].Uuid || barriered[2].Uuid != users[2].Uuid {
		t.Fatalf("installed barriers were not returned for rollback safety: %#v", barriered)
	}
	for _, user := range barriered {
		if _, ok := instance.users.uidMap[format.UserTag(info.Tag, user.Uuid)]; !ok {
			t.Fatalf("traffic ownership was forgotten before durable finalization: %s", user.Uuid)
		}
	}
	for _, index := range []int{0, 2} {
		if _, ok := instance.users.quiesced[format.UserTag(info.Tag, users[index].Uuid)]; !ok {
			t.Fatalf("user after partial removal failure was not revoked: %s", users[index].Uuid)
		}
	}
}
