package node

import (
	"testing"

	panel "github.com/Duyvj/v3node/api/v2board"
)

func TestCompareUserListKeepsMultipleUUIDsForOneUser(t *testing.T) {
	old := []panel.UserInfo{{Id: 9, Uuid: "uuid-a", DeviceLimit: 2}}
	newUsers := []panel.UserInfo{
		{Id: 9, Uuid: "uuid-a", DeviceLimit: 2},
		{Id: 9, Uuid: "uuid-b", DeviceLimit: 2},
	}

	deleted, added, modified := compareUserList(old, newUsers)
	if len(deleted) != 0 || len(modified) != 0 || len(added) != 1 || added[0].Uuid != "uuid-b" {
		t.Fatalf("unexpected diff: deleted=%#v added=%#v modified=%#v", deleted, added, modified)
	}
}

func TestCompareUserListRefreshesChangedRuntimeID(t *testing.T) {
	old := []panel.UserInfo{{Id: 9, Uuid: "uuid-a"}}
	newUsers := []panel.UserInfo{{Id: 1000000000001, Uuid: "uuid-a"}}

	deleted, added, modified := compareUserList(old, newUsers)
	if len(deleted) != 1 || deleted[0].Id != 9 || len(added) != 1 || added[0].Id != 1000000000001 || len(modified) != 0 {
		t.Fatalf("runtime ID change must remove/add UUID: deleted=%#v added=%#v modified=%#v", deleted, added, modified)
	}
}

func TestCompareUserListDeletesOnlyRequestedUUID(t *testing.T) {
	old := []panel.UserInfo{
		{Id: 9, Uuid: "uuid-a"},
		{Id: 9, Uuid: "uuid-b"},
	}
	newUsers := []panel.UserInfo{{Id: 9, Uuid: "uuid-b"}}

	deleted, added, modified := compareUserList(old, newUsers)
	if len(deleted) != 1 || deleted[0].Uuid != "uuid-a" || len(added) != 0 || len(modified) != 0 {
		t.Fatalf("deleting one UUID affected its sibling: deleted=%#v added=%#v modified=%#v", deleted, added, modified)
	}
}

func TestOnlineUsersMeetingTrafficThresholdUsesAggregatedSnapshot(t *testing.T) {
	online := []panel.OnlineUser{
		{UID: 9, IP: "192.0.2.1"},
		{UID: 10, IP: "192.0.2.2"},
	}
	trafficByUID := map[int]int64{9: 2_500, 10: 999}

	got := onlineUsersMeetingTrafficThreshold(online, trafficByUID, 2)
	if len(got) != 1 || got[0].UID != 9 {
		t.Fatalf("expected only UID 9 to meet the online threshold, got %#v", got)
	}
}
