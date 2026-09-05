package node

import (
	"strings"
	"testing"

	panel "github.com/Duyvj/v3node/api/v2board"
)

func TestValidateUniqueServerPorts(t *testing.T) {
	infos := []*panel.NodeInfo{
		{Id: 12, Tag: "node-12", Common: &panel.CommonNode{ServerPort: 443}},
		{Id: 18, Tag: "node-18", Common: &panel.CommonNode{ServerPort: 8443}},
	}
	if err := ValidateUniqueServerPorts(infos); err != nil {
		t.Fatalf("unique ports rejected: %v", err)
	}

	infos[1].Common.ServerPort = 443
	err := ValidateUniqueServerPorts(infos)
	if err == nil {
		t.Fatal("expected duplicate port error")
	}
	message := err.Error()
	for _, want := range []string{"443", "12", "18"} {
		if !strings.Contains(message, want) {
			t.Fatalf("error %q does not identify conflict %q", message, want)
		}
	}
}

func TestValidateUniqueServerPortsAllowsZeroNodes(t *testing.T) {
	if err := ValidateUniqueServerPorts(nil); err != nil {
		t.Fatalf("zero-node agent should be valid: %v", err)
	}
}
