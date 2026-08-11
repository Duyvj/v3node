//go:build linux

package app

import "testing"

func TestSystemMemoryBytes(t *testing.T) {
	if got := systemMemoryBytes(); got == 0 {
		t.Fatal("sysinfo returned no physical memory")
	}
}
