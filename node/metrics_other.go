//go:build !linux

package node

import "runtime"

func readPlatformSnapshot() platformSnapshot {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return platformSnapshot{
		memoryUsed:    memory.Alloc,
		memoryTotal:   memory.Sys,
		processMemory: memory.Sys,
	}
}
