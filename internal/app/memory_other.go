//go:build !linux

package app

func systemMemoryBytes() uint64 {
	return 0
}
