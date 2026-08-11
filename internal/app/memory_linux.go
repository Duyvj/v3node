//go:build linux

package app

import (
	"math"

	"golang.org/x/sys/unix"
)

func systemMemoryBytes() uint64 {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return 0
	}
	total := uint64(info.Totalram)
	unit := uint64(info.Unit)
	if unit == 0 {
		// Linux has always documented mem_unit as a byte multiplier. Treat a
		// zero value defensively as one byte, as older compatibility code does.
		unit = 1
	}
	if total > math.MaxUint64/unit {
		return 0
	}
	return total * unit
}
