package app

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// HostMemoryBytes returns the memory available to the current Linux service.
// In a cgroup v2/v1 container it uses the lower of MemTotal and the cgroup
// limit, so the controller's soft Go heap target does not accidentally use the
// physical host size. Zero means that neither source was available.
func HostMemoryBytes() uint64 {
	return hostMemoryBytes(
		"/proc/meminfo",
		"/proc/self/cgroup",
		"/sys/fs/cgroup",
		systemMemoryBytes,
	)
}

func hostMemoryBytes(meminfoPath, cgroupPath, cgroupRoot string, fallback func() uint64) uint64 {
	host := readMemTotal(meminfoPath)
	if host == 0 && fallback != nil {
		// ProcSubset=pid deliberately hides /proc/meminfo in the service's
		// mount namespace. Linux can still report the same physical-memory
		// value through sysinfo(2).
		host = fallback()
	}
	cgroup := readCgroupMemoryLimit(cgroupPath, cgroupRoot)
	if host == 0 {
		return cgroup
	}
	if cgroup != 0 && cgroup < host {
		return cgroup
	}
	return host
}

func readMemTotal(path string) uint64 {
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kib, err := strconv.ParseUint(fields[1], 10, 64)
			if err == nil && kib <= ^uint64(0)/1024 {
				return kib * 1024
			}
			return 0
		}
	}
	return 0
}

func readCgroupMemoryLimit(cgroupPath, cgroupRoot string) uint64 {
	file, err := os.Open(cgroupPath)
	if err != nil {
		return 0
	}
	defer file.Close()

	var unifiedPath, legacyPath string
	scanner := bufio.NewScanner(io.LimitReader(file, 64<<10))
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			unifiedPath = parts[2]
			continue
		}
		for _, controller := range strings.Split(parts[1], ",") {
			if controller == "memory" {
				legacyPath = parts[2]
				break
			}
		}
	}
	if unifiedPath != "" {
		if limit := readCgroupLimitFile(cgroupRoot, unifiedPath, "memory.max"); limit != 0 {
			return limit
		}
	}
	if legacyPath != "" {
		if limit := readCgroupLimitFile(filepath.Join(cgroupRoot, "memory"), legacyPath, "memory.limit_in_bytes"); limit != 0 {
			return limit
		}
		return readCgroupLimitFile(cgroupRoot, legacyPath, "memory.limit_in_bytes")
	}
	return 0
}

func readCgroupLimitFile(root, groupPath, name string) uint64 {
	root = filepath.Clean(root)
	relative := strings.TrimPrefix(filepath.Clean("/"+groupPath), string(filepath.Separator))
	path := filepath.Join(root, relative, name)
	withinRoot, err := filepath.Rel(root, path)
	if err != nil || withinRoot == ".." || strings.HasPrefix(withinRoot, ".."+string(filepath.Separator)) {
		return 0
	}
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 128))
	if err != nil && !errors.Is(err, io.EOF) {
		return 0
	}
	value := strings.TrimSpace(string(data))
	if value == "" || value == "max" {
		return 0
	}
	limit, err := strconv.ParseUint(value, 10, 64)
	if err != nil || limit == 0 {
		return 0
	}
	return limit
}
