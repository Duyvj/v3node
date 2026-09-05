//go:build linux

package node

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

func readPlatformSnapshot() platformSnapshot {
	snapshot := platformSnapshot{}
	readCPU(&snapshot)
	readMemory(&snapshot)
	readDisk(&snapshot)
	readNetwork(&snapshot)
	readUptimeAndLoad(&snapshot)
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	snapshot.processMemory = memory.Sys
	return snapshot
}

func readCPU(snapshot *platformSnapshot) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return
	}
	fields := strings.Fields(strings.SplitN(string(data), "\n", 2)[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return
	}
	for index, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return
		}
		snapshot.cpuTotal += value
		if index == 3 || index == 4 {
			snapshot.cpuIdle += value
		}
	}
}

func readMemory(snapshot *platformSnapshot) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer file.Close()
	var total, available uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			total = value * 1024
		case "MemAvailable":
			available = value * 1024
		}
	}
	snapshot.memoryTotal = total
	if total >= available {
		snapshot.memoryUsed = total - available
	}
}

func readDisk(snapshot *platformSnapshot) {
	var stat syscall.Statfs_t
	if syscall.Statfs("/", &stat) != nil {
		return
	}
	snapshot.diskTotal = stat.Blocks * uint64(stat.Bsize)
	available := stat.Bavail * uint64(stat.Bsize)
	if snapshot.diskTotal >= available {
		snapshot.diskUsed = snapshot.diskTotal - available
	}
}

func readNetwork(snapshot *platformSnapshot) {
	defaultInterface := defaultNetworkInterface()
	file, err := os.Open("/proc/net/dev")
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			parts := strings.SplitN(scanner.Text(), ":", 2)
			interfaceName := strings.TrimSpace(parts[0])
			if len(parts) != 2 || interfaceName == "lo" || (defaultInterface != "" && interfaceName != defaultInterface) {
				continue
			}
			fields := strings.Fields(parts[1])
			if len(fields) < 9 {
				continue
			}
			rx, rxErr := strconv.ParseUint(fields[0], 10, 64)
			tx, txErr := strconv.ParseUint(fields[8], 10, 64)
			if rxErr == nil {
				snapshot.networkRX += rx
			}
			if txErr == nil {
				snapshot.networkTX += tx
			}
		}
	}
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.Name() == "lo" || (defaultInterface != "" && entry.Name() != defaultInterface) {
			continue
		}
		data, err := os.ReadFile("/sys/class/net/" + entry.Name() + "/speed")
		if err != nil {
			continue
		}
		speed, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		if err == nil && speed > 0 {
			snapshot.networkLinkSpeedMbps += uint64(speed)
		}
	}
}

func defaultNetworkInterface() string {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[1] == "00000000" {
			flags, err := strconv.ParseUint(fields[3], 16, 64)
			if err == nil && flags&1 != 0 {
				return fields[0]
			}
		}
	}
	return ""
}

func readUptimeAndLoad(snapshot *platformSnapshot) {
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			if value, err := strconv.ParseFloat(fields[0], 64); err == nil && value > 0 {
				snapshot.uptimeSeconds = uint64(value)
			}
		}
	}
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			snapshot.load1, _ = strconv.ParseFloat(fields[0], 64)
		}
	}
}
