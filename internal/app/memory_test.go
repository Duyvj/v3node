package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadMemTotal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meminfo")
	if err := os.WriteFile(path, []byte("MemFree: 10 kB\nMemTotal: 2097152 kB\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readMemTotal(path); got != 2<<30 {
		t.Fatalf("readMemTotal = %d, want %d", got, uint64(2<<30))
	}
}

func TestHostMemoryUsesFallbackWhenProcMeminfoIsHidden(t *testing.T) {
	directory := t.TempDir()
	cgroupPath := filepath.Join(directory, "self.cgroup")
	root := filepath.Join(directory, "cgroup")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cgroupPath, []byte("0::/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "memory.max"), []byte("max\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	const physical = uint64(4 << 30)
	got := hostMemoryBytes(
		filepath.Join(directory, "proc-meminfo-is-hidden"),
		cgroupPath,
		root,
		func() uint64 { return physical },
	)
	if got != physical {
		t.Fatalf("host memory with hidden meminfo = %d, want %d", got, physical)
	}
}

func TestHostMemoryPrefersCgroupLimitOverFallback(t *testing.T) {
	directory := t.TempDir()
	cgroupPath := filepath.Join(directory, "self.cgroup")
	root := filepath.Join(directory, "cgroup")
	group := filepath.Join(root, "system.slice", "v3node.service")
	if err := os.MkdirAll(group, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cgroupPath, []byte("0::/system.slice/v3node.service\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(group, "memory.max"), []byte("536870912\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := hostMemoryBytes(
		filepath.Join(directory, "proc-meminfo-is-hidden"),
		cgroupPath,
		root,
		func() uint64 { return 4 << 30 },
	)
	if got != 512<<20 {
		t.Fatalf("host memory with cgroup limit = %d, want %d", got, uint64(512<<20))
	}
}

func TestReadCgroupV2MemoryLimit(t *testing.T) {
	directory := t.TempDir()
	cgroupPath := filepath.Join(directory, "self.cgroup")
	root := filepath.Join(directory, "cgroup")
	group := filepath.Join(root, "system.slice", "v3node.service")
	if err := os.MkdirAll(group, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cgroupPath, []byte("0::/system.slice/v3node.service\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(group, "memory.max"), []byte("536870912\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readCgroupMemoryLimit(cgroupPath, root); got != 512<<20 {
		t.Fatalf("cgroup v2 memory limit = %d, want %d", got, uint64(512<<20))
	}
}

func TestReadCgroupUnlimitedAndTraversal(t *testing.T) {
	directory := t.TempDir()
	cgroupPath := filepath.Join(directory, "self.cgroup")
	root := filepath.Join(directory, "cgroup")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cgroupPath, []byte("0::/../../outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "memory.max"), []byte("max\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readCgroupMemoryLimit(cgroupPath, root); got != 0 {
		t.Fatalf("unlimited/traversal cgroup = %d, want 0", got)
	}
}
