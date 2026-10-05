package primitives

import (
	"os"
	"path/filepath"
	"testing"
)

// A container's status check reports the site's own memory: its cgroup's use
// out of its limit, not the shared server's /proc/meminfo.
func TestCollectMemoryInAContainerIsTheSites(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The server: 4 GiB, 3 GiB available.
	write("meminfo", "MemTotal:        4194304 kB\nMemAvailable:    3145728 kB\nSwapTotal:       1048576 kB\nSwapFree:         524288 kB\n")
	write("memory.current", "314572800\n")                      // 300 MiB held
	write("memory.stat", "anon 100\ninactive_file 104857600\n") // 100 MiB of it cache
	write("memory.max", "268435456\n")                          // 256 MiB limit
	write("dockerenv", "")

	saved := []string{meminfoPath, dockerEnvPath, ownCgroupDir}
	defer func() { meminfoPath, dockerEnvPath, ownCgroupDir = saved[0], saved[1], saved[2] }()
	meminfoPath, ownCgroupDir = filepath.Join(dir, "meminfo"), dir

	// Outside a container: the machine, as always.
	dockerEnvPath = filepath.Join(dir, "absent")
	r := map[string]interface{}{}
	collectMemory(r)
	if r["memory_total_mb"] != int64(4096) || r["memory_used_mb"] != int64(1024) {
		t.Fatalf("outside a container the figures are the machine's, got %v", r)
	}

	// In a container with a limit: 200 MiB used of 256.
	dockerEnvPath = filepath.Join(dir, "dockerenv")
	r = map[string]interface{}{}
	collectMemory(r)
	if r["memory_total_mb"] != int64(256) || r["memory_used_mb"] != int64(200) || r["memory_free_mb"] != int64(56) {
		t.Fatalf("a limited container reports its own use and limit, got %v", r)
	}
	if r["swap_total_mb"] != int64(1024) {
		t.Fatalf("swap stays the server's, got %v", r)
	}

	// In a container with no limit: its own use, out of the whole server.
	write("memory.max", "max\n")
	r = map[string]interface{}{}
	collectMemory(r)
	if r["memory_total_mb"] != int64(4096) || r["memory_used_mb"] != int64(200) {
		t.Fatalf("an unlimited container reports its own use out of the server, got %v", r)
	}
}
