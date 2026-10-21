package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The unit's start guard (restart audit H2): a binary a self-update installed
// that cannot even answer --version is replaced by the kept previous one before
// systemd starts it, since the agent's own watchdog lives in main and such a
// binary never gets there. These run the guard exactly as the unit carries it,
// pointed at a temporary install path.

func startGuardCommand(t *testing.T, install string) string {
	t.Helper()
	data, err := os.ReadFile("install/joinery-agent.service")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "ExecStartPre=-/bin/sh -c '") {
			continue
		}
		cmd := strings.TrimSuffix(strings.TrimPrefix(line, "ExecStartPre=-/bin/sh -c '"), "'")
		cmd = strings.ReplaceAll(cmd, "$$", "$") // systemd's escape for a literal $
		return strings.ReplaceAll(cmd, "/usr/local/bin/joinery-agent", install)
	}
	t.Fatal("the unit carries no start guard")
	return ""
}

func runStartGuard(t *testing.T, newBinary string, pending bool) (dir, install string) {
	t.Helper()
	dir = t.TempDir()
	install = filepath.Join(dir, "joinery-agent")
	os.WriteFile(install, []byte(newBinary), 0755)
	os.WriteFile(install+".bak", []byte("#!/bin/sh\necho 'joinery-agent 1.0.0'\n"), 0755)
	if pending {
		os.WriteFile(install+".pending", []byte("2.0.0\n1\n"), 0644)
	}
	if out, err := exec.Command("/bin/sh", "-c", startGuardCommand(t, install)).CombinedOutput(); err != nil {
		t.Fatalf("the guard itself failed: %v %s", err, out)
	}
	return dir, install
}

func TestStartGuardRestoresABinaryThatCannotStart(t *testing.T) {
	_, install := runStartGuard(t, "#!/bin/sh\nexit 2\n", true)
	if data, _ := os.ReadFile(install); !strings.Contains(string(data), "1.0.0") {
		t.Fatal("the previous binary should be back in place")
	}
	if data, _ := os.ReadFile(install + ".rejected"); strings.TrimSpace(string(data)) != "2.0.0" {
		t.Fatalf("the new version should be marked rejected, got %q", data)
	}
	for _, f := range []string{".pending", ".bak"} {
		if _, err := os.Stat(install + f); !os.IsNotExist(err) {
			t.Fatalf("%s should be gone", f)
		}
	}
}

func TestStartGuardLeavesAWorkingBinaryOnTrial(t *testing.T) {
	_, install := runStartGuard(t, "#!/bin/sh\necho 'joinery-agent 2.0.0'\n", true)
	if data, _ := os.ReadFile(install); !strings.Contains(string(data), "2.0.0") {
		t.Fatal("a binary that starts stays; the trial is the agent's to judge")
	}
	if _, err := os.Stat(install + ".pending"); err != nil {
		t.Fatal("the trial marker is the agent's, not the guard's")
	}
}

func TestStartGuardDoesNothingWithoutATrial(t *testing.T) {
	_, install := runStartGuard(t, "#!/bin/sh\nexit 2\n", false)
	if data, _ := os.ReadFile(install); !strings.Contains(string(data), "exit 2") {
		t.Fatal("with no swap on trial the guard has no business replacing anything")
	}
}

// Restart audit H6: a machine with no site restores its unit from the copy
// built into the binary. That copy must be the released unit, start guard and
// all, or the restore would put back something weaker than what it replaces.
func TestTheEmbeddedUnitIsTheReleasedOne(t *testing.T) {
	onDisk, err := os.ReadFile("install/joinery-agent.service")
	if err != nil {
		t.Fatal(err)
	}
	if string(embeddedUnit) != string(onDisk) {
		t.Fatal("the unit built into the binary differs from install/joinery-agent.service")
	}
	for _, want := range []string{"Restart=always", "ExecStartPre=-/bin/sh -c", "ExecStart=/usr/local/bin/joinery-agent", "WantedBy=multi-user.target"} {
		if !strings.Contains(string(embeddedUnit), want) {
			t.Errorf("the embedded unit lacks %q", want)
		}
	}
}
