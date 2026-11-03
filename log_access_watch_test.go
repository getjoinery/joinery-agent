package main

import (
	"os"
	"path/filepath"
	"testing"

	"joinery-agent/primitives"
)

// The log-access switch (specs/agent_log_access.md) is projected into a marker
// in the agent's state directory, so the log words can be gated without a
// database.
func TestLogAccessIsProjectedIntoTheStateDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_STATE_DIR", dir)

	projectLogAccessFromSetting("1")
	data, err := os.ReadFile(filepath.Join(dir, "log_access"))
	if err != nil {
		t.Fatalf("marker unreadable: %v", err)
	}
	if string(data) != "1\n" {
		t.Fatalf("marker should hold the projected value, got %q", data)
	}
	projectLogAccessFromSetting("")
	data, _ = os.ReadFile(filepath.Join(dir, "log_access"))
	if string(data) != "0\n" {
		t.Fatalf("an empty setting projects off, got %q", data)
	}
	if filepath.Dir(primitives.LogAccessMarkerPath()) != agentStateDir() {
		t.Fatal("the log-access marker must live in the agent's state directory")
	}
}
