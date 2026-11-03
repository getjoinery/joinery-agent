package main

import (
	"context"
	"log"
	"os"
	"time"

	"joinery-agent/primitives"
)

// The owner's switch over the log words (specs/agent_log_access.md §1) lives in
// the site database; the rule that reads it (primitives/log_access.go) reads a
// root-owned marker instead, so the error log can still be read when the
// database cannot. This watcher keeps that marker a one-way shadow of the
// setting: nothing reads the marker back into the setting, and a database that
// cannot be read leaves the last projection standing.

const (
	settingLogAccess = primitives.SettingLogAccess

	// How often the agent re-reads the setting. Matches the join/leave
	// watchers: an owner who turns log access off should see it take effect,
	// not wonder.
	logAccessCheckInterval = 5 * time.Second
)

// agentStateDir is where the agent keeps its root-owned state files.
func agentStateDir() string {
	if dir := os.Getenv("AGENT_STATE_DIR"); dir != "" {
		return dir
	}
	return "/etc/joinery-agent"
}

// LogAccessWatcher keeps the log-access marker in step with the setting.
type LogAccessWatcher struct {
	db *DB
}

func (w *LogAccessWatcher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(logAccessCheckInterval):
		}
		if value, err := readAgentSetting(w.db, settingLogAccess); err == nil {
			projectLogAccessFromSetting(value)
		}
	}
}

// projectLogAccessFromSetting writes the log-access marker from a stored
// setting value, read with the same spellings as every other switch.
func projectLogAccessFromSetting(value string) {
	if err := primitives.ProjectLogAccess(primitives.SettingOn(value)); err != nil {
		log.Printf("WARNING: could not project the log-access switch to %s: %v", primitives.LogAccessMarkerPath(), err)
	}
}
