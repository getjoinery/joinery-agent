package primitives

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
)

// The owner's switch over every word that reads a log (specs/agent_log_access.md
// §1). One setting, agent_log_access, on the node's own settings table and
// written from the node's own Management Node admin page; on by default.
//
// THE RULE, in one place, called by every log-reading word and by the poll
// claim that tells the plane where the switch stands:
//
//	setting when the database answers; marker when it does not; OFF when
//	neither exists.
//
// The marker is the setting projected one way into a root-owned file by the
// agent's switch watcher, on the same cadence as the run switch's marker. It
// exists because the error log is wanted most when the database is down, and a
// word that had to ask the database for permission to read the error log would
// be refused at exactly that moment.
//
// A MISSING marker reads OFF, not on. The run switch's marker reads
// missing-as-on for an upgrade-safety reason (stopping working agents at
// upgrade) that does not apply here: a node upgraded to this agent projects the
// marker within seconds of its database being up, and a node whose database has
// never been up since the upgrade has nothing a log word should be reading on a
// plane's say-so. Fail closed on missing proof (vocabulary rule 3).

const (
	// SettingLogAccess is the setting's name. Compiled in, never on the wire.
	SettingLogAccess = "agent_log_access"

	// logAccessMarkerName is the marker file's name inside the agent's state
	// directory, beside the run switch's "enabled".
	logAccessMarkerName = "log_access"

	// LogAccessRefusal is the reason every log word gives when the switch is
	// off. Pinned as a constant so the plane can match it and render the
	// owner's decision rather than a generic refusal.
	LogAccessRefusal = "this site's owner has not allowed log access (agent_log_access is off)"
)

// LogAccessMarkerPath is where the projected switch lives: the agent's state
// directory (AGENT_STATE_DIR in tests, /etc/joinery-agent on a machine), the
// same directory the run switch's marker uses, resolved the same way.
func LogAccessMarkerPath() string {
	dir := os.Getenv("AGENT_STATE_DIR")
	if dir == "" {
		dir = "/etc/joinery-agent"
	}
	return filepath.Join(dir, logAccessMarkerName)
}

// SettingOn reads a stored on/off setting value with the spellings every other
// reader of such a setting uses (the run switch, install_agent.sh, the admin
// page). One setting read two ways is how a machine disagrees with the page
// that configured it; the parent package pins its reader equal to this one.
func SettingOn(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// ProjectLogAccess writes the marker from a setting value. One-way: nothing
// reads the marker back into the setting.
func ProjectLogAccess(on bool) error {
	path := LogAccessMarkerPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if on {
		return os.WriteFile(path, []byte("1\n"), 0644)
	}
	return os.WriteFile(path, []byte("0\n"), 0644)
}

// LogAccessOn answers the rule above. The second value says which source
// answered, for the log line and for tests: "setting", "marker" or "none".
func LogAccessOn(ctx context.Context, env *ExecEnv) (on bool, source string) {
	if env != nil && env.DB != nil {
		if db, err := env.DB(); err == nil && db != nil {
			var value sql.NullString
			err := db.QueryRowContext(ctx,
				"SELECT stg_value FROM stg_settings WHERE stg_name = $1", SettingLogAccess).Scan(&value)
			switch {
			case err == nil:
				return SettingOn(value.String), "setting"
			case err == sql.ErrNoRows:
				// The database answered and has no row: the setting has not
				// been seeded on this node yet. That is "no proof", not "on".
				return false, "setting"
			}
			// Any other error is the database not answering: fall through
			// to the marker.
		}
	}
	data, err := os.ReadFile(LogAccessMarkerPath())
	if err != nil {
		return false, "none"
	}
	return SettingOn(string(data)), "marker"
}

// requireLogAccess is what every log word calls first. It returns the pinned
// refusal, and nothing has been read when it does.
func requireLogAccess(ctx context.Context, env *ExecEnv) error {
	if on, _ := LogAccessOn(ctx, env); !on {
		return refusedf("%s", LogAccessRefusal)
	}
	return nil
}
