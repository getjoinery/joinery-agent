package primitives

import (
	"context"
	"database/sql"
)

// SettingRootAccess is the site owner's answer to "keep emergency root access
// while Joinery is in beta" (specs/implemented/beta_break_glass_root_access.md 4.2, 5.1):
// a managed setting on the node's own settings table, written only by the
// node's own setup wizard and Management Node page. Compiled in, never on the
// wire.
const SettingRootAccess = "beta_root_access"

// RootAccessReport is what every poll says about that answer: "on" or "off"
// when the database answers and the row exists, "" otherwise. There is no
// marker and no fail-closed default, unlike log access: the plane keeps the
// last answer it was given, so a database outage never reads as the owner
// turning it off. Nothing on the node acts on it; the plane shows it to the
// operator who holds the password, who retires it.
func RootAccessReport(ctx context.Context, env *ExecEnv) string {
	if env == nil || env.DB == nil {
		return ""
	}
	db, err := env.DB()
	if err != nil || db == nil {
		return ""
	}
	var value sql.NullString
	if err := db.QueryRowContext(ctx,
		"SELECT stg_value FROM stg_settings WHERE stg_name = $1", SettingRootAccess).Scan(&value); err != nil {
		return ""
	}
	if SettingOn(value.String) {
		return "on"
	}
	return "off"
}
