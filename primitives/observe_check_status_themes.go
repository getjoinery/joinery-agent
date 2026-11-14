package primitives

import (
	"context"
	"database/sql"
)

// themeListMax caps the themes check_status carries; a site has a dozen.
const themeListMax = 100

// collectThemes reads thm_themes as collectPlugins reads plg_plugins: each
// theme by name, with its version, whether it is the active one, its status
// and its kind (specs/agent_recipes_and_vocabulary.md, 2026-11-14: nothing
// reported a site's themes). Every string is reduced to a safe character set
// and capped. False when the table cannot be read, which the plane reads as
// "not measured", never as a site with no themes.
func collectThemes(ctx context.Context, db *sql.DB) ([]map[string]interface{}, bool) {
	rows, err := db.QueryContext(ctx,
		"SELECT thm_name, thm_version, thm_is_active, thm_status, thm_kind FROM thm_themes ORDER BY thm_name LIMIT 100")
	if err != nil {
		return nil, false
	}
	defer rows.Close()
	out := []map[string]interface{}{}
	for rows.Next() && len(out) < themeListMax {
		var name string
		var version, status, kind sql.NullString
		var active sql.NullBool
		if err := rows.Scan(&name, &version, &active, &status, &kind); err != nil {
			continue
		}
		name = safeWord(name, 64)
		if name == "" {
			continue
		}
		out = append(out, map[string]interface{}{
			"name":    name,
			"version": safeWord(version.String, 32),
			"active":  active.Valid && active.Bool,
			"status":  safeWord(status.String, 20),
			"kind":    safeWord(kind.String, 20),
		})
	}
	return out, rows.Err() == nil
}
