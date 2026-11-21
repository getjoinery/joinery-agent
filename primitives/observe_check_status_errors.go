package primitives

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// collectErrorCounts counts the site's error-table rows of each kind in the
// last 24 hours (specs/agent_recipes_and_vocabulary.md, 2026-11-21: nothing
// said whether any site's visitors were being refused by the script policy
// without asking each node for its rows). The kinds and their conditions are
// log_table_tail's compiled list, so the count and the rows that word returns
// answer the same question. Numbers only: no message leaves the node here.
// False when the table cannot be read, which the plane reads as "not
// measured", never as a site with no errors.
func collectErrorCounts(ctx context.Context, db *sql.DB) (map[string]interface{}, bool) {
	selects := make([]string, len(logKindNames))
	for i, kind := range logKindNames {
		selects[i] = fmt.Sprintf("count(*) FILTER (WHERE %s)", logKinds[kind])
	}
	counts := make([]int64, len(logKindNames))
	ptrs := make([]interface{}, len(counts))
	for i := range counts {
		ptrs[i] = &counts[i]
	}
	err := db.QueryRowContext(ctx, "SELECT "+strings.Join(selects, ", ")+
		" FROM err_general_errors WHERE err_create_time >= now() - interval '24 hours'").Scan(ptrs...)
	if err != nil {
		return nil, false
	}
	out := make(map[string]interface{}, len(counts))
	for i, kind := range logKindNames {
		out[kind] = counts[i]
	}
	return out, true
}
