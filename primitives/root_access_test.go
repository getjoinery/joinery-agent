package primitives

import (
	"context"
	"errors"
	"testing"
)

// The owner's emergency root access answer rides every poll: on or off from
// the setting when the database answers, nothing at all when it does not or
// the row is not there, so the plane's last answer stands
// (specs/implemented/beta_break_glass_root_access.md 5.1).
func TestRootAccessReportAnswersFromTheSettingOrNotAtAll(t *testing.T) {
	ctx := context.Background()
	if got := RootAccessReport(ctx, &ExecEnv{DB: fakeDB(settingAnswer("1"), nil)}); got != "on" {
		t.Fatalf("the setting at 1 is on, got %q", got)
	}
	if got := RootAccessReport(ctx, &ExecEnv{DB: fakeDB(settingAnswer("0"), nil)}); got != "off" {
		t.Fatalf("the setting at 0 is off, got %q", got)
	}
	noRow := map[string]fakeRows{"FROM stg_settings WHERE stg_name = $1": {columns: []string{"stg_value"}}}
	if got := RootAccessReport(ctx, &ExecEnv{DB: fakeDB(noRow, nil)}); got != "" {
		t.Fatalf("no row is no answer, got %q", got)
	}
	if got := RootAccessReport(ctx, &ExecEnv{DB: fakeDB(nil, errors.New("connection refused"))}); got != "" {
		t.Fatalf("a database that does not answer is no answer, got %q", got)
	}
	if got := RootAccessReport(ctx, &ExecEnv{}); got != "" {
		t.Fatalf("no database resolver is no answer, got %q", got)
	}
}
