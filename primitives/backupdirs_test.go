package primitives

import (
	"context"
	"database/sql"
	"testing"
)

// The backup base comes from the site root and never from the site's
// database: the web tier can write the settings table, and the agent works in
// this directory as root.
func TestBackupBaseNeverReadsTheSitesSettings(t *testing.T) {
	asked := false
	env := &ExecEnv{
		SiteRoot: "/var/www/html/site/",
		DB: func() (*sql.DB, error) {
			asked = true
			return nil, sql.ErrConnDone
		},
	}
	ctx := context.Background()
	if got := backupBase(ctx, env); got != "/var/www/html/site/backups" {
		t.Fatalf("backupBase = %q, want the site's backups folder", got)
	}
	if got := backupDirFor(ctx, env, ProfileManager); got != "/var/www/html/site/backups/manager" {
		t.Fatalf("manager dir = %q", got)
	}
	if asked {
		t.Fatal("backupBase opened the site's database; the folder must not come from a setting")
	}
	if got := backupBase(ctx, &ExecEnv{}); got != fallbackBackupDir {
		t.Fatalf("no site root: got %q, want %q", got, fallbackBackupDir)
	}
}
