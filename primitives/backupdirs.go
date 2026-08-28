package primitives

import (
	"context"
	"path/filepath"
	"strings"
)

// Where this node's backups actually live.
//
// NOT a constant, which is the mistake this file exists to correct. The platform
// resolves it as: the `backup_output_dir` setting when set, otherwise
// {siteRoot}/backups computed from the site root, and only as a last resort the
// bare /backups constant (BackupRunner::output_dir / default_output_dir). Each
// profile then gets its own directory under that base
// (BackupProfile::output_dir): the site profile IS the base, the manager profile
// is `manager/` inside it.
//
// The agent used to compile in "/backups" and read only that. On a container
// node the computed default puts backups at {siteRoot}/backups, and /backups
// does not exist at all — so list_backups truthfully reported an empty directory
// while the node held backups, and upload_backup and delete_backup could never
// see the very archives this control plane takes. It stayed invisible because
// one bare-metal node happened to match the old assumption.
//
// The node resolves this itself, from its own setting and its own site root. The
// plane still names no path — it names a PROFILE, which is one of two values the
// node maps to a directory.

// BackupProfile is which party's backups a directory holds.
type BackupProfile string

const (
	// ProfileSite is the site's own backups: the base directory itself.
	ProfileSite BackupProfile = "site"
	// ProfileManager is a control plane's, in `manager/` beneath the base.
	ProfileManager BackupProfile = "manager"
)

// managerSubdir mirrors BackupProfile::MANAGER_SUBDIR.
const managerSubdir = "manager"

// fallbackBackupDir mirrors BackupRunner::OUTPUT_DIR, used only when the site
// root cannot be resolved — the same last resort the platform takes.
const fallbackBackupDir = "/backups"

// backupBase resolves the node's backup working directory.
//
// The setting is read from the node's own database. A database that is down is
// not an answer, so it falls through to the computed default rather than
// guessing — the same shape as everywhere else here: degrade, do not invent.
func backupBase(ctx context.Context, env *ExecEnv) string {
	if env != nil && env.DB != nil {
		if db, err := env.DB(); err == nil && db != nil {
			var value string
			row := db.QueryRowContext(ctx,
				"SELECT stg_value FROM stg_settings WHERE stg_name = $1", "backup_output_dir")
			if err := row.Scan(&value); err == nil {
				if dir := strings.TrimRight(strings.TrimSpace(value), "/"); strings.HasPrefix(dir, "/") {
					return dir
				}
			}
		}
	}
	if env != nil && env.SiteRoot != "" {
		return filepath.Join(strings.TrimRight(env.SiteRoot, "/"), "backups")
	}
	return fallbackBackupDir
}

// backupDirFor returns the directory holding one profile's backups.
func backupDirFor(ctx context.Context, env *ExecEnv, profile BackupProfile) string {
	base := backupBase(ctx, env)
	if profile == ProfileManager {
		return filepath.Join(base, managerSubdir)
	}
	return base
}

// backupDirsByProfile returns every directory this node keeps backups in, keyed
// by whose they are. Both are reported because an operator asking "what backups
// exist here" means both, and because a node showing none of its own while the
// plane's pile up is a fact worth seeing.
func backupDirsByProfile(ctx context.Context, env *ExecEnv) map[BackupProfile]string {
	base := backupBase(ctx, env)
	return map[BackupProfile]string{
		ProfileSite:    base,
		ProfileManager: filepath.Join(base, managerSubdir),
	}
}
