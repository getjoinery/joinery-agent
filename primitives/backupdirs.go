package primitives

import (
	"context"
	"path/filepath"
	"strings"
)

// Where this node's backups live: {siteRoot}/backups, the same directory the
// platform builds them in (BackupRunner::output_dir), with the bare /backups
// constant only as a last resort when the site root is unknown. Each profile
// then gets its own directory under that base (BackupProfile::output_dir): the
// site profile IS the base, the manager profile is `manager/` inside it.
//
// It is never read from the site's settings. The agent lists, deletes and
// restores from here as root, and the site's web tier can write its settings
// table: a base read from there would be a place a web write sends root.
//
// The plane names no path either: it names a PROFILE, which is one of two
// values the node maps to a directory.

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

// backupBase resolves the node's backup working directory from its site root.
func backupBase(_ context.Context, env *ExecEnv) string {
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
