package primitives

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"golang.org/x/sys/unix"
)

// upgrade_preflight: would an upgrade stop before it started?
// (specs/release_file_repair.md)
//
// A staged rollout asks this of a node before it queues the node's apply, so a
// node that cannot take an upgrade says so before anything is changed. It runs
// the cheap checks an upgrade makes first, as facts about this node only:
//
//   - manifest:    the signed release manifest is usable.
//   - files:       the five self-update files match it (none missing or changed).
//   - version:     the site's VERSION is readable.
//   - lock:        no upgrade holds the upgrade lock.
//   - disk:        room to stage a release.
//   - theme:       the site's active theme is on disk.
//
// Observe, no parameters, bounded output: a fixed object of six checks, each a
// pass or fail and one short reason. It reads one setting (the active theme's
// name), file sizes, and hashes; no file contents, row, or secret leaves the
// node (rule 8).
func init() {
	Register(Primitive{
		Name:        "upgrade_preflight",
		Class:       ClassObserve,
		Description: "Would an upgrade stop before it started: the signed manifest, the five deployment files, the VERSION, the upgrade lock, room to stage a release, and the active theme.",
		Params:      nil,
		Run:         runUpgradePreflight,
	})
}

// minStagingBytes is the room an upgrade needs to stage a release: the same
// floor upgrade.php applies per disk.
const minStagingBytes = 500 << 20

var themeNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

func runUpgradePreflight(ctx context.Context, env *ExecEnv, _ Params) (map[string]interface{}, error) {
	if env == nil || env.SiteRoot == "" {
		return nil, refusedf("upgrade_preflight asks about a site, and this machine has none")
	}
	checks := []map[string]interface{}{}
	add := func(name string, ok bool, reason string) {
		checks = append(checks, map[string]interface{}{"check": name, "ok": ok, "reason": reason})
	}

	if _, err := releaseManifest(env); err != nil {
		add("manifest", false, err.Error())
	} else {
		add("manifest", true, "the signed release manifest is usable")
	}

	if names, checked := DifferingSelfUpdateFiles(env); !checked {
		add("files", false, "not checked: the manifest cannot be used")
	} else if len(names) > 0 {
		add("files", false, "these deployment files differ from the signed release: "+joinNames(names))
	} else {
		add("files", true, "the deployment files match the signed release")
	}

	if v := InstalledVersion(env); v == "" {
		add("version", false, "the site's VERSION cannot be read")
	} else {
		add("version", true, v)
	}

	add("lock", lockFree(filepath.Join(env.SiteRoot, "uploads", ".upgrade.lock")),
		lockReason(filepath.Join(env.SiteRoot, "uploads", ".upgrade.lock")))

	var st unix.Statfs_t
	if err := unix.Statfs(env.SiteRoot, &st); err != nil {
		add("disk", false, "the disk could not be measured")
	} else if avail := int64(st.Bavail) * int64(st.Bsize); avail < minStagingBytes {
		add("disk", false, "less than 500 MB free where the release is staged")
	} else {
		add("disk", true, "room to stage a release")
	}

	tn, tok, treason := themeCheck(ctx, env)
	add(tn, tok, treason)

	ok := true
	for _, c := range checks {
		if !c["ok"].(bool) {
			ok = false
		}
	}
	return map[string]interface{}{"ok": ok, "checks": checks}, nil
}

func joinNames(names []string) string {
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}

// lockFree reports whether nothing holds the upgrade lock: a lock file that does
// not exist is free, and one that can be locked without waiting is free.
func lockFree(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return os.IsNotExist(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return false
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return true
}

func lockReason(path string) string {
	if lockFree(path) {
		return "no upgrade is running"
	}
	return "another upgrade holds the upgrade lock"
}

// themeCheck reads the active theme's name from the site's own settings and
// confirms its directory is on disk. A database that does not answer is not a
// failed check: the theme is then not known, and the reason says so.
func themeCheck(ctx context.Context, env *ExecEnv) (string, bool, string) {
	if env.DB == nil {
		return "theme", true, "not checked: this node has no database connection"
	}
	db, err := env.DB()
	if err != nil || db == nil {
		return "theme", true, "not checked: the site's database did not answer"
	}
	var name string
	if err := db.QueryRowContext(ctx,
		"SELECT stg_value FROM stg_settings WHERE stg_name = 'theme_template'").Scan(&name); err != nil || name == "" {
		return "theme", true, "no active theme is set"
	}
	if !themeNamePattern.MatchString(name) {
		return "theme", false, "the active theme's name is not a plain theme name"
	}
	if st, err := os.Stat(filepath.Join(env.WebRoot, "theme", name)); err != nil || !st.IsDir() {
		return "theme", false, "the active theme '" + name + "' is not on this node's disk"
	}
	return "theme", true, "the active theme '" + name + "' is on disk"
}
