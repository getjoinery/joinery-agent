package primitives

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// list_backups: what backup artifacts exist on this node.
//
// The second observe primitive, and like check_status it runs no command — it
// reads a directory. The SSH path this replaces shelled a `for` loop over four
// globs calling stat; the failure modes it carried (a glob that matches
// nothing expanding to a literal, stat output parsed by regex on the plane) are
// not translated here, they are gone.
//
// TAKES NO PARAMETERS, deliberately. The directory and the suffixes are
// compiled in, mirroring BackupNaming on the platform side. A primitive that
// accepted a directory would let whatever asked enumerate any path on the node
// it liked — an observe class is still a disclosure surface, and "read this
// directory for me" is the shape of that mistake.
func init() {
	Register(Primitive{
		Name:        "list_backups",
		Class:       ClassObserve,
		Description: "Backup artifacts present in the node's backup directory, with size and date.",
		Params:      nil,
		Run:         runListBackups,
	})
}

// backupDir is where backups live on a node (BackupNaming::BACKUP_DIR).
const backupDir = "/backups"

// backupExtensions are the recognised artifact suffixes, longest first — the
// same list and the same ordering rule as BackupNaming::EXTENSIONS, where
// shortest-first would classify every encrypted dump as plaintext.
var backupExtensions = []string{".tar.gz.enc", ".sql.gz.enc", ".tar.gz", ".sql.gz"}

// envelopeSuffix names the key file that sits beside an encrypted archive
// (BackupEnvelope::SIDECAR_SUFFIX). It is not itself a backup artifact — it is
// never listed as one — but whether it is PRESENT is reported per archive.
//
// An encrypted archive is sealed with a data key minted for that archive alone,
// and this file holds the only copy of it. An archive that reaches cloud storage
// without it cannot be opened by anyone, and it looks exactly like a good backup
// in every listing. Whoever is deciding what to upload, restore or trust needs
// to know whether the key is there, and this is the only place that can answer:
// the plane cannot see the node's disk.
const envelopeSuffix = ".keys.json"

// encryptedSuffix is what makes an archive need a key at all. A plaintext
// archive reported as "missing its key" would be a false alarm, and a listing
// that cries wolf gets ignored on the day it is right.
const encryptedSuffix = ".enc"

// runListBackups reports both profiles' backups.
//
// BOTH, because "what backups exist on this node" means both, and because a node
// whose own backups have stopped while the control plane's pile up is a fact
// worth being able to see. Each file carries the profile it belongs to, so the
// plane can address it later without ever naming a path.
//
// A missing directory is not an error and not a gap in the report: a node that
// has never run one profile simply has no directory for it.
func runListBackups(ctx context.Context, env *ExecEnv, _ Params) (map[string]interface{}, error) {
	files := []map[string]interface{}{}

	for profile, dir := range backupDirsByProfile(ctx, env) {
		found, err := runListBackupsFrom(ctx, dir)
		if err != nil {
			return nil, err
		}
		for _, f := range found["files"].([]map[string]interface{}) {
			f["profile"] = string(profile)
			files = append(files, f)
		}
	}

	// The manager directory sits INSIDE the site base, so a naive read of the
	// base would report the plane's archives as the site's. runListBackupsFrom
	// skips directories, so nothing is double counted — but sort here, once, now
	// that both profiles are in one list.
	sort.Slice(files, func(i, j int) bool {
		return files[i]["mtime"].(int64) > files[j]["mtime"].(int64)
	})

	return map[string]interface{}{"files": files}, nil
}

// runListBackupsFrom is the body, with the directory as an argument so it can be
// exercised against a temp tree. The exported primitive above passes the
// compiled-in constant and nothing else can: a job has no way to reach this.
func runListBackupsFrom(_ context.Context, dir string) (map[string]interface{}, error) {
	files := []map[string]interface{}{}

	entries, err := os.ReadDir(dir)
	if err != nil {
		// No backup directory is a legitimate state — a node that has never
		// been backed up — and it is not this primitive's place to call that a
		// failure. An empty list says exactly what is true.
		if os.IsNotExist(err) {
			return map[string]interface{}{"files": files}, nil
		}
		return nil, err
	}

	// Names first, so each archive can be asked whether its key file is here
	// without re-reading the directory once per artifact.
	present := map[string]bool{}
	for _, entry := range entries {
		if !entry.IsDir() {
			present[entry.Name()] = true
		}
	}

	for _, entry := range entries {
		if entry.IsDir() || !isBackupArtifact(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue // vanished between listing and stat; it is not a backup we can report
		}

		size := info.Size()
		mtime := info.ModTime().UTC()
		encrypted := strings.HasSuffix(entry.Name(), encryptedSuffix)
		files = append(files, map[string]interface{}{
			"encrypted":    encrypted,
			"has_envelope": encrypted && present[entry.Name()+envelopeSuffix],
			"filename":     entry.Name(),
			"size":         formatSize(uint64(size)),
			"size_bytes":   size,
			"date":         mtime.Format("2006-01-02"),
			"mtime":        mtime.Unix(),
			"local_path":   filepath.Join(dir, entry.Name()),
			"cloud_path":   nil,
			"location":     "local",
		})
	}

	// Newest first. The plane sorts too, but a primitive whose output order
	// depends on directory iteration order makes two identical nodes look
	// different for no reason.
	sort.Slice(files, func(i, j int) bool {
		return files[i]["mtime"].(int64) > files[j]["mtime"].(int64)
	})

	return map[string]interface{}{"files": files}, nil
}

// isBackupArtifact reports whether a filename is one of the recognised shapes.
func isBackupArtifact(name string) bool {
	for _, ext := range backupExtensions {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}
