package primitives

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// delete_backup: remove one backup file from this node's disk.
//
// LOCAL ONLY, AND THAT IS THE DESIGN. The SSH job this replaces had two halves:
// an `rm` on the node, and a cloud-object delete that ALSO ran on the node. The
// second half is not migrated, because it should never have run there.
//
// A backup target can hold a second, write-only credential (bkt_node_credentials)
// precisely so that "a compromised node then cannot erase the fleet's backups"
// — JobCommandBuilder's own words. But a write-only key cannot delete, so the
// SSH delete step was forced to carry the MAIN, delete-capable credential, the
// one whose docblock says it "stays on the control plane for retention and
// listings". Every cloud delete therefore handed a managed node a key that could
// erase every node's backups, to perform one HTTPS DELETE that the control plane
// — which holds that credential already, and already does every other cloud-side
// operation itself — could issue in-process. Migrating that shape would have
// carried a live defect across the boundary and made it look reviewed.
//
// So the cloud object is deleted by the plane, and this primitive deletes the
// file. Nothing in the vocabulary below can name a cloud object, a bucket, or a
// credential, because none of those words appear in it. From the operator's side
// the backup is still deleted; the two halves simply happen where each one's
// authority already lives.
//
// It cannot name a path either, for the same reason upload_backup cannot: a
// filename, checked against the recognised backup suffixes, resolved inside the
// node's own compiled-in backup directory. The plane cannot ask this node to
// unlink something that is not a backup.
//
// The sudo question disappears with the SSH path. The old step needed a sudo
// prefix on bare-metal nodes because backups under /backups are written as root
// while jobs ran as user1, and without it the rm failed Permission denied while
// the step still reported done. The agent is root.
//
// WHY A MISSING FILE IS SUCCESS, since this is the kind of `return nil` that
// gets re-litigated by someone who only sees the code: the SSH steps set
// continue_on_error on both halves, which meant a delete that quietly did
// nothing was indistinguishable from one that worked — the failure mode this
// whole architecture is trying to remove. The fix is NOT to be that forgiving.
// It is to define the requested end state and report honestly against it. The
// end state is "this backup is not on this node". A file that is already gone
// satisfies it — deleting the same backup twice is not an error, and a job that
// failed because someone else got there first would be a lie about the node.
// Anything else — a permission error, a busy file, a name that resolves to a
// directory — does NOT satisfy it, and fails loudly, with no continue_on_error
// anywhere to swallow it.
func init() {
	Register(Primitive{
		Name:        "delete_backup",
		Class:       ClassOperate,
		Description: "Delete one backup file from this node's backup directory.",
		Params: []ParamSpec{
			// The same name-not-a-path rule as upload_backup, and the same
			// reason: an alphanumeric first character excludes "." and "..",
			// and the pattern excludes the separator.
			{Name: "filename", Type: ParamString, Required: true, MaxLen: 255,
				Pattern: regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)},
		},
		Run: runDeleteBackup,
	})
}

func runDeleteBackup(ctx context.Context, _ *ExecEnv, params Params) (map[string]interface{}, error) {
	return runDeleteBackupIn(ctx, backupDir, params.String("filename"))
}

// runDeleteBackupIn is the body, with the directory as an argument so it can be
// exercised against a temp tree — the same arrangement list_backups uses. The
// registered primitive passes the compiled-in constant and nothing else can: a
// job has no way to reach this.
func runDeleteBackupIn(_ context.Context, dir, filename string) (map[string]interface{}, error) {
	if !isBackupArtifact(filename) {
		return nil, refusedf("%q is not the name of a backup artifact, so this node will not delete it", filename)
	}

	path := filepath.Join(dir, filename)

	// Lstat, not Stat: a symlink is inspected as a symlink. Removing one would
	// only unlink the link, but a link is not what was asked for either.
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		// Already gone. The end state holds; say what is true about the node
		// rather than reporting a failure the operator cannot act on.
		return map[string]interface{}{
			"filename": filename,
			"deleted":  false,
			"detail":   "no such backup on this node; nothing to delete",
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("could not examine %s: %w", filename, err)
	}
	if info.IsDir() {
		return nil, refusedf("%q on this node is a directory, not a backup file", filename)
	}
	if !info.Mode().IsRegular() {
		return nil, refusedf("%q on this node is not a regular file, so it is not the backup it claims to be", filename)
	}

	size := info.Size()
	if err := os.Remove(path); err != nil {
		// Losing the race with another deleter still leaves the end state we
		// were asked for.
		if os.IsNotExist(err) {
			return map[string]interface{}{
				"filename": filename,
				"deleted":  false,
				"detail":   "no such backup on this node; nothing to delete",
			}, nil
		}
		return nil, fmt.Errorf("could not delete %s: %w", filename, err)
	}

	return map[string]interface{}{
		"filename":    filename,
		"deleted":     true,
		"freed_bytes": size,
		"detail":      "deleted from this node",
	}, nil
}
