package primitives

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// delete_backup deletes a file on this node and nothing else. The tests that
// matter are the ones about what it cannot be asked to do, and about the
// difference between "already gone" and "could not delete".

func deleteParams(t *testing.T, raw map[string]interface{}) (Params, error) {
	t.Helper()
	p, ok := Lookup("delete_backup")
	if !ok {
		t.Fatal("delete_backup should be registered")
	}
	return Validate(p.Params, raw)
}

func backupTree(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("archive bytes"), 0600); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	return dir
}

func TestNoCloudObjectCanBeNamedForDeletion(t *testing.T) {
	// The SSH job's cloud half is not migrated: it forced the MAIN,
	// delete-capable bucket credential onto the node — the very credential the
	// write-only node credential exists to keep off nodes — so that a node could
	// issue an HTTPS DELETE the plane can issue itself. The cloud object is the
	// plane's to delete. Nothing here can name one.
	for _, field := range []string{"cloud_path", "bucket", "credentials_b64", "target", "remote_key", "path_prefix", "local_path"} {
		params := map[string]interface{}{"filename": "site_2026-08-27.sql.gz", "profile": "site", field: "anything"}

		if _, err := deleteParams(t, params); err == nil {
			t.Errorf("a delete job carrying %q must be refused as out-of-vocabulary", field)
		}
	}

	// A NAME and WHOSE, and nothing else. profile is an enum of two values the
	// node maps to a directory itself — it is not a path, and it exists because
	// the two profiles keep separate directories (BackupProfile::output_dir).
	// Pinned exactly, so a third parameter has to be argued for here.
	p, _ := Lookup("delete_backup")
	allowed := map[string]bool{"filename": true, "profile": true}
	if len(p.Params) != len(allowed) {
		t.Errorf("delete_backup should take a filename and a profile and nothing else, got %v", p.Params)
	}
	for _, spec := range p.Params {
		if !allowed[spec.Name] {
			t.Errorf("delete_backup gained parameter %q", spec.Name)
		}
		if spec.Name == "profile" && spec.Type != ParamEnum {
			t.Error("profile must be an enum: a free string here would be a directory selector")
		}
	}
	if p.Script != nil {
		t.Error("delete_backup runs no script: there is nothing here to invoke and no credential to carry")
	}
	if p.Class != ClassOperate {
		t.Errorf("delete_backup is operate, not %q", p.Class)
	}
}

func TestThePlaneCannotNameAPathToDelete(t *testing.T) {
	for _, bad := range []string{"/etc/passwd", "../../config/Globalvars_site.php", "..", ".", "sub/dir.tar.gz", ""} {
		if _, err := deleteParams(t, map[string]interface{}{"filename": bad, "profile": "site"}); err == nil {
			t.Errorf("filename %q should be refused; it is a path", bad)
		}
	}
}

func TestOnlyABackupArtifactCanBeDeleted(t *testing.T) {
	dir := backupTree(t, "Globalvars_site.php")

	if _, err := runDeleteBackupIn(context.Background(), dir, "Globalvars_site.php"); !Refused(err) {
		t.Fatalf("deleting a non-artifact should be refused, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "Globalvars_site.php")); err != nil {
		t.Error("the refused file should still be there")
	}
}

func TestDeletingABackupRemovesIt(t *testing.T) {
	dir := backupTree(t, "site_2026-08-27_full.tar.gz.enc")

	result, err := runDeleteBackupIn(context.Background(), dir, "site_2026-08-27_full.tar.gz.enc")
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if result["deleted"] != true {
		t.Errorf("the result should say the file was deleted, got %v", result)
	}
	if _, err := os.Stat(filepath.Join(dir, "site_2026-08-27_full.tar.gz.enc")); !os.IsNotExist(err) {
		t.Error("the backup should be gone")
	}
}

func TestAMissingBackupIsSuccessBecauseTheEndStateHolds(t *testing.T) {
	// Deleting the same backup twice is not an error. The requested end state is
	// "this backup is not on this node", and it holds. A job that failed because
	// someone else got there first would be a lie about the node — and the SSH
	// version's answer to this, continue_on_error on every step, made a delete
	// that quietly did nothing indistinguishable from one that worked.
	dir := backupTree(t)

	result, err := runDeleteBackupIn(context.Background(), dir, "never_existed.sql.gz")
	if err != nil {
		t.Fatalf("an absent backup should not be a failure: %v", err)
	}
	if result["deleted"] != false {
		t.Errorf("the result should say plainly that nothing was deleted, got %v", result)
	}
}

func TestSomethingThatIsNotAFileIsRefusedRatherThanRemoved(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "site_2026-08-27.tar.gz"), 0755); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if _, err := runDeleteBackupIn(context.Background(), dir, "site_2026-08-27.tar.gz"); !Refused(err) {
		t.Fatalf("a directory wearing a backup's name should be refused, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "site_2026-08-27.tar.gz")); err != nil {
		t.Error("the directory should still be there")
	}
}

func TestAnUndeletableBackupFailsLoudly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can unlink from a read-only directory, so this cannot be shown here")
	}
	dir := backupTree(t, "site_2026-08-27.sql.gz")
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })

	_, err := runDeleteBackupIn(context.Background(), dir, "site_2026-08-27.sql.gz")
	if err == nil {
		t.Fatal("a backup that could not be deleted must fail; the end state does not hold")
	}
	if Refused(err) {
		t.Error("this is a failure to carry out the job, not a refusal to attempt it")
	}
	if !strings.Contains(err.Error(), "site_2026-08-27.sql.gz") {
		t.Errorf("the failure should name the backup: %v", err)
	}
}
