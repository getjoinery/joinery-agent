package primitives

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const ckChain = "chain-20261108_120000"

func chainKeySite(t *testing.T) (*ExecEnv, string) {
	t.Helper()
	isolateSiteState(t)
	root := filepath.Join(t.TempDir(), "site")
	base := filepath.Join(root, "backups")
	if err := os.MkdirAll(filepath.Join(base, managerSubdir), 0o770); err != nil {
		t.Fatal(err)
	}
	return &ExecEnv{SiteRoot: root}, base
}

func TestRootKeepsChainKeysOutOfTheBackupsFolder(t *testing.T) {
	env, base := chainKeySite(t)
	ctx := context.Background()
	if err := writeChainKey(ctx, env, ckChain, []byte("k\n")); err != nil {
		t.Fatal(err)
	}
	path := chainKeyPath(env, ckChain)
	if rel, err := filepath.Rel(base, path); err == nil && rel[0] != '.' {
		t.Fatalf("the key went under the backups folder: %s", path)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "k\n" {
		t.Fatalf("key = %q, %v", got, err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("key mode %04o", info.Mode().Perm())
	}
	if info, _ := os.Stat(filepath.Dir(path)); info.Mode().Perm() != 0o700 {
		t.Errorf("key folder mode %04o", info.Mode().Perm())
	}
	if !haveChainKey(env, ckChain) {
		t.Error("haveChainKey does not see it")
	}
	if err := writeChainKey(ctx, env, "../escape", []byte("k")); err == nil {
		t.Error("a chain id that is a path was taken")
	}
}

// A chain staged with this machine's own key leaves the key in the
// workspace; root takes it into its own state byte for byte.
func TestARestoreAdoptsTheWorkspaceKey(t *testing.T) {
	env, base := chainKeySite(t)
	work := filepath.Join(base, chainWorkspacePrefix+ckChain)
	if err := os.Mkdir(work, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, chainKeyFile), []byte("site key\n"), 0o660); err != nil {
		t.Fatal(err)
	}
	path, err := restoreKeyFile(context.Background(), env, ckChain)
	if err != nil {
		t.Fatal(err)
	}
	if path != adoptedKeyPath(env, ckChain) {
		t.Fatalf("restore reads %s, not root's copy", path)
	}
	if got, _ := os.ReadFile(path); string(got) != "site key\n" {
		t.Fatalf("adopted %q", got)
	}
	if haveChainKey(env, ckChain) {
		t.Error("an adopted key counts as one root opened")
	}
	// Staged again with another key: the next restore reads the new one.
	if err := os.WriteFile(filepath.Join(work, chainKeyFile), []byte("restaged"), 0o660); err != nil {
		t.Fatal(err)
	}
	if path, err = restoreKeyFile(context.Background(), env, ckChain); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "restaged" {
		t.Fatalf("a restaged chain still restores with the earlier key: %q", got)
	}
}

// The web user owns backups/: a link it plants must not make root read a
// file from outside it as the key.
func TestAdoptingRefusesALinkOutOfTheBackupsFolder(t *testing.T) {
	env, base := chainKeySite(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, chainKeyFile), []byte("not yours"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(base, chainWorkspacePrefix+ckChain)); err != nil {
		t.Fatal(err)
	}
	if workspaceHasKey(context.Background(), env, ckChain) {
		t.Error("a linked workspace counted as holding a key")
	}
	if _, err := restoreKeyFile(context.Background(), env, ckChain); err == nil {
		t.Fatal("root read a key through a link out of the backups folder")
	}
	if haveChainKey(env, ckChain) {
		t.Fatal("a key from outside was kept")
	}
}

func TestAdoptingRefusesALinkedBackupsFolder(t *testing.T) {
	isolateSiteState(t)
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, chainWorkspacePrefix+ckChain), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, chainWorkspacePrefix+ckChain, chainKeyFile), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "backups")); err != nil {
		t.Fatal(err)
	}
	if _, err := restoreKeyFile(context.Background(), &ExecEnv{SiteRoot: root}, ckChain); err == nil {
		t.Fatal("root read a key through a linked backups folder")
	}
}

func TestStaleChainKeysArePruned(t *testing.T) {
	env, base := chainKeySite(t)
	ctx := context.Background()
	const gone, fresh, live = "chain-1", "chain-2", "chain-3"
	for _, id := range []string{gone, fresh, live} {
		if err := writeChainKey(ctx, env, id, []byte("k")); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-chainKeyKeep - time.Hour)
	for _, id := range []string{gone, live} {
		if err := os.Chtimes(chainKeyPath(env, id), old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(base, chainWorkspacePrefix+live), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := writeChainKey(ctx, env, "chain-4", []byte("k")); err != nil {
		t.Fatal(err)
	}
	if haveChainKey(env, gone) {
		t.Error("a week-old key with no workspace was kept")
	}
	if !haveChainKey(env, fresh) {
		t.Error("a new key with no workspace yet (a copy's, before staging) was pruned")
	}
	if !haveChainKey(env, live) {
		t.Error("a key whose workspace is there was pruned")
	}
}

func TestDeleteBackupRefusesALinkedManagerFolder(t *testing.T) {
	env, base := chainKeySite(t)
	outside := t.TempDir()
	victim := filepath.Join(outside, "x.sql.gz.enc")
	if err := os.WriteFile(victim, []byte("v"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(base, managerSubdir)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(base, managerSubdir)); err != nil {
		t.Fatal(err)
	}
	_, _ = runDeleteBackup(context.Background(), env, Params{values: map[string]interface{}{"filename": "x.sql.gz.enc", "profile": "manager"}})
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("root deleted a file through a linked manager folder: %v", err)
	}
	// And a link at the file's own name inside the folder.
	if err := os.Remove(filepath.Join(base, managerSubdir)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(base, "x.sql.gz.enc")); err != nil {
		t.Fatal(err)
	}
	_, _ = runDeleteBackup(context.Background(), env, Params{values: map[string]interface{}{"filename": "x.sql.gz.enc", "profile": "site"}})
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("root deleted a link's target: %v", err)
	}
}

// Every script that writes only into the web user's folders runs as that
// user, never as root.
func TestChainStagingRunsAsTheSiteUser(t *testing.T) {
	for _, name := range []string{"backup_run", "stage_chain", "copy_stage", "download_backup", "upload_backup",
		"verify_backup", "restore_objects"} {
		p := mustLookup(t, name)
		if p.Script == nil || !p.Script.AsSiteUser {
			t.Errorf("%s does not run as the site's web user", name)
		}
	}
}
