package primitives

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func chainArgs(t *testing.T, env *ExecEnv, raw map[string]interface{}) ([]string, error) {
	t.Helper()
	p := restorePrimitive(t, "restore_chain")
	params, err := Validate(p.Params, raw)
	if err != nil {
		return nil, err
	}
	return p.Script.ArgsFrom(context.Background(), env, params)
}

// chainEnv builds a node with a fully prepared chain workspace — what the SSH
// path's earlier steps would have left behind.
func chainEnv(t *testing.T) (*ExecEnv, string) {
	t.Helper()
	const id = "chain-20260807_231507"
	work := filepath.Join("backups", chainWorkspacePrefix+id)
	env := restoreEnv(t,
		filepath.Join(work, chainManifestFile),
		filepath.Join(work, chainKeyFile),
	)
	return env, filepath.Join(env.SiteRoot, work)
}

func TestARestoreChainJobComposesTheEnginesArgv(t *testing.T) {
	env, work := chainEnv(t)
	argv, err := chainArgs(t, env, validRestoreParams("restore_chain"))
	if err != nil {
		t.Fatalf("a prepared chain should compose: %v", err)
	}
	want := []string{
		"jeremytunnell",
		"--artifacts", work,
		"--key-file", filepath.Join(work, chainKeyFile),
		"--force",
	}
	if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv is %q, want %q", argv, want)
	}
}

func TestTheChainWorkspaceIsDerivedFromTheChainIdAlone(t *testing.T) {
	// The plane names a chain, not a directory. restore_chain.sh extracts a
	// tree and replays the deletions the chain recorded, so a directory the
	// plane could choose is a tree the plane could delete.
	env, work := chainEnv(t)
	argv, err := chainArgs(t, env, validRestoreParams("restore_chain"))
	if err != nil {
		t.Fatal(err)
	}
	if base := filepath.Base(work); base != chainWorkspacePrefix+"chain-20260807_231507" {
		t.Fatalf("workspace is %q", base)
	}
	if filepath.Dir(work) != filepath.Join(env.SiteRoot, "backups") {
		t.Errorf("the workspace escaped the node's backup base: %s", work)
	}
	if argv[2] != work {
		t.Errorf("argv points at %s, want %s", argv[2], work)
	}
}

func TestAChainWithNoDownloadedArtifactsRefusesAndSaysWhatIsMissing(t *testing.T) {
	// The honest resting state of this round. A primitive runs one script, and
	// six of the SSH path's seven steps are not this script — so the answer is
	// a refusal naming what is absent, not a restore that does less than asked.
	env := restoreEnv(t)
	_, err := chainArgs(t, env, validRestoreParams("restore_chain"))
	if err == nil || !Refused(err) {
		t.Fatalf("an unprepared chain should refuse, got %v", err)
	}
	if !strings.Contains(err.Error(), chainManifestFile) {
		t.Errorf("the refusal should name the missing manifest, got %q", err)
	}
}

func TestAChainWithNoRecoveredKeyRefusesAndRefusesToBeSentOne(t *testing.T) {
	// The key is recovered on the node from the node's own backup_site_key,
	// which is already how the SSH path did it — the control plane's recovery
	// private key never travelled, because a key in a job record is a key in
	// every stored job. The refusal says both halves.
	const id = "chain-20260807_231507"
	env := restoreEnv(t, filepath.Join("backups", chainWorkspacePrefix+id, chainManifestFile))
	_, err := chainArgs(t, env, validRestoreParams("restore_chain"))
	if err == nil || !Refused(err) {
		t.Fatalf("a chain with no key should refuse, got %v", err)
	}
	if !strings.Contains(err.Error(), chainKeyFile) || !strings.Contains(err.Error(), "backup_envelope.php") {
		t.Errorf("the refusal should name the key and how it is recovered, got %q", err)
	}
	if !strings.Contains(err.Error(), "wire") {
		t.Errorf("the refusal should say a key may not be sent, got %q", err)
	}
}

func TestTheChainRunIsForwardedOnlyWhenAsked(t *testing.T) {
	env, _ := chainEnv(t)
	raw := validRestoreParams("restore_chain")
	raw["seq"] = float64(3) // JSON numbers arrive as float64
	argv, err := chainArgs(t, env, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(argv, "--seq") || !contains(argv, "3") {
		t.Errorf("argv %q dropped the requested run", argv)
	}

	// Absent, the script restores as at the newest run in the manifest. An
	// always-present --seq would mean the agent choosing a run nobody named.
	argv, err = chainArgs(t, env, validRestoreParams("restore_chain"))
	if err != nil {
		t.Fatal(err)
	}
	if contains(argv, "--seq") {
		t.Errorf("argv %q chose a run nobody asked for", argv)
	}
}

func TestAFilesOnlyChainRestoreIsAskedForExplicitly(t *testing.T) {
	env, _ := chainEnv(t)
	raw := validRestoreParams("restore_chain")
	raw["skip_database"] = true
	argv, err := chainArgs(t, env, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(argv, "--skip-database") {
		t.Errorf("argv %q dropped the files-only request", argv)
	}

	raw["skip_database"] = false
	argv, err = chainArgs(t, env, raw)
	if err != nil {
		t.Fatal(err)
	}
	if contains(argv, "--skip-database") {
		t.Errorf("argv %q skipped the database when asked not to", argv)
	}
}

func TestTheChainRestoreNamesNoProfile(t *testing.T) {
	// The profile decides which shelf in the BUCKET a chain is read from, and
	// that work has already happened by the time anything is on this node. The
	// workspace is restore_<chain_id> under the backup base whichever profile
	// the chain came from, which is where the SSH path put it.
	for _, spec := range restorePrimitive(t, "restore_chain").Params {
		if spec.Name == "profile" {
			t.Error("restore_chain declares profile — it decides nothing node-side")
		}
	}
}
