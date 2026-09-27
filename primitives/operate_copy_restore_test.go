package primitives

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// copy_restore (specs/site_copy.md WP2): restore_chain.sh with the source's
// secret key, only on a dormant copy, only of runs the source vouched for.

const copyChainID = "chain-20260807_231507"

// copyEnv is a site with a staged chain workspace and the given state line
// ("" for a live site). vouch, when not nil, is written as the vouched record.
func copyEnv(t *testing.T, state string, vouch []string) (*ExecEnv, string) {
	t.Helper()
	work := filepath.Join("backups", chainWorkspacePrefix+copyChainID)
	env := restoreEnv(t, filepath.Join(work, chainManifestFile), filepath.Join(work, chainKeyFile))

	dir := t.TempDir()
	old := SiteStateDir
	SiteStateDir = dir
	t.Cleanup(func() { SiteStateDir = old })
	site := filepath.Join(dir, filepath.Base(env.SiteRoot))
	if err := os.MkdirAll(site, 0o700); err != nil {
		t.Fatal(err)
	}
	if state != "" {
		if err := os.WriteFile(filepath.Join(site, "state"), []byte(state+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if vouch != nil {
		body := strings.Join(vouch, "\n") + "\n"
		if err := os.WriteFile(filepath.Join(site, copyVouchedFile), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return env, filepath.Join(env.SiteRoot, work)
}

// stagedSum is the hash of what restoreEnv writes for every staged file.
func stagedSum(t *testing.T, work string) string {
	t.Helper()
	sum, err := hashFile(filepath.Join(work, chainManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

func copyArgs(t *testing.T, env *ExecEnv, raw map[string]interface{}) ([]string, error) {
	t.Helper()
	p := mustLookup(t, "copy_restore")
	params, err := Validate(p.Params, raw)
	if err != nil {
		return nil, err
	}
	return p.Script.ArgsFrom(context.Background(), env, params)
}

func copyParams() map[string]interface{} {
	return map[string]interface{}{"project": restoreFixtureProject, "chain_id": copyChainID}
}

func vouchedEnv(t *testing.T) (*ExecEnv, string) {
	t.Helper()
	env, work := copyEnv(t, "quiet copy", []string{})
	line := stagedSum(t, work) + " " + copyChainID
	if err := os.WriteFile(filepath.Join(siteStateDir(env), copyVouchedFile), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return env, work
}

func TestACopyRestoreRunsTheChainRestoreWithTheSourcesKeyAndNoCertificate(t *testing.T) {
	env, work := vouchedEnv(t)
	argv, err := copyArgs(t, env, copyParams())
	if err != nil {
		t.Fatalf("a vouched chain on a dormant copy should compose: %v", err)
	}
	want := []string{
		restoreFixtureProject,
		"--artifacts", work,
		"--key-file", filepath.Join(work, chainKeyFile),
		"--force",
		"--adopt-secret-key",
		"--skip-ssl",
	}
	if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv is %q, want %q", argv, want)
	}

	raw := copyParams()
	raw["seq"] = float64(4)
	argv, err = copyArgs(t, env, raw)
	if err != nil || strings.Join(argv[len(argv)-2:], " ") != "--seq 4" {
		t.Fatalf("the run is forwarded when asked: %q %v", argv, err)
	}
}

func TestACopyRestoreRunsOnlyOnADormantCopy(t *testing.T) {
	// Live: the dispatcher lets every word through, so the word says no.
	env, work := copyEnv(t, "", nil)
	os.WriteFile(filepath.Join(siteStateDir(env), copyVouchedFile), []byte(stagedSum(t, work)+" "+copyChainID+"\n"), 0o600)
	if _, err := copyArgs(t, env, copyParams()); err == nil || !Refused(err) || !strings.Contains(err.Error(), "only on a dormant copy") {
		t.Errorf("a live site must refuse, even with a vouched record beside it: %v", err)
	}

	// A frozen source: the dispatcher refuses before the parameters.
	env, _ = copyEnv(t, "quiet switchover", nil)
	if err := quietAllows(env, mustLookup(t, "copy_restore")); err == nil || !Refused(err) {
		t.Errorf("a frozen source must refuse copy_restore: %v", err)
	}
	if _, err := copyArgs(t, env, copyParams()); err == nil || !Refused(err) {
		t.Errorf("and so must the word itself: %v", err)
	}

	// A dormant copy: the dispatcher lets it through.
	env, _ = copyEnv(t, "quiet copy", nil)
	if err := quietAllows(env, mustLookup(t, "copy_restore")); err != nil {
		t.Errorf("a dormant copy runs copy_restore: %v", err)
	}
}

func TestACopyRestoreAppliesOnlyWhatTheSourceVouchedFor(t *testing.T) {
	// The upload ledger lists the staged files (restoreEnv writes it), and
	// that is not enough: a copy's ledger vouches for nothing of its source's.
	env, _ := copyEnv(t, "quiet copy", nil)
	if _, err := copyArgs(t, env, copyParams()); err == nil || !Refused(err) || !strings.Contains(err.Error(), "no runs vouched") {
		t.Errorf("no vouched record must refuse: %v", err)
	}

	env, _ = copyEnv(t, "quiet copy", []string{strings.Repeat("0", 64) + " " + copyChainID})
	if _, err := copyArgs(t, env, copyParams()); err == nil || !Refused(err) || !strings.Contains(err.Error(), "not one the source vouched for") {
		t.Errorf("a manifest whose hash is not listed must refuse: %v", err)
	}

	env, work := copyEnv(t, "quiet copy", []string{})
	os.WriteFile(filepath.Join(siteStateDir(env), copyVouchedFile), []byte(stagedSum(t, work)+" chain-20990101_000000\n"), 0o600)
	if _, err := copyArgs(t, env, copyParams()); err == nil || !Refused(err) {
		t.Errorf("the right hash under another chain id must refuse: %v", err)
	}

	env, _ = vouchedEnv(t)
	if err := os.Chmod(filepath.Join(siteStateDir(env), copyVouchedFile), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := copyArgs(t, env, copyParams()); err == nil || !Refused(err) || !strings.Contains(err.Error(), "writable by other accounts") {
		t.Errorf("a record others could write vouches for nothing: %v", err)
	}
}

func TestACopyRestoreNamesNoPathAndOnlyItsOwnProject(t *testing.T) {
	env, _ := vouchedEnv(t)
	raw := copyParams()
	raw["project"] = "somebody_else"
	if _, err := copyArgs(t, env, raw); err == nil || !Refused(err) {
		t.Errorf("another project must refuse: %v", err)
	}
	for _, bad := range []map[string]interface{}{
		{"project": restoreFixtureProject, "chain_id": "../etc"},
		{"project": restoreFixtureProject, "chain_id": copyChainID, "key_file": "/tmp/k"},
		{"project": restoreFixtureProject, "chain_id": copyChainID, "skip_database": true},
	} {
		if _, err := Validate(mustLookup(t, "copy_restore").Params, bad); err == nil {
			t.Errorf("%v must be refused by the vocabulary", bad)
		}
	}
}

func TestACopyRestoreWithNothingStagedSaysWhatIsMissing(t *testing.T) {
	env := restoreEnv(t)
	dir := t.TempDir()
	old := SiteStateDir
	SiteStateDir = dir
	t.Cleanup(func() { SiteStateDir = old })
	site := filepath.Join(dir, filepath.Base(env.SiteRoot))
	os.MkdirAll(site, 0o700)
	os.WriteFile(filepath.Join(site, "state"), []byte("quiet copy\n"), 0o644)
	_, err := copyArgs(t, env, copyParams())
	if err == nil || !Refused(err) || !strings.Contains(err.Error(), chainManifestFile) || !strings.Contains(err.Error(), "sealed export") {
		t.Errorf("an unstaged copy should name the missing manifest and how a copy stages: %v", err)
	}
}

func TestCopyRestoreShape(t *testing.T) {
	p := mustLookup(t, "copy_restore")
	if p.Class != ClassOperate || p.Quiet != QuietCopy {
		t.Fatal("copy_restore is an operate word that runs only under quiet copy")
	}
	if p.Script == nil || p.Script.ScriptPath != restoreChainScript || p.Script.Interpreter != "/bin/bash" {
		t.Fatal("copy_restore runs restore_chain.sh, the one chain restore")
	}
	if p.Machine {
		t.Error("a machine with no site has nothing to restore into")
	}
	if p.Timeout >= mustLookup(t, "restore_chain").Timeout {
		t.Error("with no approval to wait for, copy_restore's budget is restore_chain's work alone")
	}
}
