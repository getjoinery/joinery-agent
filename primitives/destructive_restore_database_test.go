package primitives

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func dbArgs(t *testing.T, env *ExecEnv, raw map[string]interface{}) ([]string, error) {
	t.Helper()
	p := restorePrimitive(t, "restore_database")
	params, err := Validate(p.Params, raw)
	if err != nil {
		return nil, err
	}
	return p.Script.ArgsFrom(context.Background(), env, params)
}

func TestARestoreDatabaseJobComposesTheEnginesArgv(t *testing.T) {
	env := restoreEnv(t, "backups/manager/db_2026-08-27.sql.gz.enc")
	argv, err := dbArgs(t, env, validRestoreParams("restore_database"))
	if err != nil {
		t.Fatalf("a well-formed job should compose: %v", err)
	}

	want := []string{
		"jeremytunnell",
		filepath.Join(env.SiteRoot, "backups", managerSubdir, "db_2026-08-27.sql.gz.enc"),
		"--non-interactive",
	}
	if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv is %q, want %q", argv, want)
	}
}

func TestTheDatabaseRestorePassesNoKeyFile(t *testing.T) {
	// The whole of rule 2 for this primitive, and it is an ABSENCE, so it has to
	// be asserted rather than read. restore_database.sh resolves the key itself
	// when no --key-file is given: the envelope sidecar beside the archive,
	// opened with this machine's own backup_site_key, then
	// $BACKUP_ENCRYPTION_KEY, then ~/.joinery_backup_key. Passing --key-file —
	// even pointed at the node's own key on disk — would SUPPRESS the sidecar
	// step, because an explicit key is the caller saying which key to use and
	// the script must not second-guess it. The archives that matter most are
	// envelope-sealed, so a --key-file here would break exactly the restores
	// this exists for.
	env := restoreEnv(t, "backups/manager/db_2026-08-27.sql.gz.enc")
	argv, err := dbArgs(t, env, validRestoreParams("restore_database"))
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range argv {
		if strings.Contains(arg, "key") {
			t.Errorf("argv carries %q — the node resolves its own key, and naming one turns the sidecar off", arg)
		}
	}
}

func TestTheDatabaseRestoreIsAlwaysNonInteractive(t *testing.T) {
	// Compiled in, not offered. Without it the script is willing to prompt on
	// /dev/tty for a decryption key, and a root process waiting on a terminal
	// that does not exist is a job that hangs until the node kills it.
	env := restoreEnv(t, "backups/manager/db_2026-08-27.sql.gz.enc")
	argv, err := dbArgs(t, env, validRestoreParams("restore_database"))
	if err != nil {
		t.Fatal(err)
	}
	if !contains(argv, "--non-interactive") {
		t.Errorf("argv %q does not force non-interactive mode", argv)
	}
}

func TestTheDatabaseUserIsForwardedOnlyWhenGiven(t *testing.T) {
	env := restoreEnv(t, "backups/manager/db_2026-08-27.sql.gz.enc")
	raw := validRestoreParams("restore_database")
	raw["db_user"] = "joinery"
	argv, err := dbArgs(t, env, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(argv, "--db-user") || !contains(argv, "joinery") {
		t.Errorf("argv %q dropped the requested role", argv)
	}

	// Absent, the script's own default (postgres) stands. An always-present
	// flag would mean the agent deciding a thing it was not told.
	argv, err = dbArgs(t, env, validRestoreParams("restore_database"))
	if err != nil {
		t.Fatal(err)
	}
	if contains(argv, "--db-user") {
		t.Errorf("argv %q invented a role nobody asked for", argv)
	}
}

func TestOnlyADatabaseArchiveCanBeRestoredOverADatabase(t *testing.T) {
	// A name can pass the pattern and still be the wrong kind of archive.
	// Handing restore_database.sh a project tarball has it fail somewhere
	// inside, after the operator has been told the restore started.
	env := restoreEnv(t,
		"backups/manager/site_2026-08-27.tar.gz.enc",
		"backups/manager/notes.txt",
	)
	for _, bad := range []string{"site_2026-08-27.tar.gz.enc", "notes.txt"} {
		raw := validRestoreParams("restore_database")
		raw["file"] = bad
		if _, err := dbArgs(t, env, raw); err == nil {
			t.Errorf("%q is not a database archive and must not be loaded over a database", bad)
		} else if !Refused(err) {
			t.Errorf("%q should be a refusal, not a failure: %v", bad, err)
		}
	}
}

func TestABackupThatIsNotThereRefusesBeforeRootRuns(t *testing.T) {
	// The script's own answer is RESTORE_USAGE_ERROR, after it has been started
	// as root. This is the same fact said earlier, naming the directory actually
	// looked in — which on a container node is not /backups.
	env := restoreEnv(t)
	_, err := dbArgs(t, env, validRestoreParams("restore_database"))
	if err == nil || !Refused(err) {
		t.Fatalf("a missing archive should refuse, got %v", err)
	}
	if !strings.Contains(err.Error(), filepath.Join(env.SiteRoot, "backups")) {
		t.Errorf("the refusal should name where it looked, got %q", err)
	}
}

func TestTheProfileDecidesWhichDirectoryIsRead(t *testing.T) {
	// Same filename in both profiles' directories. Getting this wrong loads one
	// party's backup over the other's database, which is why profile is
	// required rather than defaulted.
	env := restoreEnv(t,
		"backups/db_2026-08-27.sql.gz.enc",
		"backups/manager/db_2026-08-27.sql.gz.enc",
	)
	for profile, wantDir := range map[string]string{
		"site":    filepath.Join(env.SiteRoot, "backups"),
		"manager": filepath.Join(env.SiteRoot, "backups", managerSubdir),
	} {
		raw := validRestoreParams("restore_database")
		raw["profile"] = profile
		argv, err := dbArgs(t, env, raw)
		if err != nil {
			t.Fatalf("profile %s: %v", profile, err)
		}
		if got := filepath.Dir(argv[1]); got != wantDir {
			t.Errorf("profile %s read %s, want %s", profile, got, wantDir)
		}
	}

	// And it cannot be omitted.
	raw := validRestoreParams("restore_database")
	delete(raw, "profile")
	if _, err := dbArgs(t, env, raw); err == nil {
		t.Error("profile must be required — guessing restores the wrong party's backup")
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestADatabaseRestoreDefaultsToThisNodesOwnDatabase(t *testing.T) {
	// The normal case, and the reason db_name is optional. The control plane
	// stores no column for a node's database name, so a plane that always sent
	// one would be inventing it — and an invented name aimed at the wrong node
	// is somebody else's database, in the operation whose contract is DROP
	// SCHEMA public CASCADE.
	env := restoreEnv(t, "backups/manager/db_2026-08-27.sql.gz.enc")
	raw := validRestoreParams("restore_database")
	delete(raw, "db_name")

	argv, err := dbArgs(t, env, raw)
	if err != nil {
		t.Fatalf("a job that names no database should restore this node's own: %v", err)
	}
	if argv[0] != env.DBName {
		t.Errorf("restored over %q, want this node's own %q", argv[0], env.DBName)
	}
}

func TestANamedDatabaseStillWins(t *testing.T) {
	// The case the parameter is kept for: an operator restoring into a scratch
	// database beside the live one, which the node cannot infer.
	env := restoreEnv(t, "backups/manager/db_2026-08-27.sql.gz.enc")
	raw := validRestoreParams("restore_database")
	raw["db_name"] = "jeremytunnell_scratch"

	argv, err := dbArgs(t, env, raw)
	if err != nil {
		t.Fatal(err)
	}
	if argv[0] != "jeremytunnell_scratch" {
		t.Errorf("restored over %q, want the database the job named", argv[0])
	}
}

func TestANodeThatCannotNameItsOwnDatabaseRefuses(t *testing.T) {
	// No guessing. "postgres" would be the cluster's own catalogue and the site
	// name is not reliably the database name, so a machine whose config could
	// not be read makes the operator say which database to replace.
	env := restoreEnv(t, "backups/manager/db_2026-08-27.sql.gz.enc")
	env.DBName = ""
	raw := validRestoreParams("restore_database")
	delete(raw, "db_name")

	_, err := dbArgs(t, env, raw)
	if err == nil || !Refused(err) {
		t.Fatalf("a node with no database name should refuse, got %v", err)
	}
	if !strings.Contains(err.Error(), "guess") {
		t.Errorf("the refusal should say it will not guess, got %q", err)
	}
}
