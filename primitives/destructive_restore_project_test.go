package primitives

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func projectArgs(t *testing.T, env *ExecEnv, raw map[string]interface{}) ([]string, error) {
	t.Helper()
	p := restorePrimitive(t, "restore_project")
	params, err := Validate(p.Params, raw)
	if err != nil {
		return nil, err
	}
	return p.Script.ArgsFrom(context.Background(), env, params)
}

func TestARestoreProjectJobComposesTheEnginesArgv(t *testing.T) {
	env := restoreEnv(t, "backups/manager/jeremytunnell_2026-08-27.tar.gz.enc")
	argv, err := projectArgs(t, env, validRestoreParams("restore_project"))
	if err != nil {
		t.Fatalf("a well-formed job should compose: %v", err)
	}
	want := []string{
		"jeremytunnell",
		filepath.Join(env.SiteRoot, "backups", managerSubdir, "jeremytunnell_2026-08-27.tar.gz.enc"),
		"--force",
	}
	if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv is %q, want %q", argv, want)
	}
}

func TestAnUnforcedProjectRestoreRefusesRatherThanBlocking(t *testing.T) {
	// Without --force the script reaches its confirmation prompt and waits on a
	// tty that does not exist, until the node's timeout kills a root process an
	// hour later. That reads as a slow restore rather than one that was never
	// going to run, so the answer is a refusal that names the parameter.
	env := restoreEnv(t, "backups/manager/jeremytunnell_2026-08-27.tar.gz.enc")
	raw := validRestoreParams("restore_project")
	raw["force"] = false
	_, err := projectArgs(t, env, raw)
	if err == nil || !Refused(err) {
		t.Fatalf("an unforced restore should refuse, got %v", err)
	}
	if !strings.Contains(err.Error(), "force") {
		t.Errorf("the refusal should name the parameter, got %q", err)
	}
}

func TestTheProjectRestoreNamesNoDomain(t *testing.T) {
	// The SSH job path required one, computed on the plane from its own
	// database column, and the script installs it as the identity the restored
	// site answers to. Omitted, the script keeps the domain THIS machine's
	// config already names — which is the answer that cannot be wrong. So the
	// parameter must not exist AND must not appear in argv.
	p := restorePrimitive(t, "restore_project")
	for _, spec := range p.Params {
		if spec.Name == "domain" {
			t.Fatal("restore_project declares domain — a node told its own name by a remote party " +
				"is only as correct as a row someone else can edit")
		}
	}
	env := restoreEnv(t, "backups/manager/jeremytunnell_2026-08-27.tar.gz.enc")
	argv, err := projectArgs(t, env, validRestoreParams("restore_project"))
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range argv {
		if strings.Contains(arg, "domain") {
			t.Errorf("argv carries %q", arg)
		}
	}
}

func TestTheProjectRestorePassesNoKeyFile(t *testing.T) {
	// restore_project.sh 1.3.0 resolves the archive key itself, and in the
	// right order: the envelope sidecar beside the archive opened with this
	// site's own backup_site_key first, because that is the key that provably
	// belongs to this archive. Naming a key would put --key-file ahead of
	// nothing useful and behind the sidecar for no gain, and would mean the
	// agent deciding which key opens an archive it did not make.
	env := restoreEnv(t, "backups/manager/jeremytunnell_2026-08-27.tar.gz.enc")
	argv, err := projectArgs(t, env, validRestoreParams("restore_project"))
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range argv {
		if strings.Contains(arg, "key") {
			t.Errorf("argv carries %q — the node opens its own envelope with its own key", arg)
		}
	}
}

func TestAProjectRestoreCannotSilentlyDoHalfTheJob(t *testing.T) {
	// The SSH builder offered skip_database and skip_files. A restore that
	// silently did half the job is the failure mode this migration removes, and
	// the flags exist for rehearsals an operator drives by hand.
	p := restorePrimitive(t, "restore_project")
	for _, spec := range p.Params {
		if spec.Name == "skip_database" || spec.Name == "skip_files" {
			t.Errorf("restore_project declares %q", spec.Name)
		}
	}
	env := restoreEnv(t, "backups/manager/jeremytunnell_2026-08-27.tar.gz.enc")
	argv, _ := projectArgs(t, env, validRestoreParams("restore_project"))
	for _, arg := range argv {
		if strings.HasPrefix(arg, "--skip") {
			t.Errorf("argv carries %q", arg)
		}
	}
}

func TestOnlyAProjectArchiveCanBeRestoredOverAProject(t *testing.T) {
	// The file half of this restore extracts over a live tree. A database dump
	// handed to it is not a near miss.
	env := restoreEnv(t,
		"backups/manager/db_2026-08-27.sql.gz.enc",
		"backups/manager/readme.md",
	)
	for _, bad := range []string{"db_2026-08-27.sql.gz.enc", "readme.md"} {
		raw := validRestoreParams("restore_project")
		raw["file"] = bad
		if _, err := projectArgs(t, env, raw); err == nil {
			t.Errorf("%q is not a project archive and must not be extracted over a site", bad)
		} else if !Refused(err) {
			t.Errorf("%q should be a refusal, not a failure: %v", bad, err)
		}
	}
}
