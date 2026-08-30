package primitives

import (
	"context"
	"regexp"
	"time"
)

// restore_database: load one of this node's own database backups over the
// node's database. The first DESTRUCTIVE primitive, and the class is the point.
//
// It replaces a schema. restore_database.sh's contract is DROP SCHEMA public
// CASCADE, CREATE SCHEMA public, then load — so a successful run destroys
// whatever was there, and a run against the wrong database destroys something
// nobody asked about. Nothing in this file makes that safe to do unattended, and
// nothing tries to: Policy.Accepts refuses ClassDestructive at a compiled
// ceiling above the policy file, so registering this primitive gives no node the
// ability to run it. What registering it does is put the operation behind a
// declared vocabulary, so that when the approval verifier lands (the deferred
// spec) the thing being approved is already bounded.
//
// WHAT THE SSH PATH COULD EXPRESS AND THIS CANNOT. The plane composed
// `bash restore_database.sh "$DB_NAME" <path> --non-interactive --db-user
// "$DB_USER" --key-file "$KEY_PATH"`, where <path> was a string it built. Two
// capabilities came with that and neither is in the vocabulary below:
//
//   - ANY PATH ON THE NODE as the dump to load. A file the plane names is a file
//     the plane can substitute, and the substituted content is loaded into the
//     database as SQL, as root, after the existing schema has been dropped.
//     Here the plane sends a NAME, it has to look like a database archive, and
//     the node resolves it inside its own backup directory. See restore_paths.go.
//   - A KEY PATH. --key-file pointed at whatever the plane's own preamble had
//     unsealed. This primitive passes no --key-file at all, so the script falls
//     to its next source, which is the node's own ~/.joinery_backup_key. There
//     is no parameter through which key bytes or a key location could arrive.
//
// --non-interactive is compiled in rather than offered. Its absence would leave
// the script willing to prompt on /dev/tty for a decryption key, and a root
// process waiting on a terminal that does not exist is a job that hangs until
// the node's own timeout kills it — which reads as a slow restore rather than a
// misconfigured one.
func init() {
	Register(Primitive{
		Name:        "restore_database",
		Class:       ClassDestructive,
		Description: "Replace this node's database with one of its own database backups.",
		Params: []ParamSpec{
			// Which database. OPTIONAL, and the absence is the normal case:
			// the control plane stores no column for a node's database name, so
			// a plane that always sent one would be inventing it — and an
			// invented name aimed at the wrong node is somebody else's database
			// in the one operation whose contract is DROP SCHEMA public
			// CASCADE. Absent, the node uses its own, read from its own config.
			// That is the run_plugin_installers rule again: a node told its own
			// name by a remote party is only as correct as a row someone else
			// can edit.
			//
			// It stays in the vocabulary for the case that genuinely needs it —
			// an operator restoring into a scratch database (foo_test) beside
			// the live one, which the node cannot infer. Bounded to what
			// PostgreSQL accepts as an identifier: no quotes, no spaces,
			// nothing that could read as a second argument.
			{Name: "db_name", Type: ParamString, MaxLen: 63,
				Pattern: regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)},

			// A NAME, never a path, resolved node-side. The pattern excludes
			// the separator and excludes "." and ".." by requiring an
			// alphanumeric first character; the suffix check happens in
			// resolveBackupFile against what this script can actually read.
			{Name: "file", Type: ParamString, Required: true, MaxLen: 255,
				Pattern: backupFileName},

			// Whose backup directory to look in. An enum of two known values,
			// which the node maps to a directory — not a location. REQUIRED,
			// exactly as upload_backup and delete_backup require it: the two
			// profiles keep separate directories, and an archive looked for in
			// the wrong one is either not there or, worse, is a different
			// party's archive of the same name being loaded over a database.
			{Name: "profile", Type: ParamEnum, Required: true,
				Values: []string{"site", "manager"}},

			// The role the load runs as. Optional: the script defaults to
			// postgres, and the SSH path passed the node's own configured user.
			{Name: "db_user", Type: ParamString, MaxLen: 63,
				Pattern: regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  restoreDatabaseScript,
			ArgsFrom:    restoreDatabaseArgs,
			// No stdin. The script reads none, and a channel that exists is a
			// channel someone will find a use for — run_plugin_installers'
			// argument, and it applies here for a second reason: the one thing
			// that would justify stdin is a credential, and rule 2 says there
			// is no credential in this vocabulary to carry.
			StdinFrom: nil,
		},
		// The SSH step allowed 3600s for exactly this work, plus its own
		// pre-restore dump. A deadline under the work turns a slow restore into
		// a killed one, and a restore killed mid-load is the single worst state
		// this operation has (RESTORE_LOAD_FAILED — the only marker that can
		// leave the database modified). So: the SSH budget, plus slack.
		Describe: describeRestoreDatabase,
		// The work, plus the window in which a human on this machine's own site
		// answers the approval — the wait happens inside this deadline.
		Timeout: 70*time.Minute + ApprovalWindow,
	})
}

// restoreDatabaseScript is the one restore engine, site-root relative and
// outside public_html, so it verifies against the core release manifest.
const restoreDatabaseScript = "maintenance_scripts/sysadmin_tools/restore_database.sh"

// restoreDatabaseArgs composes the argv. Every element is either compiled in or
// a validated parameter, and the one path in it was built here from the node's
// own backup directory.
func restoreDatabaseArgs(ctx context.Context, env *ExecEnv, params Params) ([]string, error) {
	path, err := resolveBackupFile(ctx, env, params, databaseArchiveSuffixes)
	if err != nil {
		return nil, err
	}

	name, err := restoreDatabaseTarget(env, params)
	if err != nil {
		return nil, err
	}

	argv := []string{name, path, "--non-interactive"}
	if params.Has("db_user") {
		argv = append(argv, "--db-user", params.String("db_user"))
	}
	return argv, nil
}

// restoreDatabaseTarget answers which database this restore loads over: the one
// the job named, or — the normal case — this machine's own.
//
// A machine that cannot say which database is its own refuses rather than
// guessing. There is no sensible fallback here: "postgres" would be the cluster's
// own catalogue, and the site name is not reliably the database name. A siteless
// machine has no database to restore onto at all, and on a machine whose config
// could not be read the honest answer is to make the operator name it.
func restoreDatabaseTarget(env *ExecEnv, params Params) (string, error) {
	if params.Has("db_name") {
		return params.String("db_name"), nil
	}
	if env == nil || env.DBName == "" {
		return "", refusedf("this node cannot say which database is its own, so it will not guess " +
			"which one to replace — name it in the job")
	}
	return env.DBName, nil
}

// --- Node-side prerequisites -------------------------------------------------
//
// Two things the node has to be true for a dispatchable restore to succeed, both
// of them state rather than code, and both worth writing down here because the
// SSH path met them by accident and this path does not.
//
//  1. THE KEY FILE IS ROOT'S. The SSH restore step ran as the login user, so
//     ~/.joinery_backup_key resolved under that user's home. The agent is root,
//     so it resolves under /root. A node whose key lives only in an operator's
//     home directory will refuse to decrypt an encrypted dump over this
//     primitive while decrypting it fine over SSH, and the failure reads as a
//     bad key rather than a key in the wrong place.
//
//  2. THERE IS NO ENVELOPE FALLBACK IN THIS SCRIPT. restore_project.sh 1.3.0
//     opens the .keys.json sidecar beside an archive with the site's own key;
//     restore_database.sh has no such step, and the SSH path supplied it from
//     outside (step_resolve_restore_key). So an archive sealed to an envelope
//     rather than to the legacy standing key is restorable over SSH and not over
//     this primitive. Closing that means giving restore_database.sh the sidecar
//     resolution its sibling already has — a platform change, and the right one,
//     since it also fixes the by-hand case.
