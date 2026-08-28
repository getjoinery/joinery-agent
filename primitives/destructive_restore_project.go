package primitives

import (
	"context"
	"regexp"
	"time"
)

// restore_project: replace this node's project tree, and its database, from one
// of the node's own project archives.
//
// The most destructive thing in the vocabulary, and by some distance. It is not
// only that it drops a schema the way restore_database does; the file half
// EXTRACTS OVER a live tree, and restore_project.sh's own header describes
// replacing the site's files from the archive. An archive aimed at the wrong
// project name is a site overwritten with another site. Which is why the plane
// gets a name it cannot turn into a path, and why the class is destructive: it
// is refused at the compiled ceiling and stays refused until a node-verified
// approval exists.
//
// WHAT IS NOT IN THE VOCABULARY, and each absence is a capability withdrawn:
//
//   - No path. The SSH path built /backups/<whatever> on the plane and passed it
//     as the archive. Here the plane sends a name, it must look like a project
//     archive, and the node resolves it in its own backup directory.
//   - No key and no key path. restore_project.sh 1.3.0 resolves the archive key
//     itself, and in the right order: the envelope sidecar beside the archive
//     opened with THIS site's own backup_site_key first, because that is the key
//     that provably belongs to this archive; then --key-file; then the standing
//     ~/.joinery_backup_key. The primitive passes no --key-file, so the node
//     opens its own envelope with its own key and nothing about the key crosses
//     the wire.
//   - No domain. The SSH job path required one, computed on the plane from its
//     own database column, and restore_project.sh installs it as the identity
//     the restored site answers to. That is the run_plugin_installers argument
//     in its sharpest form: a node told its own name by a remote party is a node
//     whose identity is only as correct as a row someone else can edit. Omitted,
//     the script keeps the domain THIS machine's config already names, which is
//     the answer that cannot be wrong.
//   - No skip flags. The SSH builder offered skip_database and skip_files. A
//     restore that silently did half the job is the failure mode this whole
//     migration exists to remove, and the two flags exist for rehearsals an
//     operator drives by hand, not for a job.
func init() {
	Register(Primitive{
		Name:        "restore_project",
		Class:       ClassDestructive,
		Description: "Replace this node's project tree and database from one of its own project archives.",
		Params: []ParamSpec{
			// Which project. It is a directory name under the web root's
			// parent, so it is bound to what can safely be one segment: no
			// separator, no leading dot, nothing that reads as a flag.
			{Name: "project_name", Type: ParamString, Required: true, MaxLen: 128,
				Pattern: regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)},

			// A NAME, never a path. See restore_paths.go.
			{Name: "file", Type: ParamString, Required: true, MaxLen: 255,
				Pattern: backupFileName},

			// Whose backup directory to look in. REQUIRED, exactly as
			// upload_backup and delete_backup require it, and for a sharper
			// version of delete_backup's reason: the two profiles keep separate
			// directories, and an archive of the same name exists in both often
			// enough that guessing would eventually restore the control plane's
			// backup over a site.
			{Name: "profile", Type: ParamEnum, Required: true,
				Values: []string{"site", "manager"}},

			// Proceed without a confirmation prompt. Declared rather than
			// compiled in because it is the one place the plane says out loud
			// that this is meant to happen — see restoreProjectArgs, which
			// refuses when it is not true rather than letting the script sit on
			// a prompt.
			{Name: "force", Type: ParamBool, Required: true},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  restoreProjectScript,
			ArgsFrom:    restoreProjectArgs,
			StdinFrom:   nil,
		},
		// The SSH step allowed 3600s for the restore itself. Extraction of a
		// large tree plus the inner database load genuinely uses it, and a
		// deadline under the work would kill a project restore part-way through
		// extracting over a live site — the worst state this operation has.
		Timeout: 70 * time.Minute,
	})
}

// restoreProjectScript is site-root relative and outside public_html, so it
// verifies against the core release manifest.
const restoreProjectScript = "maintenance_scripts/sysadmin_tools/restore_project.sh"

func restoreProjectArgs(ctx context.Context, env *ExecEnv, params Params) ([]string, error) {
	// A restore run by an agent has no terminal to confirm at. Without --force
	// the script reaches its confirmation prompt and blocks on a tty that does
	// not exist, until the node's own timeout kills a root process an hour
	// later — which reads as a slow restore rather than a job that was never
	// going to run. Refusing is the honest answer, and it names the parameter.
	if !params.Bool("force") {
		return nil, refusedf("restore_project needs force: this node has no terminal for the " +
			"script's confirmation prompt, so an unforced restore would block until it was killed")
	}

	path, err := resolveBackupFile(ctx, env, params, projectArchiveSuffixes)
	if err != nil {
		return nil, err
	}

	return []string{params.String("project_name"), path, "--force"}, nil
}
