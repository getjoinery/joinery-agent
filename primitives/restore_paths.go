package primitives

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// What the three restore primitives share: the rule that turns a NAME the plane
// sent into a PATH only the node could have known, and the rule that there is
// no key on the wire to begin with.
//
// RULE 1, THE PLANE CANNOT EXPRESS A PATH. Under SSH the plane composed
// absolute paths and handed them to a root process — `bash restore_database.sh
// "$DB_NAME" /backups/whatever.sql.gz.enc`. The path was a string the plane
// built, so a compromised plane could aim the one operation that DROPS A SCHEMA
// at any file on the node, and aim the project restore — which extracts a tree
// and deletes what the archive does not carry — at any directory. The
// vocabulary here has no path in it. There is a filename, it must match a
// backup artifact's shape, and the node resolves it inside its own backup
// directory. resolveBackupFile below is where that happens, once, for all three.
//
// RULE 2, NO KEY MATERIAL CROSSES THE WIRE, and it is enforced by the parameter
// lists being what they are rather than by a check that has to run. None of the
// three primitives declares key_file, encryption_key, recovery_private_key,
// recovery_public_key or anything else that could carry key bytes, so a job
// carrying one is refused by Validate as an undeclared key before any of this
// code is reached. Each script then resolves the key on the node, from the
// node's own disk, exactly as it does when an operator runs it by hand:
//
//   - restore_database.sh: --key-file, then $BACKUP_ENCRYPTION_KEY, then
//     ~/.joinery_backup_key. The primitives pass no --key-file and the agent
//     sets no BACKUP_ENCRYPTION_KEY, so the node's own key file is what is used.
//   - restore_project.sh 1.3.0: the envelope sidecar beside the archive, opened
//     with this site's own backup_site_key, then --key-file, then
//     ~/.joinery_backup_key. Again the primitive passes nothing, so the node
//     opens its own envelope with its own key.
//   - restore_chain.sh: --key-file is mandatory, and the chain data key is
//     recovered on the node by backup_envelope.php open against the node's own
//     backup_site_key. See restore_chain's own file for what that costs.
//
// A read of the wire format is therefore enough to see that no key is on it,
// which is the property A4 asks for: not "the builder was careful", but "there
// is no field for it".

// backupFileName is what a restorable archive may be called. The same pattern
// upload_backup and delete_backup use, and for the same reason: it excludes the
// path separator, and requiring an alphanumeric first character excludes "."
// and ".." as well, so neither traversal nor an absolute path can be spelled.
var backupFileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// databaseArchiveSuffixes are what restore_database.sh can actually read. Its
// header says so: "Supported formats: .sql .sql.gz .sql.gz.enc". Longest first,
// the ordering rule backupExtensions documents.
var databaseArchiveSuffixes = []string{".sql.gz.enc", ".sql.gz", ".sql"}

// projectArchiveSuffixes are what restore_project.sh can read: a project
// archive, encrypted or not.
var projectArchiveSuffixes = []string{".tar.gz.enc", ".tar.gz"}

// chainWorkspacePrefix names the per-chain working directory, matching what the
// SSH path creates (/backups/restore_<chain_id>). It is a PREFIX plus the chain
// id and nothing else, so the whole directory name is derived from one
// pattern-bound parameter.
const chainWorkspacePrefix = "restore_"

// chainKeyFile is the recovered chain data key, inside that workspace.
const chainKeyFile = "chain.key"

// chainManifestFile is what makes a workspace a chain rather than a directory.
const chainManifestFile = "manifest.json"

// resolveBackupFile turns the "file" parameter into an absolute path inside
// this node's own backup directory for the named profile, or refuses.
//
// Three refusals, in the order that gives the most useful answer first:
//
//  1. the name is not a restorable archive of the expected kind — a decision,
//     not an attempt. Handing restore_database.sh a .tar.gz would have it fail
//     somewhere inside, after the operator has been told the restore started.
//  2. the resolved path escaped the backup directory. It cannot, given the
//     pattern, and that is exactly why the check is here: this is the assertion
//     that the pattern is still doing its job, in the file that would notice.
//  3. the file is not there. The script's own answer is RESTORE_USAGE_ERROR
//     after it has already been started as root; this is the same fact, said
//     before anything runs, naming the directory actually looked in — which on
//     a container node is not /backups, and that difference is what
//     backupdirs.go exists to get right.
func resolveBackupFile(ctx context.Context, env *ExecEnv, params Params, suffixes []string) (string, error) {
	name := params.String("file")
	if !hasAnySuffix(name, suffixes) {
		return "", refusedf("%q is not a %s this node can restore from", name, strings.Join(suffixes, " / "))
	}

	profile, err := restoreProfile(params)
	if err != nil {
		return "", err
	}

	dir := backupDirFor(ctx, env, profile)
	path := filepath.Join(dir, name)
	if filepath.Dir(path) != filepath.Clean(dir) {
		return "", refusedf("%q does not resolve to a file in this node's backup directory", name)
	}

	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", refusedf("this node has no backup called %q in %s", name, dir)
	}
	return path, nil
}

// restoreProfile reads the profile parameter: whose backups to look among.
//
// THERE IS NO DEFAULT, deliberately. Every restore declares profile as
// required, so an absent value cannot reach here through Validate — and a
// default sitting under a required parameter is a line a later reader has to
// decide the meaning of, in a file where choosing the wrong directory means
// loading one party's backup over the other's database. If the parameter ever
// stops being required, this refuses instead of quietly picking a side.
func restoreProfile(params Params) (BackupProfile, error) {
	switch params.String("profile") {
	case string(ProfileManager):
		return ProfileManager, nil
	case string(ProfileSite):
		return ProfileSite, nil
	default:
		return "", refusedf("this restore does not say whose backups to look among")
	}
}

// chainWorkspace resolves the artifact directory for one chain, node-side, from
// the chain id alone. The plane never names it, for the same reason it never
// names a backup file — restore_chain.sh extracts into a tree and replays the
// deletions the chain recorded, so a directory the plane could choose is a tree
// the plane could delete.
func chainWorkspace(ctx context.Context, env *ExecEnv, chainID string) string {
	return filepath.Join(backupBase(ctx, env), chainWorkspacePrefix+chainID)
}

func hasAnySuffix(name string, suffixes []string) bool {
	for _, s := range suffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// formatSeq renders a validated run number for argv. Its own function so the
// conversion is one thing rather than an fmt verb repeated at each call site,
// and so the value handed to a root process is provably a decimal integer.
func formatSeq(seq int64) string {
	return strconv.FormatInt(seq, 10)
}
