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

	// RULE 3, ADDED WITH THE DISPATCH ROUND: the archive has to be one this
	// machine remembers making.
	//
	// Rules 1 and 2 stop the plane naming a path and stop it sending a key. They
	// do not stop it choosing the BYTES: the plane owns the bucket, signs the
	// download, and picks the name a fetched object lands under, while the
	// operator approving the restore approves a name and never sees content. So
	// the last question — is this file the one this machine uploaded under this
	// name — is answered against a record the plane has never been able to
	// touch: the node-side upload ledger, written by the backup run itself at
	// upload time.
	//
	// It is checked HERE, immediately before a root process reads the file,
	// rather than only where the file arrived. download_backup verifies what it
	// fetches, which closes the delivery path; this closes the path where
	// something already sitting in the backup directory has been changed since.
	// A restore drops a schema or replaces a tree, so "was this ever tampered
	// with" is a question that belongs at the moment of use.
	if err := verifyLedgered(env, profile, name, path); err != nil {
		return "", err
	}
	return path, nil
}

// requireStagedChain refuses unless a chain workspace holds the two things
// staging leaves behind, and unless its manifest is one this machine recorded
// uploading.
//
// Split out of restoreChainArgs so the approval statement can make exactly the
// same checks before the operator is shown anything. An approval screen for a
// restore that would refuse the instant it was approved is worse than no screen:
// it spends the one moment of the operator's attention this design gets.
func requireStagedChain(env *ExecEnv, work string) error {
	manifest := filepath.Join(work, chainManifestFile)
	if info, err := os.Stat(manifest); err != nil || !info.Mode().IsRegular() {
		return refusedf("this node has no downloaded chain at %s: %s is missing. "+
			"Stage the chain first (the stage_chain primitive downloads what the chain manifest "+
			"names and recovers the data key from this machine's own key)",
			work, chainManifestFile)
	}

	key := filepath.Join(work, chainKeyFile)
	if info, err := os.Stat(key); err != nil || !info.Mode().IsRegular() {
		return refusedf("the chain at %s has no recovered data key (%s). "+
			"It is recovered on this node, from this node's own backup_site_key, by stage_chain. "+
			"No key may be sent to it: a key on the wire is a key in every stored job",
			work, chainKeyFile)
	}

	// The manifest against the ledger, under whichever shelf this machine
	// recorded uploading it to. The manifest carries every artifact's expected
	// size and hash, so restore_chain.sh's own verification is only worth as
	// much as the manifest is — which makes this the check the whole chain
	// restore rests on.
	relname := filepath.Base(work)
	if strings.HasPrefix(relname, chainWorkspacePrefix) {
		relname = strings.TrimPrefix(relname, chainWorkspacePrefix) + "/" + chainManifestFile
	} else {
		relname = chainManifestFile
	}
	// Both shelves are tried because a chain workspace does not record which one
	// its chain came from — the profile decides a bucket path, and by the time
	// anything is staged that question is settled.
	//
	// WHICH REFUSAL COMES BACK MATTERS. Every chain lives on exactly one shelf,
	// so the other one truthfully has no record of it, and returning the last
	// error meant a manifest whose BYTES were wrong was reported as a manifest
	// nobody had ever heard of — the same message a pre-ledger archive gets, and
	// a completely different problem. Prefer a refusal from a shelf that has
	// actually heard of this chain.
	var noRecord error
	for _, profile := range []BackupProfile{ProfileManager, ProfileSite} {
		err := verifyLedgered(env, profile, relname, manifest)
		if err == nil {
			return nil
		}
		if _, known := ledgerFact(env, profile, relname); known {
			return err
		}
		if noRecord == nil {
			noRecord = err
		}
	}
	return noRecord
}

// nodeProjectName is what THIS machine calls its own project: the last segment
// of its site root, which is the directory restore_chain.sh replaces
// (/var/www/html/<project>) and the name it hands the database engine.
//
// Empty on a machine with no site, and that is a real answer rather than a
// missing one — a siteless machine has no project to restore into.
func nodeProjectName(env *ExecEnv) string {
	if env == nil || env.SiteRoot == "" {
		return ""
	}
	return filepath.Base(env.SiteRoot)
}

// restoreChainProject answers which project a chain restore lands in, and
// refuses to let the plane answer it differently from this machine.
//
// The project is not a label. restore_chain.sh uses it twice: as the tree it
// replaces, and as the DATABASE NAME it hands the restore engine. So a value the
// plane chooses is a plane naming a database to drop — the exact thing
// restoreDatabaseTarget exists to stop it doing for restore_database, and the
// reason restore_project.sh is told no domain. The script has a check of its own
// (the archive's carried root directory must be the target's last segment), but
// that check happens after a root process has started, reads a chain the plane
// staged, and says nothing at all about the database name.
//
// So: this machine's own project is the answer. A job that names the same one
// passes through — the plane derives it from its own record of the node's web
// root, and agreement is the normal case. A job that names a different one is
// refused, naming both, because there is no legitimate restore of this machine's
// own chain into somebody else's project.
func restoreChainProject(env *ExecEnv, params Params) (string, error) {
	own := nodeProjectName(env)
	named := params.String("project")

	if own == "" {
		if named == "" {
			return "", refusedf("this node cannot say which project is its own, so it will not " +
				"guess which one to replace")
		}
		// A machine with no site root of its own has nothing to check against.
		// It also has nothing to restore, so this is very nearly unreachable —
		// but taking the job's word is the only thing left, and saying so here
		// is better than a silent fallback.
		return named, nil
	}
	if named != "" && named != own {
		return "", refusedf("this restore names the project %q, and this machine's own project is %q. "+
			"A chain restore replaces that project's files AND loads over the database of the same "+
			"name, so it will only ever do that to its own", named, own)
	}
	return own, nil
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
