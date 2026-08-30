package primitives

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// The node's own record of what it uploaded, read here so that a DESTRUCTIVE
// restore can refuse an archive this machine has no account of making.
//
// The file is written by the backup run itself (BackupLedger, PHP side), at
// upload time, on this machine, before the bytes were anywhere a management node
// could reach. Nothing in this package writes it: the agent reads it and
// refuses, which is the whole of its business with it.
//
// WHY THE CHECK IS HERE AND NOT ONLY IN THE DOWNLOAD SCRIPT. download_backup
// verifies what it fetches, and that closes the path where the plane hands over
// bytes. It does not close the path where an archive is already sitting in the
// backup directory — put there by an earlier download that has since been
// tampered with, or by anything else with write access to that directory. A
// restore replaces a live database or a live site tree, so the check that the
// artifact is one this machine made belongs immediately before that, not only at
// the moment it arrived.
//
// WHERE IT IS, and why the address is derived rather than compiled in.
// config/backup-ledger under this machine's own site root — beside
// config/backup_site_key, the other artifact that identifies one machine as the
// maker of its own backups. config/ is a named volume on a container node, so
// the ledger survives a container rebuild; a path under /var/lib would not, and
// a ledger that vanishes on a routine operation would leave the recovery path
// broken for as long as the current chain is old. restore_project.sh drops this
// directory from a staged archive for the matching reason: the first restore
// must not overwrite the record that vouches for the second.
//
// Derived from ExecEnv.SiteRoot rather than read from anywhere. There is no
// setting, no flag and no wire value that moves it — a ledger path something
// else can choose is a ledger something else can replace with one it wrote.
// This side only reads it; BackupLedger on the PHP side is the only writer.

// ledgerDirName is BackupLedger::DIR_NAME, under the site's config/.
const ledgerDirName = "backup-ledger"

// ledgerEntry is one recorded upload. Fields mirror BackupLedger::record.
type ledgerEntry struct {
	SHA256       string `json:"sha256"`
	Bytes        int64  `json:"bytes"`
	UploadedTime string `json:"uploaded_time"`
	ObjectKey    string `json:"object_key"`

	// Previous holds the versions this NAME used to have, newest first.
	//
	// Empty for every artifact, because chain artifacts are named per run and
	// written once. It is non-empty only for manifest.json, which every run of a
	// chain rewrites under a stable name — that is what a growing chain is. The
	// ledger's question is "did this machine make these bytes", not "are these
	// the newest bytes it made", and treating a rewritten name as having exactly
	// one true version refused an already-approved chain restore whenever a
	// scheduled backup landed during the approval window.
	Previous []ledgerEntry `json:"previous,omitempty"`
}

// matches reports which recorded version of a name these bytes are, if any.
func (e ledgerEntry) matches(sum string) (ledgerEntry, bool) {
	if e.SHA256 == sum {
		return e, true
	}
	for _, old := range e.Previous {
		if old.SHA256 == sum {
			return old, true
		}
	}
	return ledgerEntry{}, false
}

// ledgerDir is this machine's ledger directory, or "" on a machine with no site
// root — where there is nothing to restore in place anyway.
func ledgerDir(env *ExecEnv) string {
	if env == nil || env.SiteRoot == "" {
		return ""
	}
	return filepath.Join(strings.TrimRight(env.SiteRoot, "/"), "config", ledgerDirName)
}

// ledgerPath is the ledger file for one profile.
func ledgerPath(env *ExecEnv, profile BackupProfile) string {
	dir := ledgerDir(env)
	if dir == "" {
		return ""
	}
	name := "site"
	if profile == ProfileManager {
		name = "manager"
	}
	return filepath.Join(dir, name+".json")
}

// readLedger loads one profile's ledger. A missing file is not an error here —
// it is an empty ledger, and verifyLedgered turns that into the refusal that
// says so.
//
// A ledger that is WRITABLE BY GROUP OR OTHER is not an empty ledger and not a
// readable one: it is a file that something other than the accounts allowed to
// make a backup could have written, and a file like that vouches for nothing.
// It is refused, in the same posture and for the same reason LoadPolicy refuses
// a policy file it cannot trust the provenance of — failing open there would
// hand the decision to whoever could write the file, which is the one thing the
// file exists to prevent.
//
// Deliberately NOT a root-ownership check, which is where the obvious analogy
// with LoadPolicy stops. Backups legitimately run under more than one account:
// root via the agent on a managed node, the web user on a site's own scheduled
// run. Both are already trusted to make the backup whose hash is being
// recorded, so requiring root would refuse ledgers written by a party that is
// not the adversary. The adversary is the MANAGEMENT NODE, and it is no more
// able to write a 0600 www-data file than a 0600 root one. What the mode check
// closes is "anyone with a shell on this box", which a deploy-time permissions
// sweep had been opening on every deploy.
func readLedger(env *ExecEnv, profile BackupProfile) (map[string]ledgerEntry, bool, error) {
	path := ledgerPath(env, profile)
	if path == "" {
		return nil, false, nil
	}

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, true, &untrustedLedgerError{path: path, why: "is not a regular file"}
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return nil, true, &untrustedLedgerError{path: path,
			why: fmt.Sprintf("is writable by group or other (mode %04o), so something that is not "+
				"this machine's backup could have written it", perm)}
	}
	// The directory matters as much as the file: write permission on a
	// directory is permission to replace what is in it, so a wide-open
	// directory makes a tight file meaningless.
	if dir, err := os.Stat(filepath.Dir(path)); err == nil {
		if perm := dir.Mode().Perm(); perm&0o022 != 0 {
			return nil, true, &untrustedLedgerError{path: filepath.Dir(path),
				why: fmt.Sprintf("is writable by group or other (mode %04o), so the ledger inside "+
					"it could be replaced by anything with a shell on this machine", perm)}
		}
	}

	body, err := os.ReadFile(path)
	if err != nil {
		return nil, true, err
	}
	entries := map[string]ledgerEntry{}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, true, err
	}
	return entries, true, nil
}

// untrustedLedgerError is a ledger whose provenance cannot be relied on. It is
// its own type so the refusal can say that plainly rather than reporting it as
// an unreadable file — "I will not trust this" and "I could not open this" are
// different answers and lead to different fixes.
type untrustedLedgerError struct {
	path string
	why  string
}

func (e *untrustedLedgerError) Error() string {
	return e.path + " " + e.why
}

// ledgerOwner reports the uid owning a path, for the refusal message. Best
// effort: an unavailable uid is simply left out.
func ledgerOwner(path string) (uint32, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// verifyLedgered refuses unless the file at path is the file this machine
// recorded uploading under relname.
//
// relname is the name relative to the profile's backup directory — a bare
// filename for a standalone archive, "chain-…/files-0001.tar.gz.enc" for a chain
// artifact. It is what the PHP side keyed the entry on.
//
// The hash is computed over the whole file. On a multi-gigabyte archive that is
// tens of seconds, spent once, immediately before an operation whose contract is
// to destroy what is already there. That is the right trade and it is not close.
func verifyLedgered(env *ExecEnv, profile BackupProfile, relname, path string) error {
	entries, present, err := readLedger(env, profile)
	if untrusted, ok := err.(*untrustedLedgerError); ok {
		owner := ""
		if uid, found := ledgerOwner(untrusted.path); found {
			owner = fmt.Sprintf(" (owned by uid %d)", uid)
		}
		return refusedf("this node will not restore from %q: its upload ledger %s%s. "+
			"A record anything on this machine could have written is not evidence that an archive "+
			"is one this machine made. Fix the permissions (fix_permissions.sh pins this directory "+
			"to 0700) and dispatch the restore again",
			relname, untrusted.Error(), owner)
	}
	if err != nil {
		return refusedf("this node's upload ledger (%s) could not be read, so it cannot confirm "+
			"%q is an archive it made: %v", ledgerPath(env, profile), relname, err)
	}
	if !present {
		return refusedf("this node has no upload ledger at %s, so it cannot confirm %q is an archive "+
			"it made. A restore loads bytes as root over live data; it will not do that on the "+
			"strength of a filename alone. The ledger starts on this node's next backup run",
			ledgerPath(env, profile), relname)
	}

	entry, ok := entries[relname]
	if !ok {
		// Two very different situations, and the benign one dominates for a few
		// days after an upgrade: the ledger records only what has been uploaded
		// since it existed, so anything older is unrecognised. Naming that
		// first stops a routine case reading as an attack. The refusal is the
		// same either way, because this node genuinely cannot tell them apart.
		return refusedf("this node has no record of uploading %q. Either it predates this node's "+
			"upload ledger, or it is not the archive it is being offered as — and this node cannot "+
			"tell those apart, so it will not restore from it", relname)
	}

	sum, err := hashFile(path)
	if err != nil {
		return refusedf("could not read %q to check it against this node's upload ledger: %v", relname, err)
	}
	if _, ok := entry.matches(sum); !ok {
		return refusedf("the file called %q is not one this node uploaded under that name "+
			"(recorded %s…, on disk %s…) — a restore from it is refused",
			relname, short(entry.SHA256), short(sum))
	}
	return nil
}

// ledgerMatchFor returns the recorded version that the file at path actually IS,
// which is not always the newest one recorded under that name.
//
// It exists for the approval statement. The operator is shown an archive's age,
// and on a chain restore that date is the single fact no automatic check can
// substitute for — so it has to be the age of the bytes in front of them. A
// screen reporting the newest recorded time for a staged manifest that is one
// run behind would be showing a date that is not quite a lie and not the truth
// either, on the one line the whole screen exists for.
func ledgerMatchFor(env *ExecEnv, profile BackupProfile, relname, path string) (ledgerEntry, bool) {
	entries, present, err := readLedger(env, profile)
	if err != nil || !present {
		return ledgerEntry{}, false
	}
	entry, ok := entries[relname]
	if !ok {
		return ledgerEntry{}, false
	}
	sum, err := hashFile(path)
	if err != nil {
		return ledgerEntry{}, false
	}
	return entry.matches(sum)
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ledgerFact returns what the ledger records about an artifact, for the approval
// statement. Absence is not an error to the caller: the statement says the
// archive's age is unknown, and verifyLedgered is what refuses.
func ledgerFact(env *ExecEnv, profile BackupProfile, relname string) (ledgerEntry, bool) {
	entries, present, err := readLedger(env, profile)
	if err != nil || !present {
		return ledgerEntry{}, false
	}
	entry, ok := entries[relname]
	return entry, ok
}

func short(hexSum string) string {
	if len(hexSum) > 16 {
		return hexSum[:16]
	}
	return hexSum
}
