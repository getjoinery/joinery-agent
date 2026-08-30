package primitives

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// What a restore tells its own operator before it is allowed to happen.
//
// The statement is composed HERE, on the node, from the node's own records —
// never from the job. That is the whole point of it: the party that dispatched
// the job is the party whose word is not being taken, so a screen that repeated
// the job's own description back would be asking the operator to approve the
// attacker's account of the attack. Every fact below is read from this machine's
// disk: the resolved archive, its size, and its age as this machine recorded it
// at upload time.
//
// THE AGE IS FIRST-CLASS, and that is deliberate rather than tidy. The attack
// that survives a fully sealed, fully signed fleet is REPLAY: this machine's own
// genuine month-old archive, served under a fresh-looking name. Every signature
// checks out because the archive really is this machine's. What does not check
// out is the date, so the date is on the screen, in words, next to what it is
// about to destroy — not in a details fold.

// restoreFileFacts describes one resolved archive: what it is, how big, how old.
//
// relname is the ledger key — the same name the upload recorded, so what the
// operator is shown is drawn from the same row that will refuse the restore if
// the bytes are wrong.
func restoreFileFacts(env *ExecEnv, profile BackupProfile, relname, path string) []ApprovalFact {
	facts := []ApprovalFact{{Label: "Archive", Value: relname}}

	if info, err := os.Stat(path); err == nil {
		facts = append(facts, ApprovalFact{Label: "Size", Value: humanBytes(info.Size())})
	}

	entry, ok := ledgerFact(env, profile, relname)
	if !ok {
		// Said plainly rather than left blank. An archive this machine has no
		// record of is one the restore is about to refuse anyway (see
		// verifyLedgered), and an operator should be told that on the approval
		// screen instead of discovering it after approving.
		facts = append(facts, ApprovalFact{
			Label: "Age",
			Value: "unknown — this machine has no record of uploading this archive, and will refuse to restore from it",
		})
		return facts
	}

	facts = append(facts, ApprovalFact{Label: "Taken", Value: describeAge(entry.UploadedTime)})
	facts = append(facts, ApprovalFact{Label: "Fingerprint", Value: short(entry.SHA256) + "…"})
	return facts
}

// describeAge renders a recorded upload time as a date AND an age, because the
// two answer different questions and the operator needs both: the date is what
// they compare against what they think they asked for, and the age is what makes
// "this is last month's" impossible to skim past.
func describeAge(uploaded string) string {
	if uploaded == "" {
		return "unknown"
	}
	t, err := time.Parse("2006-01-02 15:04:05", uploaded)
	if err != nil {
		return uploaded + " UTC"
	}
	age := time.Since(t)
	switch {
	case age < 0:
		return uploaded + " UTC (dated in the future — this machine's clock and this record disagree)"
	case age < time.Hour:
		return fmt.Sprintf("%s UTC (%d minutes ago)", uploaded, int(age.Minutes()))
	case age < 48*time.Hour:
		return fmt.Sprintf("%s UTC (%d hours ago)", uploaded, int(age.Hours()))
	default:
		return fmt.Sprintf("%s UTC (%d days ago)", uploaded, int(age.Hours()/24))
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 3; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

// describeRestoreDatabase: what a database restore would do to this machine.
func describeRestoreDatabase(ctx context.Context, env *ExecEnv, params Params) (ApprovalStatement, error) {
	path, err := resolveBackupFile(ctx, env, params, databaseArchiveSuffixes)
	if err != nil {
		return ApprovalStatement{}, err
	}
	target, err := restoreDatabaseTarget(env, params)
	if err != nil {
		return ApprovalStatement{}, err
	}
	profile, err := restoreProfile(params)
	if err != nil {
		return ApprovalStatement{}, err
	}

	facts := []ApprovalFact{
		{Label: "Database", Value: target},
		{Label: "What happens to it", Value: "every table is dropped and replaced by the archive's contents"},
	}
	facts = append(facts, restoreFileFacts(env, profile, filepath.Base(path), path)...)
	if params.Has("db_user") {
		facts = append(facts, ApprovalFact{Label: "Loaded as", Value: params.String("db_user")})
	}

	return ApprovalStatement{
		Primitive: "restore_database",
		Summary: "This will erase the database " + target + " on this machine and load an old copy of it " +
			"in its place. Anything written since that copy was taken is gone.",
		Facts: facts,
	}, nil
}

// describeRestoreProject: what a project restore would do to this machine.
func describeRestoreProject(ctx context.Context, env *ExecEnv, params Params) (ApprovalStatement, error) {
	path, err := resolveBackupFile(ctx, env, params, projectArchiveSuffixes)
	if err != nil {
		return ApprovalStatement{}, err
	}
	profile, err := restoreProfile(params)
	if err != nil {
		return ApprovalStatement{}, err
	}

	// No skip flags in this vocabulary, deliberately (see the primitive's own
	// header) — a project restore replaces the tree and the database, and the
	// statement says so without qualification.
	what := "this machine's site files and its database"

	facts := []ApprovalFact{
		{Label: "Project", Value: params.String("project_name")},
		{Label: "What is replaced", Value: what},
	}
	facts = append(facts, restoreFileFacts(env, profile, filepath.Base(path), path)...)

	return ApprovalStatement{
		Primitive: "restore_project",
		Summary: "This will replace " + what + " with an old copy. Files the archive does not " +
			"carry are removed, and anything written since that copy was taken is gone.",
		Facts: facts,
	}, nil
}

// describeRestoreChain: what a chain restore would do to this machine.
//
// A chain restore is the fleet's normal restore, and the fact that matters most
// is which RUN it lands on — the difference between "yesterday" and "six days
// ago" is a seq number, and a seq number is not something an operator reads as a
// date. So the run's own recorded date is spelled out.
func describeRestoreChain(ctx context.Context, env *ExecEnv, params Params) (ApprovalStatement, error) {
	chainID := params.String("chain_id")
	work := chainWorkspace(ctx, env, chainID)

	// The same two files restoreChainArgs insists on. Checked here too, so that
	// an operator is never shown an approval screen for a restore that would
	// refuse the moment they approved it.
	manifest := filepath.Join(work, chainManifestFile)
	if err := requireStagedChain(env, work); err != nil {
		return ApprovalStatement{}, err
	}

	// WHICH PROJECT, AND WHICH DATABASE — named on the screen, because they are
	// what gets destroyed and because a chain restore is the one restore that
	// used not to say. restore_database names its database and restore_project
	// names its project; this one showed a chain id, and a chain id is not
	// something an operator can read as "my site" or "somebody else's".
	//
	// The value is this machine's own (restoreChainProject refuses any other),
	// so what the screen shows is what the node resolved, never what the job
	// asserted — the same rule every other fact here follows.
	project, err := restoreChainProject(env, params)
	if err != nil {
		return ApprovalStatement{}, err
	}

	facts := []ApprovalFact{
		{Label: "Chain", Value: chainID},
		{Label: "What is replaced", Value: chainReplaces(params)},
		{Label: "Project", Value: project + " (the site at /var/www/html/" + project + ")"},
	}
	if !params.Bool("skip_database") {
		// restore_chain.sh hands the project name to the restore engine as the
		// database name, so that is the database that gets dropped and reloaded
		// — said outright rather than left to be inferred from "and its
		// database".
		db := ApprovalFact{Label: "Database", Value: project}
		if env != nil && env.DBName != "" && env.DBName != project {
			// Worth stopping on. This machine's config names one database and
			// the chain restore would load over another, which means either the
			// site is about to keep running against an untouched database or
			// something unrelated is about to be overwritten.
			db.Value = project + " — but this machine's own config names " + env.DBName +
				", so this would not restore the database this site actually uses"
		}
		facts = append(facts, db)
	}
	facts = append(facts, ApprovalFact{Label: "Staged in", Value: work})
	if params.Has("seq") {
		facts = append(facts, ApprovalFact{
			Label: "Restored as at run", Value: formatSeq(params.Int("seq"))})
	} else {
		facts = append(facts, ApprovalFact{
			Label: "Restored as at run", Value: "the newest run in this chain"})
	}

	// The age of the manifest that is ACTUALLY STAGED — matched by its bytes,
	// not read off the newest entry under its name.
	//
	// The distinction is the whole reason this is not a one-liner. A chain's
	// manifest is rewritten by every run, so the newest recorded time is when
	// the chain last grew, which is not necessarily what is sitting in the
	// workspace: a scheduled backup landing between staging and approval moves
	// the recorded time forward while the staged file stays where it was.
	// Reporting the newest would show the operator a date fresher than the thing
	// they are approving, on the one line the screen exists for.
	relname := chainID + "/" + chainManifestFile
	for _, profile := range []BackupProfile{ProfileManager, ProfileSite} {
		if entry, ok := ledgerMatchFor(env, profile, relname, manifest); ok {
			facts = append(facts, ApprovalFact{
				Label: "Chain last extended", Value: describeAge(entry.UploadedTime)})
			break
		}
	}
	if info, err := os.Stat(manifest); err == nil {
		facts = append(facts, ApprovalFact{
			Label: "Manifest staged", Value: info.ModTime().UTC().Format("2006-01-02 15:04:05") + " UTC"})
	}

	return ApprovalStatement{
		Primitive: "restore_chain",
		Summary: "This will replace " + chainReplaces(params) + " for " + project + " on this machine by " +
			"replaying the backup chain " + chainID + " from its full backup forward. Anything written " +
			"since the run it lands on is gone.",
		Facts: facts,
	}, nil
}

func chainReplaces(params Params) string {
	if params.Bool("skip_database") {
		return "this machine's site files (the database is left alone)"
	}
	return "this machine's site files and its database"
}
