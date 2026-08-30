package primitives

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// What is true of all three restores, asserted once. The per-primitive files
// below check each one's own argv; this file checks the properties that make
// the family safe to have compiled in at all.

var restoreFamily = []string{"restore_database", "restore_project", "restore_chain"}

// alwaysApproves stands in for the operator at the machine's own keyboard.
//
// The argv tests below are about what a restore COMPOSES, not about who said
// yes, so they run with the approval already given — and they say so by name,
// because a test environment that silently approved would be a test environment
// in which the gate could disappear unnoticed. TestARestoreNeedsAnApprovalGate
// is the one that asserts the gate is there.
type alwaysApproves struct{ asked []ApprovalStatement }

func (a *alwaysApproves) Require(ctx context.Context, jobID int64, s ApprovalStatement) error {
	a.asked = append(a.asked, s)
	return nil
}

// deadlineRecorder answers yes, and remembers the deadline it was handed.
type deadlineRecorder struct {
	deadline time.Time
	ok       bool
}

func (d *deadlineRecorder) Require(ctx context.Context, jobID int64, s ApprovalStatement) error {
	d.deadline, d.ok = ctx.Deadline()
	return nil
}

// alwaysDeclines is the operator saying no.
type alwaysDeclines struct{}

func (alwaysDeclines) Require(ctx context.Context, jobID int64, s ApprovalStatement) error {
	return refusedf("the operator of this machine declined this restore")
}

// restoreEnv builds a node with a real backup directory under a temp site root,
// optionally holding the named files — and, for each of them, the LEDGER ENTRY
// that says this machine uploaded it.
//
// Writing the ledger here rather than in each test is deliberate: an archive
// with no ledger entry is refused, so a helper that made files without records
// would make every restore test a test of the ledger refusal. The one test that
// wants that case (TestARestoreRefusesAnArchiveTheNodeNeverUploaded) removes the
// entry itself, which is legible where a missing setup step would not be.
// restoreFixtureProject is the project every restore fixture belongs to. The
// site root ENDS in it, because that is where a node's own project name comes
// from — restoreChainProject reads it off the site root and refuses a job naming
// any other. A fixture whose root did not end in it would be a machine whose own
// project is "001", which is what t.TempDir() hands out.
const restoreFixtureProject = "jeremytunnell"

func restoreEnv(t *testing.T, files ...string) *ExecEnv {
	t.Helper()
	root := filepath.Join(t.TempDir(), restoreFixtureProject)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"backups", filepath.Join("backups", managerSubdir)} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// The real address: config/backup-ledger under this machine's own site root.
	// Derived rather than injected, so the tests exercise the same resolution
	// production does — a seam here would be a seam that could be wrong.
	ledgerRoot := filepath.Join(root, "config", ledgerDirName)
	if err := os.MkdirAll(ledgerRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	ledgers := map[BackupProfile]map[string]ledgerEntry{
		ProfileSite:    {},
		ProfileManager: {},
	}
	for _, rel := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		profile, relname := ledgerKeyFor(rel)
		sum := sha256.Sum256([]byte("x"))
		ledgers[profile][relname] = ledgerEntry{
			SHA256:       hex.EncodeToString(sum[:]),
			Bytes:        1,
			UploadedTime: time.Now().UTC().Add(-3 * time.Hour).Format("2006-01-02 15:04:05"),
		}
	}
	for profile, entries := range ledgers {
		body, err := json.Marshal(entries)
		if err != nil {
			t.Fatal(err)
		}
		name := "site.json"
		if profile == ProfileManager {
			name = "manager.json"
		}
		if err := os.WriteFile(filepath.Join(ledgerRoot, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return &ExecEnv{
		SiteRoot: root,
		WebRoot:  filepath.Join(root, "public_html"),
		// What this machine's own config says its database is called. The plane
		// has no column for it; see ExecEnv.DBName.
		DBName:   "jeremytunnell",
		Approval: &alwaysApproves{},
	}
}

// ledgerKeyFor turns a site-root-relative test path into the (profile, name)
// pair the ledger is keyed on — the same mapping BackupRunner::upload makes when
// it records an artifact.
func ledgerKeyFor(rel string) (BackupProfile, string) {
	rel = filepath.ToSlash(rel)
	// A staged chain workspace, restore_<chain_id>/, holds artifacts whose
	// ledger key is <chain_id>/<name> — the workspace prefix is a local
	// staging detail and was never part of what was uploaded.
	if after, ok := strings.CutPrefix(rel, "backups/"+chainWorkspacePrefix); ok {
		return ProfileManager, after
	}
	if after, ok := strings.CutPrefix(rel, "backups/"+managerSubdir+"/"); ok {
		return ProfileManager, after
	}
	return ProfileSite, strings.TrimPrefix(rel, "backups/")
}

// ledgerFileFor is where restoreEnv put one profile's ledger, for the tests
// that need to take an entry away again.
func ledgerFileFor(env *ExecEnv, profile BackupProfile) string {
	return ledgerPath(env, profile)
}

func restorePrimitive(t *testing.T, name string) Primitive {
	t.Helper()
	p, ok := Lookup(name)
	if !ok {
		t.Fatalf("%s should be registered", name)
	}
	return p
}

func TestEveryRestoreIsDestructive(t *testing.T) {
	// The class is not a label, it is what the compiled ceiling keys off. A
	// restore registered as operate would be dispatchable unattended on every
	// node in the fleet the moment it shipped.
	for _, name := range restoreFamily {
		if class := restorePrimitive(t, name).Class; class != ClassDestructive {
			t.Errorf("%s is class %q — a restore replaces data and must be %q", name, class, ClassDestructive)
		}
	}
}

func TestARestoreNeedsAnApprovalGate(t *testing.T) {
	// The resting state, and the one that must never regress: a node with no way
	// to ask its own operator does not restore. A build that forgot to wire the
	// gate, or a machine whose database is down, refuses — it does not fall
	// through to running, and it does not treat "nobody to ask" as "nobody
	// objected".
	for _, policy := range []*Policy{ShippedPolicy(), {Accept: []Class{ClassObserve, ClassOperate, ClassDestructive}, source: "a policy file that asks for everything"}} {
		for _, name := range restoreFamily {
			env := restoreEnv(t)
			env.Approval = nil
			// Deliberately an EMPTY parameter set. A machine that cannot ask
			// its operator refuses for that reason, ahead of anything about the
			// job — so this also pins the order: "I cannot ask" is a fact about
			// the machine and must not be reported as a bad parameter.
			_, err := Execute(context.Background(), env, policy, Request{
				JobID: 1, Primitive: name, Params: map[string]interface{}{},
			})
			if err == nil {
				t.Fatalf("%s ran with no way to approve it", name)
			}
			if !Refused(err) {
				t.Errorf("%s: this must be a refusal, not a failure: %v", name, err)
			}
			if !strings.Contains(err.Error(), "approve") {
				t.Errorf("%s: the refusal should say it cannot ask, got %q", name, err)
			}
		}
	}
}

func TestADeclinedRestoreDoesNotRun(t *testing.T) {
	// The operator at the machine says no, and that is the end of it — a
	// refusal, reported as a decision rather than a fault.
	env := restoreEnv(t, "backups/manager/jeremytunnell_2026-08-27.tar.gz.enc")
	env.Approval = alwaysDeclines{}
	_, err := Execute(context.Background(), env, ShippedPolicy(), Request{
		JobID: 7, Primitive: "restore_project",
		Params: map[string]interface{}{
			"project_name": "jeremytunnell",
			"file":         "jeremytunnell_2026-08-27.tar.gz.enc",
			"profile":      "manager",
			"force":        true,
		},
	})
	if !Refused(err) || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("a declined restore must refuse and say so, got %v", err)
	}
}

func TestTheApprovalIsAskedAfterValidationAndBeforeAnythingRuns(t *testing.T) {
	// Order matters twice. A malformed job is refused BEFORE an operator is
	// asked — nobody should be shown an approval screen for a job the node was
	// going to reject anyway. And a well-formed job is approved BEFORE the
	// script is reached, which is what the manifest refusal below proves: it
	// comes from script.go, which only runs once the gate has let the job past.
	gate := &alwaysApproves{}
	env := restoreEnv(t, "backups/manager/jeremytunnell_2026-08-27.tar.gz.enc")
	env.Approval = gate

	_, err := Execute(context.Background(), env, ShippedPolicy(), Request{
		JobID: 2, Primitive: "restore_project",
		Params: map[string]interface{}{"nonsense": strings.Repeat("x", 40)},
	})
	if err == nil || !strings.Contains(err.Error(), "undeclared key") {
		t.Fatalf("a malformed job should be refused on its parameters, got %v", err)
	}
	if len(gate.asked) != 0 {
		t.Fatalf("an operator was asked to approve a job the node was going to refuse anyway")
	}

	_, err = Execute(context.Background(), env, ShippedPolicy(), Request{
		JobID: 3, Primitive: "restore_project",
		Params: map[string]interface{}{
			"project_name": "jeremytunnell",
			"file":         "jeremytunnell_2026-08-27.tar.gz.enc",
			"profile":      "manager",
			"force":        true,
		},
	})
	if err == nil || !Refused(err) {
		t.Fatalf("without a signed manifest the script must still refuse, got %v", err)
	}
	if len(gate.asked) != 1 {
		t.Fatalf("the operator should have been asked exactly once, was asked %d times", len(gate.asked))
	}
}

func TestTheApprovalStatementIsComposedByTheNode(t *testing.T) {
	// What the operator reads must come from this machine's own disk, not from
	// the job. The archive's recorded age is the sharpest case: it is the fact
	// that catches a REPLAY, which every signature and every envelope would
	// happily confirm, and there is nowhere in the job it could have come from.
	gate := &alwaysApproves{}
	env := restoreEnv(t, "backups/manager/db_2026-08-27.sql.gz.enc")
	env.Approval = gate

	Execute(context.Background(), env, ShippedPolicy(), Request{
		JobID: 4, Primitive: "restore_database",
		Params: map[string]interface{}{
			"file":    "db_2026-08-27.sql.gz.enc",
			"profile": "manager",
		},
	})
	if len(gate.asked) != 1 {
		t.Fatalf("the operator was asked %d times, want 1", len(gate.asked))
	}
	statement := gate.asked[0]
	if statement.Primitive != "restore_database" {
		t.Errorf("the statement names %q", statement.Primitive)
	}
	// The node's own database name, which the plane has no column for.
	if !strings.Contains(statement.Summary, "jeremytunnell") {
		t.Errorf("the statement should name the database being erased, got %q", statement.Summary)
	}
	labels := map[string]string{}
	for _, f := range statement.Facts {
		labels[f.Label] = f.Value
	}
	for _, want := range []string{"Database", "Archive", "Size", "Taken", "Fingerprint"} {
		if _, ok := labels[want]; !ok {
			t.Errorf("the statement has no %q line — the operator cannot check what they are approving", want)
		}
	}
	if !strings.Contains(labels["Taken"], "hours ago") {
		t.Errorf("the archive's age should be spelled out as an age, got %q", labels["Taken"])
	}
}

func TestARestoreRefusesAnArchiveTheNodeNeverUploaded(t *testing.T) {
	// The replay and forgery defence, at the moment of use. The plane chooses
	// the bucket, the signature and the landing name; the operator approves a
	// NAME. So the last question — are these the bytes this machine uploaded
	// under this name — is answered against a record the plane has never been
	// able to touch.
	env := restoreEnv(t, "backups/manager/db_2026-08-27.sql.gz.enc")
	if err := os.WriteFile(ledgerFileFor(env, ProfileManager), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Execute(context.Background(), env, ShippedPolicy(), Request{
		JobID: 5, Primitive: "restore_database",
		Params: map[string]interface{}{
			"file":    "db_2026-08-27.sql.gz.enc",
			"profile": "manager",
		},
	})
	if !Refused(err) || !strings.Contains(err.Error(), "no record of uploading") {
		t.Fatalf("an unledgered archive must be refused, got %v", err)
	}
}

func TestARestoreRefusesAnArchiveWhoseBytesChanged(t *testing.T) {
	// The same defence against the archive that IS ledgered and has since been
	// altered on disk. The name matches, the entry exists, the bytes do not.
	env := restoreEnv(t, "backups/manager/db_2026-08-27.sql.gz.enc")
	archive := filepath.Join(env.SiteRoot, "backups", managerSubdir, "db_2026-08-27.sql.gz.enc")
	if err := os.WriteFile(archive, []byte("something else entirely"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Execute(context.Background(), env, ShippedPolicy(), Request{
		JobID: 6, Primitive: "restore_database",
		Params: map[string]interface{}{
			"file":    "db_2026-08-27.sql.gz.enc",
			"profile": "manager",
		},
	})
	if !Refused(err) || !strings.Contains(err.Error(), "not one this node uploaded") {
		t.Fatalf("a tampered archive must be refused, got %v", err)
	}
}

func TestNoRestoreHasAParameterThatCouldCarryAKey(t *testing.T) {
	// A4's read side, enforced by the vocabulary rather than by a check. There
	// is no field for key material, so a job carrying some is refused by
	// Validate as an undeclared key before any restore code is reached.
	banned := []string{
		"key", "key_file", "keyfile", "key_path", "encryption_key",
		"recovery_key", "recovery_private_key", "recovery_public_key",
		"recovery_fpr", "private_key", "passphrase", "password", "secret",
	}
	for _, name := range restoreFamily {
		for _, spec := range restorePrimitive(t, name).Params {
			for _, bad := range banned {
				if spec.Name == bad {
					t.Errorf("%s declares %q — no key material may cross the wire", name, spec.Name)
				}
			}
		}
	}
}

func TestAJobCarryingKeyMaterialIsRefused(t *testing.T) {
	// The same property from the other side: the actual refusal a plane trying
	// to send a key would get. Checked at Validate, since the ceiling would
	// otherwise answer first.
	for _, name := range restoreFamily {
		p := restorePrimitive(t, name)
		for _, bad := range []string{"key_file", "encryption_key", "recovery_private_key"} {
			raw := map[string]interface{}{bad: "AAAAC3NzaC1lZDI1NTE5"}
			if _, err := Validate(p.Params, raw); err == nil {
				t.Errorf("%s accepted %q — key material must have nowhere to land", name, bad)
			} else if !strings.Contains(err.Error(), "undeclared key") {
				t.Errorf("%s: %q should be refused as undeclared, got %q", name, bad, err)
			}
		}
	}
}

func TestNoRestoreCanBeAskedToNameAPath(t *testing.T) {
	// Rule 1. Under SSH the plane composed the path and handed it to a root
	// process that drops a schema or extracts over a tree.
	for _, name := range []string{"restore_database", "restore_project"} {
		p := restorePrimitive(t, name)
		for _, bad := range []string{
			"/backups/site.sql.gz", "../../etc/shadow", "..", ".",
			".hidden.sql.gz", "sub/dir.tar.gz", "a.sql.gz\x00.png", "a b.sql.gz", "",
		} {
			raw := validRestoreParams(name)
			raw["file"] = bad
			if _, err := Validate(p.Params, raw); err == nil {
				t.Errorf("%s accepted file %q — that is a path", name, bad)
			}
		}
	}

	// The chain names no file at all; its one wire-supplied path component is
	// the chain id, which becomes a directory name.
	chain := restorePrimitive(t, "restore_chain")
	for _, bad := range []string{"../escape", "chain-1/../..", "/backups/chain-1", "chain-1;rm", "chain-.."} {
		raw := validRestoreParams("restore_chain")
		raw["chain_id"] = bad
		if _, err := Validate(chain.Params, raw); err == nil {
			t.Errorf("restore_chain accepted chain_id %q — it becomes a directory name", bad)
		}
	}
}

func TestEveryRestoreDeclaresItsOwnTimeout(t *testing.T) {
	// A restore inheriting the 5-minute default would be killed part-way
	// through, which for these three is the worst state each one has.
	for _, name := range restoreFamily {
		p := restorePrimitive(t, name)
		if p.Timeout <= DefaultTimeout {
			t.Errorf("%s declares %v, at or under the %v default — a restore is not five minutes' work",
				name, p.Timeout, DefaultTimeout)
		}
		if p.Timeout > MaxTimeout {
			t.Errorf("%s declares %v, over the %v ceiling", name, p.Timeout, MaxTimeout)
		}
	}
}

func TestEveryRestoreRunsAManifestVerifiedScript(t *testing.T) {
	// Not an embedded implementation: the thing that runs as root is a file on
	// the node's disk, checked against the signed release manifest first. And
	// none of them takes stdin — the scripts read argv, and the one thing that
	// would justify a stdin channel is a credential this vocabulary does not
	// carry.
	for _, name := range restoreFamily {
		p := restorePrimitive(t, name)
		if p.Script == nil {
			t.Fatalf("%s must invoke a shipped script, not embed the logic", name)
		}
		if !strings.HasPrefix(p.Script.ScriptPath, "maintenance_scripts/sysadmin_tools/restore_") {
			t.Errorf("%s runs %q, which is not the shipped restore engine", name, p.Script.ScriptPath)
		}
		if p.Script.StdinFrom != nil {
			t.Errorf("%s supplies stdin; these scripts read argv and carry no credential", name)
		}
		if p.Script.ArgsFrom == nil {
			t.Errorf("%s must compose argv node-side — a template can only emit what the wire sent", name)
		}
	}
}

func TestAMissingScriptTreeRefusesRatherThanRuns(t *testing.T) {
	// A machine with no site root and no support bundle has no tree to resolve
	// the script in, and no manifest to check it against.
	p := restorePrimitive(t, "restore_database")
	params, err := Validate(p.Params, validRestoreParams("restore_database"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runScriptPrimitive(context.Background(), &ExecEnv{}, p, params); err == nil || !Refused(err) {
		t.Fatalf("a machine with no tree must refuse, got %v", err)
	}
}

// validRestoreParams is one well-formed job per primitive, so every negative
// test above varies exactly one field of something that otherwise passes.
func validRestoreParams(name string) map[string]interface{} {
	switch name {
	case "restore_database":
		return map[string]interface{}{
			"db_name": "jeremytunnell", "file": "db_2026-08-27.sql.gz.enc", "profile": "manager",
		}
	case "restore_project":
		return map[string]interface{}{
			"project_name": "jeremytunnell", "file": "jeremytunnell_2026-08-27.tar.gz.enc",
			"profile": "manager", "force": true,
		}
	default:
		return map[string]interface{}{
			"project": "jeremytunnell", "chain_id": "chain-20260807_231507",
		}
	}
}

func TestTheApprovalWaitIsInsideThePrimitivesDeadline(t *testing.T) {
	// The plane's claim budget bounds the WHOLE claim, not the work inside it —
	// and a destructive job is claimed and then held while a person answers a
	// challenge. If the deadline started after the approval instead, a restore
	// could spend the full approval window and then the full work budget, over
	// the plane's ceiling, and the plane would hand the job out again while the
	// first copy was still restoring. Two concurrent restores is the one thing
	// in this vocabulary that destroys what it was recovering.
	//
	// So: the context the gate is handed must already carry the primitive's own
	// deadline. Asserted by looking at it, because the alternative is noticing
	// during a restore.
	recorder := &deadlineRecorder{}
	env := restoreEnv(t, "backups/manager/db_2026-08-27.sql.gz.enc")
	env.Approval = recorder

	p := restorePrimitive(t, "restore_database")
	before := time.Now()
	Execute(context.Background(), env, ShippedPolicy(), Request{
		JobID: 9, Primitive: "restore_database",
		Params: map[string]interface{}{
			"file":    "db_2026-08-27.sql.gz.enc",
			"profile": "manager",
		},
	})

	if !recorder.ok {
		t.Fatal("the approval gate was handed a context with no deadline — the wait is outside the " +
			"primitive's budget, so a held job can outlive the plane's claim")
	}
	// Measured from just before Execute, so the deadline is a hair MORE than the
	// budget rather than less; a minute of slack either way is the tolerance.
	budget := recorder.deadline.Sub(before)
	if budget > p.Timeout+time.Minute || budget < p.Timeout-time.Minute {
		t.Errorf("the gate's deadline is %v away, want about the primitive's own %v", budget, p.Timeout)
	}
}

func TestEveryRestoreLeavesRoomForItsOwnApproval(t *testing.T) {
	// The other half of the same invariant, stated as arithmetic: a primitive
	// whose whole deadline is the approval window has no time left to restore
	// in, and one that does not include the window kills jobs during the
	// approval it requires.
	for _, name := range restoreFamily {
		p := restorePrimitive(t, name)
		if p.Timeout <= ApprovalWindow {
			t.Errorf("%s declares %v, which is not more than the %v approval window — there would be "+
				"no time left to restore in", name, p.Timeout, ApprovalWindow)
		}
	}
}

func TestARestoreRefusesALedgerAnythingCouldHaveWritten(t *testing.T) {
	// A record that anything with a shell on this machine could have written is
	// not evidence that an archive is one this machine made — it is a file an
	// attacker can fill in to bless whatever bytes they like, on the one check
	// standing between a forged archive and a live database.
	//
	// This is not hypothetical. The deploy-time permissions sweep
	// (fix_permissions.sh) set the whole site tree to 770 in production and 777
	// in dev, and the ledger directory was not pinned out of it — so every
	// deploy reopened this until the directory was added to the pin list. The
	// mode check is what makes that a loud failure rather than a silent one.
	for _, tc := range []struct {
		name string
		mode os.FileMode
		dir  os.FileMode
	}{
		{"a group-writable ledger", 0o660, 0o700},
		{"a world-writable ledger", 0o666, 0o700},
		{"a ledger in a world-writable directory", 0o600, 0o777},
		{"a ledger in a group-writable directory", 0o600, 0o770},
	} {
		env := restoreEnv(t, "backups/manager/db_2026-08-27.sql.gz.enc")
		ledger := ledgerPath(env, ProfileManager)
		if err := os.Chmod(ledger, tc.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Dir(ledger), tc.dir); err != nil {
			t.Fatal(err)
		}

		_, err := Execute(context.Background(), env, ShippedPolicy(), Request{
			JobID: 11, Primitive: "restore_database",
			Params: map[string]interface{}{
				"file":    "db_2026-08-27.sql.gz.enc",
				"profile": "manager",
			},
		})
		if !Refused(err) {
			t.Errorf("%s: must be refused, got %v", tc.name, err)
			continue
		}
		if !strings.Contains(err.Error(), "writable by group or other") {
			t.Errorf("%s: the refusal should name the reason, got %q", tc.name, err)
		}
		// And it must not read as "the file is missing" — that sends someone to
		// the wrong fix entirely.
		if strings.Contains(err.Error(), "no upload ledger at") {
			t.Errorf("%s: an untrusted ledger reported as an absent one, got %q", tc.name, err)
		}
	}
}

func TestATightlyPermissionedLedgerIsAccepted(t *testing.T) {
	// The other direction, so the check cannot be "refuse everything". Backups
	// legitimately run under more than one account — root via the agent, the web
	// user on a site's own schedule — so ownership is deliberately not part of
	// the test. What is closed is group and other.
	env := restoreEnv(t, "backups/manager/db_2026-08-27.sql.gz.enc")
	ledger := ledgerPath(env, ProfileManager)
	if err := os.Chmod(ledger, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(ledger), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, ok := ledgerFact(env, ProfileManager, "db_2026-08-27.sql.gz.enc"); !ok {
		t.Fatal("a 0600 ledger in a 0700 directory should be readable")
	}
}

func TestABackupDuringTheApprovalWindowDoesNotRefuseTheRestore(t *testing.T) {
	// The failure this exists for, in order: an operator stages a chain, the
	// restore is dispatched and held while they read the approval screen, a
	// scheduled backup fires and re-uploads the chain manifest under the same
	// name — and then the approved restore is refused at the last step because
	// the manifest on disk is no longer the newest one recorded.
	//
	// It fails safe, and it fails at the worst moment: after a person has
	// decided, during a recovery. The ledger's question is "did this machine
	// make these bytes", and the staged manifest is one this machine made.
	const chainID = "chain-20260807_231507"
	work := filepath.Join("backups", chainWorkspacePrefix+chainID)
	env := restoreEnv(t,
		filepath.Join(work, chainManifestFile),
		filepath.Join(work, chainKeyFile),
	)
	manifest := filepath.Join(env.SiteRoot, work, chainManifestFile)

	// The chain grows while the operator is deciding: same name, new bytes,
	// recorded over the entry the staged file matched.
	staged, err := hashFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	grown := sha256.Sum256([]byte("the manifest after one more run"))
	rewriteLedgerEntry(t, env, ProfileManager, chainID+"/"+chainManifestFile,
		hex.EncodeToString(grown[:]), staged)

	if err := requireStagedChain(env, filepath.Join(env.SiteRoot, work)); err != nil {
		t.Fatalf("a chain staged before the chain grew must still restore: %v", err)
	}

	// And the operator is shown the age of what is STAGED, not of the run that
	// landed while they were reading. That line is the one fact on the screen no
	// automatic check can substitute for.
	entry, ok := ledgerMatchFor(env, ProfileManager, chainID+"/"+chainManifestFile, manifest)
	if !ok {
		t.Fatal("the staged manifest should match a recorded version")
	}
	if entry.SHA256 != staged {
		t.Errorf("the statement would report the newest version's age, not the staged one's")
	}

	// The limit of the change: bytes that were never recorded under that name
	// are still refused.
	if err := os.WriteFile(manifest, []byte("a manifest this machine never wrote"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = requireStagedChain(env, filepath.Join(env.SiteRoot, work))
	if !Refused(err) || !strings.Contains(err.Error(), "not one this node uploaded") {
		t.Fatalf("an unrecorded manifest must still be refused, got %v", err)
	}
}

// rewriteLedgerEntry makes a name's current version `now` and pushes `was` into
// its history — what BackupRunner does when a chain's manifest is re-uploaded.
func rewriteLedgerEntry(t *testing.T, env *ExecEnv, profile BackupProfile, relname, now, was string) {
	t.Helper()
	entries, _, err := readLedger(env, profile)
	if err != nil {
		t.Fatal(err)
	}
	entries[relname] = ledgerEntry{
		SHA256:       now,
		UploadedTime: time.Now().UTC().Format("2006-01-02 15:04:05"),
		Previous: []ledgerEntry{{
			SHA256:       was,
			UploadedTime: time.Now().UTC().Add(-2 * time.Hour).Format("2006-01-02 15:04:05"),
		}},
	}
	body, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ledgerPath(env, profile), body, 0o600); err != nil {
		t.Fatal(err)
	}
}
