package primitives

import (
	"os"
	"path/filepath"
	"testing"
)

// take_node_id is the one word that changes who a machine answers as, so what
// is worth testing is what it refuses, and that it stages rather than changes.

type stagedCall struct {
	id   int64
	slug string
}

// takeFixture is a copy site with a state directory, a node id and a stager
// that records what it was asked to write.
func takeFixture(t *testing.T, state string, copyOf string, nodeID int64) (*ExecEnv, *[]stagedCall) {
	t.Helper()
	states := t.TempDir()
	old := SiteStateDir
	SiteStateDir = states
	t.Cleanup(func() { SiteStateDir = old })
	root := filepath.Join(t.TempDir(), "copysite")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(states, "copysite")
	if state != "" {
		mustWrite(t, filepath.Join(dir, "state"), state+"\n", 0o644)
	}
	if copyOf != "" {
		mustWrite(t, filepath.Join(dir, "copy_of"), copyOf+"\n", 0o644)
	}
	calls := &[]stagedCall{}
	env := &ExecEnv{
		SiteRoot: root,
		NodeID:   func() (int64, error) { return nodeID, nil },
		StageNodeID: func(id int64, slug string) error {
			*calls = append(*calls, stagedCall{id, slug})
			return nil
		},
	}
	ConsumeIdentityTake()
	t.Cleanup(func() { ConsumeIdentityTake() })
	return env, calls
}

func takeParams(t *testing.T, id int64, slug string) Params {
	return validParams(t, "take_node_id", map[string]interface{}{"node_id": id, "node_slug": slug})
}

func supervised(t *testing.T) supervision {
	return withSystemd(t, supervisionIn(t), "always")
}

func TestACopyStagesItsSourcesIdAndChangesNothingYet(t *testing.T) {
	env, calls := takeFixture(t, "quiet copy", "41", 57)
	out, err := takeNodeIDUnder(env, takeParams(t, 41, "copytest"), supervised(t))
	if err != nil {
		t.Fatalf("take_node_id: %v", err)
	}
	if len(*calls) != 1 || (*calls)[0] != (stagedCall{41, "copytest"}) {
		t.Errorf("staged %v, want node 41 as copytest", *calls)
	}
	if out["from_node_id"] != int64(57) || out["node_id"] != int64(41) {
		t.Errorf("result %v", out)
	}
	if got := ConsumeIdentityTake(); got != 41 {
		t.Errorf("the job loop is asked to take %d, want 41", got)
	}
	if got := ConsumeIdentityTake(); got != 0 {
		t.Errorf("a consumed take is asked again (%d)", got)
	}
}

func TestACopyTakesOnlyItsOwnSourcesId(t *testing.T) {
	env, calls := takeFixture(t, "quiet copy", "41", 57)
	if _, err := takeNodeIDUnder(env, takeParams(t, 42, "other"), supervised(t)); !Refused(err) {
		t.Errorf("a copy of node 41 took node 42's id: %v", err)
	}
	if len(*calls) != 0 || ConsumeIdentityTake() != 0 {
		t.Error("a refused take staged an identity")
	}
}

func TestALiveOrFrozenSiteTakesNoId(t *testing.T) {
	for name, state := range map[string]string{"live": "", "frozen": "quiet switchover"} {
		env, calls := takeFixture(t, state, "", 57)
		if _, err := takeNodeIDUnder(env, takeParams(t, 41, "copytest"), supervised(t)); !Refused(err) {
			t.Errorf("a %s site took another node's id: %v", name, err)
		}
		if len(*calls) != 0 {
			t.Errorf("a %s site staged an identity", name)
		}
	}
}

func TestACopyWithNoRecordedSourceTakesNoId(t *testing.T) {
	env, calls := takeFixture(t, "quiet copy", "", 57)
	if _, err := takeNodeIDUnder(env, takeParams(t, 41, "copytest"), supervised(t)); !Refused(err) {
		t.Errorf("a copy that records no source took an id: %v", err)
	}
	if len(*calls) != 0 {
		t.Error("it staged an identity")
	}
}

func TestAMachineAlreadyTheNodeIsRefused(t *testing.T) {
	env, calls := takeFixture(t, "quiet copy", "41", 41)
	if _, err := takeNodeIDUnder(env, takeParams(t, 41, "copytest"), supervised(t)); !Refused(err) {
		t.Errorf("a machine already node 41 staged it again: %v", err)
	}
	if len(*calls) != 0 {
		t.Error("it staged an identity")
	}
}

func TestAnUnsupervisedCopyKeepsItsId(t *testing.T) {
	// The new id takes effect at a restart; with nothing to restart the agent,
	// taking it would leave the machine answering as nobody.
	env, calls := takeFixture(t, "quiet copy", "41", 57)
	if _, err := takeNodeIDUnder(env, takeParams(t, 41, "copytest"), supervisionIn(t)); !Refused(err) {
		t.Errorf("an unsupervised copy staged an id: %v", err)
	}
	if len(*calls) != 0 {
		t.Error("it staged an identity")
	}
}

func TestTheWordRunsOnlyOnADormantCopy(t *testing.T) {
	p := mustLookup(t, "take_node_id")
	if p.Class != ClassOperate || p.Quiet != QuietCopy {
		t.Errorf("take_node_id is class %v, quiet %v; it is an operate word for a dormant copy only", p.Class, p.Quiet)
	}
	for _, raw := range []map[string]interface{}{
		{"node_id": 0, "node_slug": "copytest"},
		{"node_id": 41, "node_slug": "Copy Test"},
		{"node_id": 41},
	} {
		if _, err := Validate(p.Params, raw); err == nil {
			t.Errorf("params %v were accepted", raw)
		}
	}
}

func TestTheLookPathTravelsWithTheImport(t *testing.T) {
	f := newExportFixture(t)
	secret := "0123456789abcdef0123456789abcdef"
	mustWrite(t, filepath.Join(SiteStateDir, "copysite", copyLookSecretFile), secret+"\n", 0o600)
	out, err := f.importBundle(t, f.export(t, f.target.PublicKey()))
	if err != nil {
		t.Fatalf("copy_import: %v", err)
	}
	if out["look_path"] != "/.joinery-look/"+secret {
		t.Errorf("look_path %v", out["look_path"])
	}

	// A secret not of the quiet state's shape is not reported.
	mustWrite(t, filepath.Join(SiteStateDir, "copysite", copyLookSecretFile), "../../etc\n", 0o600)
	if got := copyLookPath(f.tEnv); got != "" {
		t.Errorf("a malformed secret is reported as %q", got)
	}
	os.Remove(filepath.Join(SiteStateDir, "copysite", copyLookSecretFile))
	if got := copyLookPath(f.tEnv); got != "" {
		t.Errorf("no secret is reported as %q", got)
	}
}
