package primitives

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// noopRun is a stand-in implementation for primitives that exist only to prove
// registration refuses them.
func noopRun(_ context.Context, _ *ExecEnv, _ Params) (map[string]interface{}, error) {
	return nil, nil
}

func TestAbsentPolicyFileRunsTheShippedPolicy(t *testing.T) {
	p, err := LoadPolicy(filepath.Join(t.TempDir(), "nothing-here.json"))
	if err != nil {
		t.Fatalf("an absent policy file is normal, not an error: %v", err)
	}
	if err := p.Accepts(ClassObserve); err != nil {
		t.Errorf("the shipped policy accepts observe: %v", err)
	}
	if err := p.Accepts(ClassOperate); err != nil {
		t.Errorf("the shipped policy accepts operate: %v", err)
	}
	// The shipped policy ACCEPTS the destructive class, which means "this node
	// is willing to be asked" and nothing more — Execute still requires an
	// operator at this machine's own site to approve the specific job. It is
	// listed so that the nodes already in the fleet can approve a restore with
	// a key they already hold; the alternative was pushing a new policy file to
	// every one of them, which is the enrolment step this design exists to
	// avoid. See TestAcceptingDestructiveIsNotPermissionToRun.
	if err := p.Accepts(ClassDestructive); err != nil {
		t.Errorf("the shipped policy is willing to be asked about destructive work: %v", err)
	}
}

// The file exists to be un-relaxable by anything but root. A file the web user
// could have written is not evidence of anything, so it is refused outright
// rather than trusted or ignored.
func TestGroupWritablePolicyFileRefusesEverything(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"accept":["observe","operate"]}`), 0o664); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	refusal := p.Accepts(ClassObserve)
	if !Refused(refusal) {
		t.Fatal("a group-writable policy file must not be trusted, and must not fall back to a permissive default")
	}
	if !strings.Contains(refusal.Error(), "writable by group") {
		t.Errorf("the refusal must say what is wrong with the file; got %q", refusal)
	}
}

func TestPolicyFileCanNarrow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"accept":["observe"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	// Running as a non-root test user, ownership cannot be asserted here; the
	// mode check above is what this case exercises.
	if os.Geteuid() != 0 {
		if err := p.Accepts(ClassObserve); err != nil && !strings.Contains(err.Error(), "owned by uid") {
			t.Fatalf("unexpected refusal: %v", err)
		}
		return
	}
	if err := p.Accepts(ClassObserve); err != nil {
		t.Errorf("a narrowing policy must still accept what it lists: %v", err)
	}
	if err := p.Accepts(ClassOperate); !Refused(err) {
		t.Error("a policy listing only observe must refuse operate")
	}
}

func TestMalformedPolicyFileRefusesEverything(t *testing.T) {
	for _, body := range []string{`{ not json`, `{"accept":["exec"]}`, `{"accept":["observe"`} {
		path := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		p, err := LoadPolicy(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Accepts(ClassObserve); !Refused(err) {
			t.Errorf("policy body %q must refuse everything, got acceptance", body)
		}
	}
}

func TestDescribeSaysWhatIsAcceptedAndWhy(t *testing.T) {
	got := ShippedPolicy().Describe()
	for _, want := range []string{"observe", "operate",
		"destructive only behind an approval answered on this machine"} {
		if !strings.Contains(got, want) {
			t.Errorf("Describe() = %q, missing %q", got, want)
		}
	}
}
