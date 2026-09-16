package recipes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A host-scoped recipe inside a container: never checked, said once in the
// journal and once in the ledger, and reported as not-applicable on the
// claim. The eight container agents on a Docker host used to write "unknown"
// every ten minutes each.
func TestAHostScopedRecipeDoesNotTickInAContainer(t *testing.T) {
	h := newHarness(t)
	h.recipe.Scope = ScopeHost
	checks := 0
	h.recipe.Check = func(context.Context, *Env) Verdict { checks++; return Verdict{Fail, "would fail"} }
	var lines []string
	h.loop = NewLoop([]Recipe{h.recipe}, nil, Options{
		Now:         func() time.Time { return h.now },
		Lock:        &h.lock,
		MarkRunning: func(string) func() { return func() {} },
		Logf:        func(f string, a ...interface{}) { lines = append(lines, fmt.Sprintf(f, a...)) },
		InContainer: func() bool { return true },
	})
	h.loop.noteInapplicable()
	for i := 0; i < 6; i++ {
		h.loop.Tick(context.Background())
		h.now = h.now.Add(TickInterval)
	}
	if checks != 0 {
		t.Fatalf("the check ran %d time(s) inside a container; it must not run at all", checks)
	}
	if h.repairs != 0 {
		t.Fatalf("a repair ran inside a container")
	}
	said := 0
	for _, l := range lines {
		if strings.Contains(l, "not applicable in a container") {
			said++
		}
	}
	if said != 1 {
		t.Fatalf("the journal should say once that the recipe is not applicable here; said %d time(s): %v", said, lines)
	}
	raw, err := os.ReadFile(filepath.Join(LedgerDir, "probe.jsonl"))
	if err != nil {
		t.Fatalf("the ledger should carry the one line: %v", err)
	}
	ledgerLines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(ledgerLines) != 1 || !strings.Contains(ledgerLines[0], `"event":"`+EventNotApplicable+`"`) {
		t.Fatalf("the ledger should carry exactly one not_applicable line, got %d: %s", len(ledgerLines), raw)
	}
}

// Outside a container the same recipe ticks as before.
func TestAHostScopedRecipeTicksOnAHost(t *testing.T) {
	h := newHarness(t)
	h.recipe.Scope = ScopeHost
	checks := 0
	h.recipe.Check = func(context.Context, *Env) Verdict { checks++; return Verdict{Pass, "fine"} }
	h.loop = NewLoop([]Recipe{h.recipe}, nil, Options{
		Now:         func() time.Time { return h.now },
		Lock:        &h.lock,
		MarkRunning: func(string) func() { return func() {} },
		Logf:        func(string, ...interface{}) {},
		InContainer: func() bool { return false },
	})
	h.loop.noteInapplicable()
	h.loop.Tick(context.Background())
	if checks != 1 {
		t.Fatalf("on a host the check should run once per tick, ran %d", checks)
	}
}

// The claim's list says not-applicable for a host-scoped recipe in a
// container and the compiled mode everywhere else; fail2ban is host-scoped.
func TestTheReportSaysNotApplicableInAContainer(t *testing.T) {
	r, ok := Lookup("fail2ban")
	if !ok {
		t.Fatal("fail2ban should be registered")
	}
	if r.Scope != ScopeHost {
		t.Fatalf("fail2ban's subject is the host; scope is %q", r.Scope)
	}
	restore := InContainer
	t.Cleanup(func() { InContainer = restore })
	InContainer = func() bool { return true }
	if got := ModeOf(r); got != ModeNotApplicable {
		t.Fatalf("in a container fail2ban's mode should be %q, got %q", ModeNotApplicable, got)
	}
	if !strings.Contains(","+Report()+",", ",fail2ban:"+ModeNotApplicable+",") {
		t.Fatalf("the claim should carry fail2ban:%s in a container, got %q", ModeNotApplicable, Report())
	}
	InContainer = func() bool { return false }
	if got := ModeOf(r); got != Mode() {
		t.Fatalf("on a host fail2ban's mode should be the compiled %q, got %q", Mode(), got)
	}
	// The wire format: the plane's pattern for a mode is letters and dashes.
	for _, c := range ModeNotApplicable {
		if !(c >= 'a' && c <= 'z') && c != '-' {
			t.Fatalf("mode %q carries %q, outside the wire format", ModeNotApplicable, c)
		}
	}
}

// A site-scoped recipe on a machine with no site: never checked, said once,
// reported as not-applicable — the support bundle carries no install_agent.sh,
// so there is nothing the recipe could run.
func TestASiteScopedRecipeDoesNotTickWithoutASite(t *testing.T) {
	ResetVerdictsForTests()
	defer ResetVerdictsForTests()
	h := newHarness(t)
	h.recipe.Scope = ScopeSite
	checks := 0
	h.recipe.Check = func(context.Context, *Env) Verdict { checks++; return Verdict{Fail, "would fail"} }
	var lines []string
	h.loop = NewLoop([]Recipe{h.recipe}, nil, Options{
		Now:     func() time.Time { return h.now },
		Lock:    &h.lock,
		Logf:    func(f string, a ...interface{}) { lines = append(lines, fmt.Sprintf(f, a...)) },
		HasSite: func() bool { return false },
	})
	h.loop.noteInapplicable()
	for i := 0; i < 3; i++ {
		h.loop.Tick(context.Background())
		h.now = h.now.Add(TickInterval)
	}
	if checks != 0 || h.repairs != 0 {
		t.Fatalf("a site-scoped recipe ran on a siteless machine (%d checks, %d repairs)", checks, h.repairs)
	}
	said := 0
	for _, l := range lines {
		if strings.Contains(l, "not applicable on a machine with no site") {
			said++
		}
	}
	if said != 1 {
		t.Fatalf("the journal should say once why; said %d time(s): %v", said, lines)
	}
	raw, _ := os.ReadFile(filepath.Join(LedgerDir, "probe.jsonl"))
	if !strings.Contains(string(raw), `"event":"`+EventNotApplicable+`"`) || !strings.Contains(string(raw), "no site tree") {
		t.Fatalf("the ledger should carry one not_applicable line naming the reason, got %s", raw)
	}
	// And the claim: the registered site-scoped recipe reads not-applicable
	// with no verdict, and ticks normally where there is a site.
	restore := HasSite
	HasSite = func() bool { return false }
	if !strings.Contains(","+Report()+",", ",agent_supervision:"+ModeNotApplicable+",") {
		t.Errorf("the claim should carry agent_supervision:%s on a siteless machine, got %q", ModeNotApplicable, Report())
	}
	HasSite = func() bool { return true }
	if strings.Contains(Report(), "agent_supervision:"+ModeNotApplicable) {
		t.Errorf("with a site the recipe applies, got %q", Report())
	}
	HasSite = restore
}
