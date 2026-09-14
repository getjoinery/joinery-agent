package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"joinery-agent/primitives"
	"joinery-agent/recipes"
)

// The plane must never GUESS a node's vocabulary. It did once, from a version
// number, and the first apply_update rollout dispatched the new primitive to
// nine agents whose compiled-in vocabulary predated it: all nine refused. The
// poll is the one moment the machine speaks for itself about what it is, so it
// is where the fact belongs — beside the version, for the same reason.

func TestClaimReportsThisAgentsVocabulary(t *testing.T) {
	var claimed map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		json.NewDecoder(req.Body).Decode(&claimed)
		w.Write([]byte(`{"api_version":"1.0","data":{"job":null}}`))
	}))
	defer server.Close()

	src := testSource(t, testIdentity(t, server.URL, 7))
	if _, err := src.claim(context.Background()); err != nil {
		t.Fatal(err)
	}

	reported, _ := claimed["primitives"].(string)
	if reported == "" {
		t.Fatal("a claim must report the vocabulary this binary was compiled with")
	}
	names := strings.Split(reported, ",")
	compiled := primitives.Names()
	if len(names) != len(compiled) {
		t.Fatalf("reported %d primitives, this binary compiles in %d", len(names), len(compiled))
	}
	for i, name := range compiled {
		if names[i] != name {
			t.Fatalf("reported vocabulary diverges at %d: %q vs %q", i, names[i], name)
		}
	}
	// Every name must survive the plane's own field pattern, or the claim is
	// refused wholesale and the node goes dark over a formatting detail.
	for _, name := range names {
		for _, r := range name {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '_' {
				t.Errorf("primitive name %q carries a character the wire format does not allow", name)
			}
		}
	}
}

// The recipe list rides beside the vocabulary, with its mode: the plane must
// never guess which recipes a node runs, and a person on the node page must
// be able to see that a node is report-only.
func TestClaimReportsThisAgentsRecipesWithTheirMode(t *testing.T) {
	var claimed map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		json.NewDecoder(req.Body).Decode(&claimed)
		w.Write([]byte(`{"api_version":"1.0","data":{"job":null}}`))
	}))
	defer server.Close()

	src := testSource(t, testIdentity(t, server.URL, 7))
	if _, err := src.claim(context.Background()); err != nil {
		t.Fatal(err)
	}
	reported, _ := claimed["recipes"].(string)
	if reported != recipes.Report() {
		t.Fatalf("a claim must report the recipes this binary compiles in; got %q, want %q", reported, recipes.Report())
	}
	for _, name := range recipes.Names() {
		if !strings.Contains(","+reported+",", ","+name+":"+recipes.Mode()+",") {
			t.Errorf("recipe %s should be reported with its mode %s, got %q", name, recipes.Mode(), reported)
		}
	}
}

// The other half of the same fact: what this machine's script tree is, so the
// plane can see whether the support bundle actually landed. Empty is the honest
// answer on a machine that has a site and needs no bundle.
func TestClaimReportsTheBundleVersion(t *testing.T) {
	var claimed map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		json.NewDecoder(req.Body).Decode(&claimed)
		w.Write([]byte(`{"api_version":"1.0","data":{"job":null}}`))
	}))
	defer server.Close()

	t.Setenv("AGENT_TOOL_ROOT", t.TempDir()+"/tree")
	src := testSource(t, testIdentity(t, server.URL, 7))
	if _, err := src.claim(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, present := claimed["bundle_version"]; !present {
		t.Fatal("a claim must say what bundle this machine holds, even when the answer is none")
	}
	if claimed["bundle_version"] != "" {
		t.Errorf("a machine with no bundle reported %q", claimed["bundle_version"])
	}
}

// A newer agent against an older plane. The plane validates a claim strictly —
// an undeclared field is refused, not ignored — which is the right rule and
// makes a new field fatal in the wrong direction. Losing the capability report
// costs the plane a fact; losing the claim costs it the node.
func TestAnOlderPlaneStillGetsClaimsFromANewerAgent(t *testing.T) {
	var bodies []map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(req.Body).Decode(&body)
		bodies = append(bodies, body)

		if _, sent := body["primitives"]; sent {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"api_version":"1.0","error":"The request carries an undeclared field: primitives"}`))
			return
		}
		w.Write([]byte(`{"api_version":"1.0","data":{"job":null}}`))
	}))
	defer server.Close()

	src := testSource(t, testIdentity(t, server.URL, 7))

	// First poll: refused for the new field, and reported as nothing to do
	// rather than as an error — the agent has already decided what to change.
	job, err := src.claim(context.Background())
	if err != nil || job != nil {
		t.Fatalf("the first claim should absorb the refusal; got job=%v err=%v", job, err)
	}
	if !src.extrasDropped {
		t.Fatal("an undeclared-field refusal must latch, or every poll repeats it forever")
	}

	// Second poll: the older shape, and it works.
	if _, err := src.claim(context.Background()); err != nil {
		t.Fatalf("the second claim should succeed against the older plane: %v", err)
	}
	if len(bodies) != 2 {
		t.Fatalf("expected two claims, got %d", len(bodies))
	}
	if _, sent := bodies[1]["primitives"]; sent {
		t.Error("the second claim still carried the field the plane refused")
	}
	if _, sent := bodies[1]["recipes"]; sent {
		t.Error("the recipe list is one of the extras, and goes with them")
	}
	if _, sent := bodies[1]["cases"]; sent {
		t.Error("the cases are one of the extras, and go with them")
	}
	if bodies[1]["agent_version"] == nil {
		t.Error("dropping the extras must not drop the version the plane has always accepted")
	}
}

// A refusal that is NOT about an undeclared field must stay an error. Absorbing
// every 400 would turn a broken pairing into a node that silently reports
// nothing wrong.
func TestAnUnrelatedRefusalIsStillAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"api_version":"1.0","error":"That request did not verify against this node's agent key."}`))
	}))
	defer server.Close()

	src := testSource(t, testIdentity(t, server.URL, 7))
	if _, err := src.claim(context.Background()); err == nil {
		t.Fatal("an authentication failure must be reported, not absorbed")
	}
	if src.extrasDropped {
		t.Error("an unrelated refusal must not be read as an older plane")
	}
}

// A case rides the claim beside the recipe list, in the same extras block,
// and the body rides until a claim carrying it has succeeded: the plane is
// told, the plane never answers (specs/agent_tier1_recipes.md, "The case").
func TestClaimCarriesTheCasesAndTheBodyUntilOneSucceeds(t *testing.T) {
	root := t.TempDir()
	restoreLedger, restoreHold, restoreOut := recipes.LedgerDir, recipes.HoldDir, recipes.OutwardDir
	recipes.LedgerDir = filepath.Join(root, "ledger")
	recipes.HoldDir = filepath.Join(root, "hold")
	recipes.OutwardDir = filepath.Join(root, "cache", "recipes")
	recipes.ResetCasesForTests()
	t.Cleanup(func() {
		recipes.LedgerDir, recipes.HoldDir, recipes.OutwardDir = restoreLedger, restoreHold, restoreOut
		recipes.ResetCasesForTests()
	})

	// A recipe that always fails, driven to its escalation on a fake clock.
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	probe := recipes.Recipe{
		Name: "probe", MinInterval: recipes.TickInterval, CheckWord: "host_report", RepairWord: "host_converge",
		Check: func(context.Context, *recipes.Env) recipes.Verdict {
			return recipes.Verdict{Kind: recipes.Fail, Reason: "down"}
		},
		Repair: func(context.Context, *recipes.Env) (string, error) { return "", nil },
	}
	loop := recipes.NewLoop([]recipes.Recipe{probe}, nil, recipes.Options{
		Now:  func() time.Time { return now },
		Logf: func(string, ...interface{}) {},
	})
	for i := 0; i < 7; i++ {
		now = now.Add(recipes.TickInterval)
		loop.Tick(context.Background())
	}
	if len(recipes.OpenCases()) != 1 {
		t.Fatalf("setup: expected one open case, got %v", recipes.OpenCases())
	}

	var bodies []map[string]interface{}
	refuse := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(req.Body).Decode(&body)
		bodies = append(bodies, body)
		if refuse {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"api_version":"1.0","error":"down for a moment"}`))
			return
		}
		w.Write([]byte(`{"api_version":"1.0","data":{"job":null}}`))
	}))
	defer server.Close()
	src := testSource(t, testIdentity(t, server.URL, 7))

	caseIn := func(body map[string]interface{}) map[string]interface{} {
		cases, _ := body["cases"].(map[string]interface{})
		c, _ := cases["recipe:probe"].(map[string]interface{})
		return c
	}

	// A claim the plane refused for its own reasons: the body rides again.
	refuse = true
	if _, err := src.claim(context.Background()); err == nil {
		t.Fatal("setup: the refused claim should be an error")
	}
	if c := caseIn(bodies[0]); c == nil || c["body"] == nil || c["status"] != "open" {
		t.Fatalf("the first claim carries the open case with its body: %v", bodies[0]["cases"])
	}
	refuse = false
	if _, err := src.claim(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := caseIn(bodies[1]); c == nil || c["body"] == nil {
		t.Fatal("a claim that failed did not deliver the body, so the next one carries it again")
	}
	if _, err := src.claim(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := caseIn(bodies[2])
	if c == nil || c["status"] != "open" {
		t.Fatalf("the summary rides every claim: %v", bodies[2]["cases"])
	}
	if c["body"] != nil {
		t.Error("once a claim carrying the body succeeded, the summary rides alone")
	}
	if bodies[2]["recipes"] == nil || bodies[2]["primitives"] == nil {
		t.Error("the cases ride beside the recipe list and the vocabulary, not instead of them")
	}
}
