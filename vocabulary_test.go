package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"joinery-agent/primitives"
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
