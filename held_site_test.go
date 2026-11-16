package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"joinery-agent/primitives"
)

func heldFixture(since time.Time, holdErr error, stopped bool, stopErr error) heldSiteProber {
	now := time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC)
	return heldSiteProber{
		locate: func(site string) (movedSiteTarget, error) {
			if site == "gone" {
				return movedSiteTarget{}, errNoVhost
			}
			return movedSiteTarget{site: site, port: 8081, primary: site + ".example.com"}, nil
		},
		holdTime: func(string) (time.Time, error) { return since, holdErr },
		stopped:  func(context.Context, string) (bool, error) { return stopped, stopErr },
		now:      func() time.Time { return now },
	}
}

func TestHeldSiteGate(t *testing.T) {
	now := time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	old := now.Add(-60 * 24 * time.Hour)

	// Held 60 days, stopped: the statement names the date and the gate passes.
	h := heldFixture(old, nil, true, nil)
	st, gate, _, err := h.ceremony(ctx, "st3")
	if err != nil {
		t.Fatalf("an old hold refused: %v", err)
	}
	if st.Primitive != "decommission_held_site" || !strings.Contains(st.Summary, old.Format("2006-01-02")) {
		t.Fatalf("statement: %+v", st)
	}
	if err := gate.Require(ctx, 1, st); err != nil {
		t.Fatalf("gate refused an old hold: %v", err)
	}

	cases := []struct {
		name string
		h    heldSiteProber
		want string
	}{
		{"not held", heldFixture(time.Time{}, os.ErrNotExist, true, nil), "does not hold"},
		{"held 30 days", heldFixture(now.Add(-30*24*time.Hour), nil, true, nil), "for 30 days"},
		{"held 54 days", heldFixture(now.Add(-54*24*time.Hour), nil, true, nil), "only after 55"},
		{"dated ahead", heldFixture(now.Add(time.Hour), nil, true, nil), "future"},
		{"running", heldFixture(old, nil, false, nil), "is running"},
		{"engine unreadable", heldFixture(old, nil, false, errors.New("no engine")), "Could not tell"},
		{"hold unreadable", heldFixture(time.Time{}, errors.New("permission denied"), true, nil), "could not be read"},
	}
	for _, c := range cases {
		_, _, _, err := c.h.ceremony(ctx, "st3")
		var r *primitives.RefusalError
		if !errors.As(err, &r) || !strings.Contains(r.Reason, c.want) || !strings.Contains(r.Reason, "Nothing was removed") {
			t.Errorf("%s: want a refusal naming %q, got %v", c.name, c.want, err)
		}
	}

	// No vhost: no such site here.
	if _, _, _, err := h.ceremony(ctx, "gone"); err == nil {
		t.Fatal("a site with no vhost was not refused")
	}

	// The gate checks again: a hold lifted after the statement refuses.
	h2 := heldFixture(old, nil, true, nil)
	st, gate, _, _ = h2.ceremony(ctx, "st3")
	gate.(*heldSiteGate).prober.stopped = func(context.Context, string) (bool, error) { return false, nil }
	if err := gate.Require(ctx, 2, st); err == nil {
		t.Fatal("the gate passed a container started after the statement")
	}

	// Not a host: no proof at all.
	if heldSiteProofFor(&Config{Siteless: false}) != nil {
		t.Fatal("a machine with a site of its own got the held-site proof")
	}
}
