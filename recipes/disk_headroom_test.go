package recipes

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// disk_headroom is the node's own floor rule (specs/disk_headroom_and_unit_diagnosis.md
// § 10): check-only, a case on the first failing check, closed by the check
// passing. The verdict is tested against host_report objects of the shape the
// script prints; the loop half with a fake check, as loop_test does.

const gib = 1024 * 1024 * 1024

func hostReportWithDisk(avail, total interface{}) map[string]interface{} {
	raw, _ := json.Marshal(map[string]interface{}{
		"disk": map[string]interface{}{"used_bytes": 1, "total_bytes": total, "avail_bytes": avail},
	})
	return map[string]interface{}{"output": string(raw) + "\n"}
}

func TestDiskHeadroomFloorVerdicts(t *testing.T) {
	cases := []struct {
		label        string
		avail, total interface{}
		want         Kind
	}{
		{"plenty on a large disk", uint64(20 * gib), uint64(50 * gib), Pass},
		// The node of 2026-09-22 on the morning it filled: 12.17 GiB free
		// of 48.6 — above both floors. The floor alone would not have
		// caught that morning; it is the floor, and the spec says so.
		{"the incident node that morning", uint64(13067400000), uint64(52183700000), Pass},
		{"under 5 GiB on a large disk", uint64(4 * gib), uint64(500 * gib), Fail},
		{"under 10% on a large disk", uint64(40 * gib), uint64(500 * gib), Fail},
		{"exactly 10% and over 5 GiB", uint64(50 * gib), uint64(500 * gib), Pass},
		{"a small disk that is only 10% free", uint64(1 * gib), uint64(10 * gib), Fail},
		{"a full disk", uint64(0), uint64(48 * gib), Fail},
		{"available unknown", "unknown", uint64(48 * gib), Unknown},
		{"total unknown", uint64(1 * gib), "unknown", Unknown},
		{"a zero-size filesystem", uint64(0), uint64(0), Unknown},
		{"a negative figure", -5, uint64(48 * gib), Unknown},
		{"a fraction", 1.5, uint64(48 * gib), Unknown},
	}
	for _, c := range cases {
		v := diskHeadroomVerdict(hostReportWithDisk(c.avail, c.total), nil)
		if v.Kind != c.want {
			t.Errorf("%s: got %s (%s), want %s", c.label, v.Kind, v.Reason, c.want)
		}
		if v.Kind == Fail && !strings.Contains(v.Reason, "available of") {
			t.Errorf("%s: a failing verdict names the figures, got %q", c.label, v.Reason)
		}
	}
}

func TestDiskHeadroomUnknownNeverFails(t *testing.T) {
	if v := diskHeadroomVerdict(nil, errors.New("boom")); v.Kind != Unknown {
		t.Errorf("a word that failed is unknown, got %s", v.Kind)
	}
	if v := diskHeadroomVerdict(map[string]interface{}{"output": "not json"}, nil); v.Kind != Unknown {
		t.Errorf("an unreadable report is unknown, got %s", v.Kind)
	}
	// An older host_report.sh, before avail_bytes: the recipe does not fall
	// back to total minus used, which counts the root reserve as free.
	raw, _ := json.Marshal(map[string]interface{}{"disk": map[string]interface{}{"used_bytes": 1, "total_bytes": 48 * gib}})
	if v := diskHeadroomVerdict(map[string]interface{}{"output": string(raw)}, nil); v.Kind != Unknown {
		t.Errorf("a report without avail_bytes is unknown, got %s", v.Kind)
	}
}

func TestDiskHeadroomIsRegisteredCheckOnly(t *testing.T) {
	r, ok := Lookup("disk_headroom")
	if !ok {
		t.Fatal("disk_headroom should be registered")
	}
	if !r.NoRepair || r.RepairWord != "" || r.Repair != nil {
		t.Errorf("disk_headroom is check-only: NoRepair=%v RepairWord=%q Repair set=%v", r.NoRepair, r.RepairWord, r.Repair != nil)
	}
	if r.CheckWord != "host_report" {
		t.Errorf("disk_headroom checks with host_report, got %q", r.CheckWord)
	}
}

// The loop half: a check-only recipe opens its case on the FIRST failing
// check, never attempts anything, notes rather than reopens while it stays
// failed, and closes when the check passes.
func TestACheckOnlyRecipeOpensACaseOnTheFirstFailAndClosesOnAPass(t *testing.T) {
	h := newHarness(t)
	h.recipe.RepairWord = ""
	h.recipe.Repair = nil
	h.recipe.NoRepair = true
	h.restart()

	h.verdict = Verdict{Unknown, "no figures"}
	h.ticks(3)
	if cases, _ := claimed(t); cases != nil || h.count(EventEscalation) != 0 {
		t.Fatal("unknown opens nothing")
	}

	h.verdict = Verdict{Fail, "the disk is nearly full"}
	h.tick()
	if h.count(EventEscalation) != 1 {
		t.Fatalf("the first failing check is the case; escalations: %d", h.count(EventEscalation))
	}
	cases, ack := claimed(t)
	c, ok := cases["recipe:probe"]
	if !ok || c.Status != CaseOpen || c.Body == nil || !strings.Contains(c.Reason, "no repair") {
		t.Fatalf("an open case with a body, saying there is no repair: %+v", c)
	}
	ack()
	if n := h.count(EventAttempt); n != 0 {
		t.Errorf("a check-only recipe never attempts anything; %d attempts ledgered", n)
	}
	if len(h.marks) != 0 {
		t.Error("nothing ran, so no job marker was written")
	}

	h.ticks(5)
	if h.count(EventEscalation) != 1 {
		t.Errorf("still failing is a note on the one case, not another case; escalations: %d", h.count(EventEscalation))
	}
	if n := h.count(EventAttempt); n != 0 {
		t.Errorf("still no attempts after five more failing ticks; got %d", n)
	}

	h.verdict = Verdict{Pass, "room again"}
	h.tick()
	cases, _ = claimed(t)
	if c := cases["recipe:probe"]; c.Status != CaseClosed {
		t.Fatalf("the check passing closes the case: %+v", c)
	}
}

// The hold marker still narrows a check-only recipe: held, no case opens.
func TestACheckOnlyRecipeRespectsTheHold(t *testing.T) {
	h := newHarness(t)
	h.recipe.RepairWord = ""
	h.recipe.Repair = nil
	h.recipe.NoRepair = true
	h.restart()
	if err := os.MkdirAll(HoldDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(HoldDir, "probe"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	h.verdict = Verdict{Fail, "the disk is nearly full"}
	h.ticks(3)
	if h.count(EventEscalation) != 0 {
		t.Error("a held check-only recipe opens no case")
	}
	if h.count(EventHeld) == 0 {
		t.Error("and says it is held")
	}
}
