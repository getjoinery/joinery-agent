package recipes

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"joinery-agent/primitives"
)

// Recipe disk_headroom: the node warns itself when its disk is nearly full
// (specs/disk_headroom_and_unit_diagnosis.md § 10).
//
// A CHECK-ONLY recipe (NoRepair). The check is host_report (observe, no
// parameters): the site filesystem's available and total bytes. There is no
// repair, because there is no safe automatic answer to a full disk — deleting
// things unattended is worse than the disease. On the first failing check the
// loop opens a case; the case closes itself when the check passes, as every
// case does. A node with no management node still gets the warning: the case
// renders on its own admin, which is the whole reason this lives on the node.
//
// The rule, compiled and deliberately simple:
//
//   - FAIL when available bytes are under 10% of the filesystem's size, or
//     under 5 GiB, whichever is met first.
//   - PASS otherwise.
//   - UNKNOWN when either figure is unknown or the report is unreadable (an
//     agent whose host_report.sh predates avail_bytes, a machine df cannot
//     answer for). Unknown opens nothing.
//
// No slope, no history: the node holds no series and this is not the place to
// build one. That asymmetry with anything the plane might compute is on
// purpose; nobody should "fix" it by adding a trend here.
//
// Available bytes, not total minus used: the difference is the root-reserved
// blocks, which an ordinary writer cannot use — 2.4 GiB on the node whose
// weekly full filled its disk on 2026-09-22.
//
// See the package header for the hostile-caller review; this recipe adds no
// surface to it. Its one word is reviewed in observe_host_report.go, and it
// runs nothing that changes the machine.
func init() {
	Register(Recipe{
		Name:        "disk_headroom",
		Description: "The site filesystem has at least 10% and at least 5 GiB available; otherwise open a case (no repair).",
		// Hourly, not every tick: host_report scans a day of the system journal
		// on each run, and a hard floor on free space does not change in ten
		// minutes. Under the floor the case is already open and updates hourly.
		MinInterval: time.Hour,
		CheckWord:   "host_report",
		NoRepair:    true,
		Check: func(ctx context.Context, env *Env) Verdict {
			result, err := env.Run(ctx, "host_report")
			return diskHeadroomVerdict(result, err)
		},
	})
}

const (
	// diskHeadroomFloorBytes: under this much available is a failing disk,
	// whatever its size.
	diskHeadroomFloorBytes = 5 * 1024 * 1024 * 1024
	// diskHeadroomFloorPercent: under this share of the filesystem available
	// is a failing disk, however large the disk.
	diskHeadroomFloorPercent = 10
)

// diskHeadroomVerdict reads a host_report result into a verdict.
func diskHeadroomVerdict(result map[string]interface{}, err error) Verdict {
	if err != nil {
		if primitives.Refused(err) {
			return Verdict{Unknown, "host_report refused: " + err.Error()}
		}
		return Verdict{Unknown, "host_report failed: " + err.Error()}
	}
	output, _ := result["output"].(string)
	var report struct {
		Disk struct {
			Avail json.RawMessage `json:"avail_bytes"`
			Total json.RawMessage `json:"total_bytes"`
		} `json:"disk"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &report); err != nil {
		return Verdict{Unknown, "host_report output is not the JSON object it should be"}
	}
	avail, okA := byteCount(report.Disk.Avail)
	total, okT := byteCount(report.Disk.Total)
	if !okA || !okT || total == 0 {
		return Verdict{Unknown, "the disk's available or total bytes are unknown"}
	}
	pct := float64(avail) * 100 / float64(total)
	figures := fmt.Sprintf("%s available of %s (%.1f%%)", humanBytes(avail), humanBytes(total), pct)
	if avail < diskHeadroomFloorBytes || pct < diskHeadroomFloorPercent {
		return Verdict{Fail, "the disk is nearly full: " + figures}
	}
	return Verdict{Pass, figures}
}

// byteCount reads a JSON non-negative integer; the string "unknown", a
// negative, a fraction or anything else is not a count.
func byteCount(raw json.RawMessage) (uint64, bool) {
	var n uint64
	if len(raw) == 0 || json.Unmarshal(raw, &n) != nil {
		return 0, false
	}
	return n, true
}

// humanBytes is a byte count as a short readable figure, in binary units.
func humanBytes(n uint64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	v := float64(n)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}
