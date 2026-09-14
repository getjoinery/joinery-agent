package recipes

import (
	"fmt"
	"os"
	"path/filepath"
)

// HoldDir is where an operator tells a recipe to stand down: a file named
// after the recipe under it (touch /etc/joinery-agent/hold/fail2ban) stops
// that recipe's repair while the operator works on that aspect of the host.
// The check still runs and the recipe says it is held on every failing tick,
// so the operator who set it sees it working and one who did not learns it
// exists the first time they need it (specs/agent_tier1_recipes.md, "Where the
// bugs will live": a recipe fighting an operator).
//
// A package var so tests point it at a temp directory; nothing at runtime
// writes to it.
var HoldDir = "/etc/joinery-agent/hold"

// holdState reports whether recipe is held. A marker counts only when its
// directory is trusted — owned by this process's user (root, in production)
// and writable by nobody else. A marker in a directory anyone else could write
// is ignored, and the second value says why, so the ledger can say it. A
// marker only ever narrows the agent, but an ignored one is a stated refusal,
// not an accident.
func holdState(recipe string) (held bool, ignored string) {
	marker := filepath.Join(HoldDir, recipe)
	if _, err := os.Stat(marker); err != nil {
		return false, ""
	}
	if err := trustedDir(HoldDir); err != nil {
		return false, fmt.Sprintf("hold marker %s ignored: its directory is %v", marker, err)
	}
	return true, ""
}

// HoldPath is where an operator would put the marker for recipe, for log
// lines that tell them so.
func HoldPath(recipe string) string {
	return filepath.Join(HoldDir, recipe)
}
