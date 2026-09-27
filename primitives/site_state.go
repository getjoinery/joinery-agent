package primitives

// The quiet state, from the agent's side (specs/site_copy.md WP5).
//
// A site is quiet while /etc/joinery/sites/{site}/state exists: `quiet copy`
// on a dormant copy, set only by the installer, or `quiet switchover` on a
// source being switched over, set only by site_quiet on. The machine enforces
// what quiet means (_site_state.sh: no outgoing traffic from the web user, no
// cron, no installers, a 503 at the web server). The agent's part is the
// vocabulary: while the site is quiet it runs every observe word, and of the
// rest only a word that declares the reason it serves.
//
// Deny by default, on the word. A new operate or destructive word runs on a
// quiet site only when its author has said under which reason it belongs; a
// word nobody thought about is refused, which is the right answer for a
// machine that is either a copy that must not act or a source that must not
// change after its final backup.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// QuietUse says under which quiet reasons a word still runs. Zero: under
// neither, the default. Observe words run under both without saying so.
type QuietUse int

const (
	// QuietSwitchover: runs on a frozen source (its final backup run).
	QuietSwitchover QuietUse = 1 << iota
	// QuietCopy: runs on a dormant copy (its restore, taking the node id).
	QuietCopy
	// QuietAny: runs under either reason (site_quiet itself).
	QuietAny = QuietSwitchover | QuietCopy
)

// SiteStateDir holds each site's state directory. A variable only so a test
// can point it at a fixture; nothing in production sets it.
var SiteStateDir = "/etc/joinery/sites"

// SiteState is what the state directory says about one site.
type SiteState struct {
	// Reason is "copy" or "switchover"; empty for a live site.
	Reason string
	// CopyOf is the node id of the site this machine is a copy of, from the
	// dormant install; zero when unknown or not a copy.
	CopyOf int64
}

// ReadSiteState reads this machine's site's state. A machine with no site has
// none. A state file that says anything else reads as switchover, the stricter
// reason, unless a copy_of record is beside it, which always means a copy; the
// machine reads it the same way (_site_state.sh).
func ReadSiteState(env *ExecEnv) (SiteState, error) {
	var st SiteState
	if env == nil || env.SiteRoot == "" {
		return st, nil
	}
	dir := filepath.Join(SiteStateDir, filepath.Base(env.SiteRoot))
	raw, err := os.ReadFile(filepath.Join(dir, "state"))
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		// Unreadable is not live. A root agent that cannot read a root file
		// is a machine in a state nobody should act on.
		return SiteState{Reason: "switchover"}, fmt.Errorf("cannot read this site's state: %w", err)
	}
	switch strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0]) {
	case "quiet copy":
		st.Reason = "copy"
	default:
		st.Reason = "switchover"
	}
	// A copy_of record makes this a copy whatever the state line says: a
	// damaged line must never turn a copy into something a bare off clears.
	if b, err := os.ReadFile(filepath.Join(dir, "copy_of")); err == nil {
		st.Reason = "copy"
		if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && n > 0 {
			st.CopyOf = n
		}
	}
	return st, nil
}

// quietAllows is the dispatcher's question: may this word run on this site
// now? nil when the site is live, when the word only reads, or when the word
// declares the reason the site is quiet for.
func quietAllows(env *ExecEnv, p Primitive) error {
	if p.Class == ClassObserve {
		return nil
	}
	st, err := ReadSiteState(env)
	if st.Reason == "" {
		return nil
	}
	want := QuietSwitchover
	if st.Reason == "copy" {
		want = QuietCopy
	}
	if p.Quiet&want != 0 && err == nil {
		return nil
	}
	if err != nil {
		return refusedf("%s refused: %v", p.Name, err)
	}
	if st.Reason == "copy" {
		return refusedf("%s refused: this site is a dormant copy (quiet copy), and a copy runs only read-only words "+
			"and the copy words until it takes over its source's node", p.Name)
	}
	return refusedf("%s refused: this site is frozen for a switch-over (quiet switchover), and runs only read-only words "+
		"and the switch-over words until site_quiet off", p.Name)
}
