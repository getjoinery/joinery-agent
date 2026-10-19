package primitives

// site_quiet {action: on|off|forward, to}: freeze this site for a switch-over,
// or let it run again (specs/site_copy.md WP5). The machine does the freezing
// (maintenance_scripts/sysadmin_tools/site_quiet.sh, over _site_state.sh);
// this word chooses the one flag the script needs and nothing else.
//
//   - forward, on a site already frozen, has it forward every visitor to its
//     copy at `to` while its address moves by DNS
//     (specs/site_copy_anything_to_anything.md D1), instead of showing the
//     maintenance page. on stops forwarding.
//
//   - on sets `quiet switchover` and waits until the web user runs no
//     command-line PHP. It never sets `quiet copy`: only the installer does.
//   - off clears either reason, and a copy only once this machine holds the
//     node id of the site it is a copy of (the dormant install recorded it).
//     That is the whole of what stops a copy going live beside its source, so
//     the check is here, where the node id lives, and the script is told the
//     answer with --copy-promoted.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word? Take
// a live site down: on turns every page into a maintenance page and stops its
// scheduled tasks until off. That is an outage, visible at once to the owner,
// and nothing is lost: the state file, the held cron file and every setting
// quiet changed are put back by off. An operator with this word can already
// do as much with restart_unit apache2 in a loop. Accepted.
//
// With forward it can send a frozen site's visitors to another address: the
// one address the management node named, and nothing else. The machine
// forwards over https, checking that address's certificate against the
// site's own name, but it also forwards the ACME challenge path there over
// http, so whoever answers at that address can be issued the site's
// certificate through the forward: the check is no stronger than the
// address. That is no new power, since a management node that names an
// address can already point the site's DNS at it. `to` must be a public
// unicast address, so nothing on the machine's own networks, nor in shared
// address space (a tailnet), is reached. Accepted.
//
// What it cannot do:
//
//   - Make a copy go live. off over `quiet copy` refuses unless this machine's
//     own identity says it has taken its source's node id, which only the
//     node-id word does.
//   - Name anything. One enum, two values; argv is composed here.

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"time"
)

const siteQuietScript = "maintenance_scripts/sysadmin_tools/site_quiet.sh"

func init() {
	Register(Primitive{
		Name:        "site_quiet",
		Class:       ClassOperate,
		Description: "Freeze this site for a switch-over (on: every page a maintenance page, nothing sent, no scheduled task, no installer) or let it run again (off).",
		Params: []ParamSpec{
			{Name: "action", Type: ParamEnum, Required: true, Values: []string{"on", "off", "forward"}},
			{Name: "to", Type: ParamString, MaxLen: 39, Pattern: forwardAddressPattern},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  siteQuietScript,
			ArgsFrom:    siteQuietArgv,
		},
		// Up to ten minutes for the host runner lock, then up to five for the
		// web user's command-line PHP to finish.
		Timeout: 16 * time.Minute,
		Quiet:   QuietAny,
	})
}

func siteQuietArgv(_ context.Context, env *ExecEnv, p Params) ([]string, error) {
	if env == nil || env.SiteRoot == "" {
		return nil, refusedf("site_quiet: this machine has no site to quiet")
	}
	if p.String("action") == "forward" {
		to, err := forwardAddress(p.String("to"))
		if err != nil {
			return nil, refusedf("site_quiet: %v", err)
		}
		return []string{"forward", to}, nil
	}
	if p.String("to") != "" {
		return nil, refusedf("site_quiet: only forward takes an address")
	}
	if p.String("action") == "on" {
		return []string{"on"}, nil
	}
	st, err := ReadSiteState(env)
	if err != nil {
		return nil, refusedf("site_quiet: %v", err)
	}
	if st.Reason != "copy" {
		return []string{"off"}, nil
	}
	if st.CopyOf == 0 {
		return nil, refusedf("site_quiet: this site is a dormant copy with no record of its source's node id, so nothing can say it has taken it; it stays quiet")
	}
	if env.NodeID == nil {
		return nil, refusedf("site_quiet: this agent cannot read its own node id; a copy stays quiet")
	}
	id, err := env.NodeID()
	if err != nil {
		return nil, refusedf("site_quiet: cannot read this machine's node id (%v); a copy stays quiet", err)
	}
	if id != st.CopyOf {
		return nil, refusedf("site_quiet: this site is a dormant copy of node %d and this machine is still node %d; "+
			"it clears only once it has taken its source's node id", st.CopyOf, id)
	}
	return []string{"off", "--copy-promoted"}, nil
}

// forwardAddressPattern bounds the characters of an address before it is parsed.
var forwardAddressPattern = regexp.MustCompile(`^[0-9a-fA-F:.]{2,39}$`)

// notPublicV4 are IPv4 ranges netip calls global unicast that are nobody's
// public address: shared address space (100.64.0.0/10, where a tailnet
// lives), IETF protocol assignments, benchmarking, and the reserved block.
// The management node refuses the same list (JobCommandBuilder::NOT_PUBLIC_V4).
var notPublicV4 = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// forwardAddress: a copy's public unicast address, in its canonical spelling.
// Loopback, private, link-local, multicast, unspecified and notPublicV4
// addresses are refused, so a forward or a trust never names something on the
// machine's own networks.
func forwardAddress(s string) (string, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return "", fmt.Errorf("%q is not an address", s)
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
		return "", fmt.Errorf("%s is not a public address", a)
	}
	for _, p := range notPublicV4 {
		if p.Contains(a) {
			return "", fmt.Errorf("%s is not a public address", a)
		}
	}
	return a.String(), nil
}
