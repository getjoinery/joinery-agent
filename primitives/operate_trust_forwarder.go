package primitives

import (
	"context"
	"fmt"
	"time"
)

// trust_forwarder {action: trust|untrust, address, hours}: believe
// X-Forwarded-For from one address, for a while
// (specs/site_copy_anything_to_anything.md D1).
//
// While a site's address moves by DNS, its old server forwards every visitor
// whose resolver still names it to the copy, adding X-Forwarded-For. The
// machine whose Apache answers the copy (the copy's own server, or the host
// fronting a copy in a container) believes that header from the old server's
// address alone, so the site's per-address checks see its visitors.
//
//   - trust believes `address` for `hours` (1 to 168): the end is written
//     beside it, and every run of the script leaves out an address past its
//     end, so a trust nobody takes back still ends.
//   - untrust stops at once. The management node sends it when the move has
//     settled, and when the switch-over is kept or undone: the old server's
//     address goes back to its provider when the server is deleted, and
//     whoever holds it next must never be believed.
//
// Runs on a site frozen for a switch-over (the way back untrusts on a copy
// quieted for it); it sends nothing, so the freeze holds.
//
// A SCRIPT WORD: maintenance_scripts/sysadmin_tools/trust_forwarder.sh,
// verified against the signed manifest (on a host, the support bundle's), with
// an argv composed here from validated values.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word? Have
// this machine believe a forwarded client address from one public address of
// its choosing for up to a week: whoever sends from there can name any
// visitor, and the sites here see that name instead of the real one (their
// per-address limits and allow-lists, their logs, fail2ban). It sees no data
// and changes no site. Bounded by the hours and one address per call, and
// public unicast only, so nothing on this machine's own networks can be named
// a proxy. Accepted for the switch it serves.
//
// What it cannot do:
//
//   - Name a range, a private or local address, or anything but an address:
//     the address is parsed here and passed in its canonical spelling.
//   - Trust for longer than a week.
func init() {
	Register(Primitive{
		Name:        "trust_forwarder",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Believe X-Forwarded-For from one public address for up to a week (a site's old server forwarding visitors while its DNS moves), or stop believing it.",
		Params: []ParamSpec{
			{Name: "action", Type: ParamEnum, Required: true, Values: []string{"trust", "untrust"}},
			{Name: "address", Type: ParamString, Required: true, MaxLen: 39, Pattern: forwardAddressPattern},
			{Name: "hours", Type: ParamInt, Min: 1, Max: 168},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  trustForwarderScript,
			ArgsFrom:    trustForwarderArgv,
		},
		Timeout: 2 * time.Minute,
		// The way back stops the copy believing the old server after the
		// copy has been quieted again for it (switchover).
		Quiet: QuietSwitchover,
	})
}

const trustForwarderScript = "maintenance_scripts/sysadmin_tools/trust_forwarder.sh"

func trustForwarderArgv(_ context.Context, _ *ExecEnv, p Params) ([]string, error) {
	addr, err := forwardAddress(p.String("address"))
	if err != nil {
		return nil, refusedf("trust_forwarder: %v", err)
	}
	if p.String("action") == "untrust" {
		if p.Has("hours") {
			return nil, refusedf("trust_forwarder: untrust takes no hours")
		}
		return []string{"untrust", addr}, nil
	}
	if !p.Has("hours") {
		return nil, refusedf("trust_forwarder: trust says for how many hours (1 to 168)")
	}
	return []string{"trust", addr, fmt.Sprintf("%d", p.Int("hours"))}, nil
}
