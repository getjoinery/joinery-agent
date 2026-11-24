package primitives

import (
	"regexp"
	"time"
)

// unban_address: lift one fail2ban ban — one address, in one jail — and say
// how many bans were lifted.
//
// The word specs/agent_recipes_and_vocabulary.md asked for on 2026-11-24: a
// live check banned the management node's own address on a test node, in a
// jail that holds a ban for two days, and nothing short of a shell could lift
// it. An operator's own address banned by a mistyped password is the same
// case.
//
// A SCRIPT WORD, for the gate's reason: only script.go may start a process.
// What runs is maintenance_scripts/sysadmin_tools/unban_address.sh, verified
// against the signed release manifest, with two argv elements.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Lift the ban on an attacker's address, as often as it can dispatch jobs:
// the attacker's next failures count from zero again, so fail2ban slows them
// less. It guards nothing by itself — sshd takes keys or its own limits, the
// site has its own sign-in limits — and a plane that hostile can already
// change the site's code with apply_update. Accepted, as restart_unit
// fail2ban was.
//
// What it cannot do:
//
//   - Ban anyone. The script's only changing call is unbanip, pinned by its
//     gate: no banip, no stop, no reload, no firewall command.
//   - Name anything but a jail and an address. `jail` is a jail name by
//     shape and the script takes it only if fail2ban lists it on this
//     machine; `address` is hex digits, dots and colons, and the script
//     takes it only as an IPv4 or IPv6 address. Neither can begin with a
//     dash or carry a space.
//   - Read anything. It prints the jail, the address and a count; no
//     redaction, no log switch.
func init() {
	Register(Primitive{
		Name:        "unban_address",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Lift one fail2ban ban: one IPv4 or IPv6 address in one of this machine's jails, reporting how many bans were lifted; never bans, never stops fail2ban.",
		Params: []ParamSpec{
			{Name: "jail", Type: ParamString, Required: true, MaxLen: 40, Pattern: unbanJail},
			{Name: "address", Type: ParamString, Required: true, MaxLen: 45, Pattern: unbanAddress},
		},

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  unbanAddressScript,
			Args:        []string{"{jail}", "{address}"},
			StdinFrom:   nil,
		},

		// Two fail2ban-client calls, each bounded at 20 seconds by the script.
		Timeout: 2 * time.Minute,
	})
}

// A MIRROR of the shapes unban_address.sh checks before it checks more: the
// jail against fail2ban's own list, the address as an address.
var (
	unbanJail    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$`)
	unbanAddress = regexp.MustCompile(`^[0-9A-Fa-f][0-9A-Fa-f:.]{1,44}$|^:[0-9A-Fa-f:.]{1,44}$`)
)

const unbanAddressScript = "maintenance_scripts/sysadmin_tools/unban_address.sh"
