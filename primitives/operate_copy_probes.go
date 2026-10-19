package primitives

import (
	"context"
	"regexp"
	"time"
)

// copy_probes {site, neighbour, old_address}: the security rows of a site copy
// that only acting as the site can prove (specs/site_copy_final_test.md, the
// rig's rows marked ‡).
//
// The management node reads every other row of a copy's security check from
// the host report. These rows are the attempts themselves, as the site's web
// user: a user namespace, a mount, a packet socket, a write to the site's
// code; then, as root, whether the site's root can read its neighbour's
// files, whether this machine still believes the site's old server as a
// forwarder, and whether the database answers off the loopback. Each comes
// back as a PASS, FAIL or SKIP line with its evidence, and RESULT: last.
//
// A SCRIPT WORD: maintenance_scripts/sysadmin_tools/copy_probes.sh, verified
// against the signed manifest (on a host, the support bundle's), with an argv
// composed here from validated values. It runs on a frozen source and on a
// dormant copy (the baseline and the copy are both probed before the switch),
// so it runs under any quiet reason; it sends nothing.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Learn whether this machine's walls hold: which of the attempts were refused.
// That is the machine's posture, which the host report already describes from
// its configuration; it learns no data. Each attempt is one a site's own code
// can make whenever it likes, made here as that site's web user, so running it
// gives the caller nothing the site's code does not already have; and a
// successful attempt changes nothing (the script's header says how).
//
// What it cannot do:
//
//   - Name anything but a site, a neighbour site and an address: names are a
//     site's character set with no leading dash, the address is parsed here
//     and passed in its canonical spelling.
//   - Loosen anything. The test plane's check that a loosened kernel setting
//     is put back is not in the shipped script and has no parameter here.
//   - Read a file's contents. The neighbour probe lists a volume as the site's
//     root and keeps only whether it was refused.
func init() {
	Register(Primitive{
		Name:        "copy_probes",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Probe one site's walls by acting as it (namespaces, mount, packet socket, writing its code, its neighbour's files, a forwarder's trust, its database's listener) and say which held.",
		Params: []ParamSpec{
			{Name: "site", Type: ParamString, Required: true, MaxLen: 50, Pattern: copyProbesSitePattern},
			{Name: "neighbour", Type: ParamString, MaxLen: 50, Pattern: copyProbesSitePattern},
			{Name: "old_address", Type: ParamString, MaxLen: 39, Pattern: forwardAddressPattern},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  copyProbesScript,
			ArgsFrom:    copyProbesArgv,
		},
		// Eight probes, each bounded at thirty seconds in the script.
		Timeout: 5 * time.Minute,
		Quiet:   QuietAny,
	})
}

const copyProbesScript = "maintenance_scripts/sysadmin_tools/copy_probes.sh"

// A site's name, never one a script could read as a flag.
var copyProbesSitePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,49}$`)

func copyProbesArgv(_ context.Context, _ *ExecEnv, p Params) ([]string, error) {
	argv := []string{p.String("site")}
	if p.Has("neighbour") {
		if p.String("neighbour") == p.String("site") {
			return nil, refusedf("copy_probes: a site is not its own neighbour")
		}
		argv = append(argv, "--neighbour", p.String("neighbour"))
	}
	if p.Has("old_address") {
		addr, err := forwardAddress(p.String("old_address"))
		if err != nil {
			return nil, refusedf("copy_probes: %v", err)
		}
		argv = append(argv, "--old-address", addr)
	}
	return argv, nil
}
