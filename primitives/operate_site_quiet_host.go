package primitives

import (
	"context"
	"time"
)

// site_quiet_host {action: on|off|forward, name, reason, to}: the host's half of one of
// its site containers' quiet state (specs/site_container_engine.md D9).
//
// A quiet site sends nothing: a dormant copy waiting to take over its source,
// or a source frozen for its final copy. On bare metal the machine holds that
// itself (site_quiet, over _site_state.sh). A container shares its machine,
// and a table it could change is no wall, so the host holds it from outside:
// a table inside the site's own network namespace refuses every account but
// the container's root, loopback and replies apart. The site's agent, as
// root, still reaches the management node and backup storage.
//
//   - on records the host's state for the site, for a switch-over, and loads
//     the table into its running container; the engine's hook loads it at
//     every start after. A dormant copy's record (copy) is install.sh's, made
//     at its install: this word never makes one, so it can never make a site
//     removable by discard_copy, and the script refuses to turn a copy's
//     record into a switch-over.
//   - forward, on a site the host holds frozen for a switch-over, lets its
//     table reach the copy at `to` on 80 and 443 and nothing else, so the
//     site can forward its visitors there while its address moves by DNS
//     (specs/site_copy_anything_to_anything.md D1). off removes it too.
//   - off lifts it, and only once the site itself has left its quiet state:
//     the script asks inside the container for the site's own state file and
//     refuses while it is there. A copy leaves that state only once it holds
//     its source's node id (site_quiet off, the agent inside the copy).
//
// A SCRIPT WORD: maintenance_scripts/sysadmin_tools/site_quiet_host.sh,
// verified against the signed manifest (on a host, the support bundle's),
// with an argv composed here from three validated values.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Cut one of the host's own sites off the network for every account but its
// root: its mail, payments and outside calls fail until off. An outage, seen
// at once by the site's owner, with nothing lost, and less than hold_container
// can already do (stop it). Accepted.
//
// What it cannot do:
//
//   - Lift a quiet site's table while the site says it is quiet: off refuses,
//     so it cannot open a dormant copy's network beside its source.
//   - Name a container that is not a Joinery site. `name` matches the site
//     pattern here, and the script refuses any container whose name is not
//     its own SITENAME, the shape install.sh creates.
//   - Write anything but the host's one-word record of the site and the table
//     in that site's own namespace. It reads nothing back but the yes or no
//     of the site's state file, which only ever keeps the table.
func init() {
	Register(Primitive{
		Name:        "site_quiet_host",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Hold one of this host's site containers quiet from outside for a switch-over (on: only its root reaches past loopback), or lift it, a dormant copy's included, once the site has left its own quiet state (off).",
		Params: []ParamSpec{
			{Name: "action", Type: ParamEnum, Required: true, Values: []string{"on", "off", "forward"}},
			{Name: "name", Type: ParamString, Required: true, MaxLen: 50, Pattern: holdContainerName},
			{Name: "reason", Type: ParamEnum, Values: []string{"switchover"}},
			{Name: "to", Type: ParamString, MaxLen: 39, Pattern: forwardAddressPattern},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  siteQuietHostScript,
			ArgsFrom:    siteQuietHostArgv,
		},
		// Each engine call and the namespace's nft run under twenty seconds.
		Timeout: 3 * time.Minute,
	})
}

const siteQuietHostScript = "maintenance_scripts/sysadmin_tools/site_quiet_host.sh"

func siteQuietHostArgv(_ context.Context, _ *ExecEnv, p Params) ([]string, error) {
	name := p.String("name")
	if p.String("action") == "forward" {
		if p.String("reason") != "" {
			return nil, refusedf("site_quiet_host: forward takes no reason")
		}
		to, err := forwardAddress(p.String("to"))
		if err != nil {
			return nil, refusedf("site_quiet_host: %v", err)
		}
		return []string{"forward", name, to}, nil
	}
	if p.String("to") != "" {
		return nil, refusedf("site_quiet_host: only forward takes an address")
	}
	if p.String("action") == "off" {
		if p.String("reason") != "" {
			return nil, refusedf("site_quiet_host: off takes no reason")
		}
		return []string{"off", name}, nil
	}
	reason := p.String("reason")
	if reason == "" {
		return nil, refusedf("site_quiet_host: on says why the site is quiet: switchover")
	}
	return []string{"on", name, reason}, nil
}
