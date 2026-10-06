package primitives

import (
	"context"
	"regexp"
	"time"
)

// outbound_limits: turn this machine's outbound limits on or off, or set
// their figures, the machine's own or one container site's
// (specs/node_outbound_and_transfer.md WP5).
//
// Why it exists: every install carries a speed ceiling and connection limits
// (outbound_limits.sh, the joinery-limits unit), at figures the machine's
// owner sets. Where the management node pays the machine's bill, its operator
// sets them, and turns them off on a node of its own, from the node page;
// without this word that meant a shell on the machine.
//
// A SCRIPT WORD: maintenance_scripts/install_tools/outbound_limits.sh,
// verified against the signed release manifest (on a Docker host, the support
// bundle's). argv is composed here from the validated params: on, off, or set
// with each figure given as the script's own flag and --by=plane, so the
// site's settings page says the figures come from whoever hosts it.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Turn a machine's limits off, or raise its figures, so a hacked site on it
// can send as fast as the link allows and open connections freely: the bill
// and the abuse reports these limits bound are unbounded again. Or lower the
// ceiling to 1 Mbit/s, so the machine's sites crawl. Both are outages and
// costs of the kind apply_update can already cause outright. Accepted.
//
// What it cannot do:
//
//   - Write anything but the host file's figure keys and enabled
//     (/etc/joinery/outbound_limits.json) or one site's outbound_* run spec
//     lines, and run the joinery-limits unit. Every value is a whole number
//     in bounds, off for a ceiling, or default; a site name matches the site
//     pattern, and the script refuses a site with no run spec.
//   - Raise a site's own setting: the site's lower ceiling still holds.
//   - Read anything. It prints the figures it set.
func init() {
	Register(Primitive{
		Name:        "outbound_limits",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Turn this machine's outbound limits on or off, or set their figures (speed ceiling, connection rate, burst, open connections) for the machine or one container site.",
		Params: []ParamSpec{
			{Name: "action", Type: ParamEnum, Required: true, Values: []string{"on", "off", "set"}},
			{Name: "ceiling", Type: ParamString, MaxLen: 7, Pattern: outboundCeilingValue},
			{Name: "conn_rate", Type: ParamString, MaxLen: 7, Pattern: outboundCountValue},
			{Name: "conn_burst", Type: ParamString, MaxLen: 7, Pattern: outboundCountValue},
			{Name: "open_conns", Type: ParamString, MaxLen: 7, Pattern: outboundCountValue},
			{Name: "site", Type: ParamString, MaxLen: 50, Pattern: holdContainerName},
		},

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  outboundLimitsScript,
			ArgsFrom:    outboundLimitsArgv,
			StdinFrom:   nil,
		},

		// One pass of the unit: an nft transaction, a tc check per site, and
		// a short docker exec into each site for its own ceiling.
		Timeout: 5 * time.Minute,
	})
}

const outboundLimitsScript = "maintenance_scripts/install_tools/outbound_limits.sh"

var (
	// A speed ceiling in Mbit/s, off for none, or default (the figure below).
	outboundCeilingValue = regexp.MustCompile(`^([1-9][0-9]{0,5}|off|default)$`)
	// A connection figure, or default.
	outboundCountValue = regexp.MustCompile(`^([1-9][0-9]{0,6}|default)$`)
)

// outboundLimitsArgv composes the script's argv. on and off take nothing
// else; set takes at least one figure, each as the script's flag, and says
// the management node set them.
func outboundLimitsArgv(_ context.Context, _ *ExecEnv, params Params) ([]string, error) {
	action := params.String("action")
	figures := []struct{ param, flag string }{
		{"ceiling", "--ceiling="},
		{"conn_rate", "--conn-rate="},
		{"conn_burst", "--conn-burst="},
		{"open_conns", "--open-conns="},
	}
	if action != "set" {
		for _, f := range figures {
			if params.String(f.param) != "" {
				return nil, refusedf("outbound_limits %s takes no figures", action)
			}
		}
		if params.String("site") != "" {
			return nil, refusedf("outbound_limits %s is the machine's; it takes no site", action)
		}
		return []string{action}, nil
	}
	argv := []string{"set"}
	for _, f := range figures {
		if v := params.String(f.param); v != "" {
			argv = append(argv, f.flag+v)
		}
	}
	if len(argv) == 1 {
		return nil, refusedf("outbound_limits set needs a figure: ceiling, conn_rate, conn_burst or open_conns")
	}
	if site := params.String("site"); site != "" {
		argv = append(argv, "--site="+site)
	}
	return append(argv, "--by=plane"), nil
}
