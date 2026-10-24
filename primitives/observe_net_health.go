package primitives

import "time"

// net_health: is this machine dropping packets or connections?
//
// The word specs/slow_request_diagnosis_words.md WP2 asked for. On 2026-10-23
// jeremytunnell.com's requests stalled for up to 90 s through Cloudflare and
// never when sent straight at the machine; Apache logged the bodies that never
// arrived, and nothing could say whether the kernel was dropping connections
// (an accept queue overflowing, a SYN queue full, the connection table full)
// or the network card was dropping packets before TCP counted anything.
//
// A SCRIPT WORD, because it reads /proc twice ten seconds apart and runs ss.
// What runs is maintenance_scripts/sysadmin_tools/net_health.sh, verified
// against the signed release manifest before it runs as root, with no argv and
// no stdin.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word?
// Learn how busy the machine's web ports are and whether it is losing packets
// or connections: what an outside load test shows anyway.
//
// What it cannot do:
//
//   - Point anywhere. NO PARAMETERS. Params is nil and Args is nil.
//   - See who talks to the machine. Counts only: kernel counters, connection
//     counts by TCP state on ports 80 and 443, each web listener's queue
//     against its limit. Never a remote address, never another port, never a
//     process.
//   - Flood the plane. A fixed set of counters and at most sixteen listeners.
//   - Change anything. /proc and /sys are read; ss runs with fixed arguments.
//
// HOST ONLY. Inside a site container the counters are the container's own
// network namespace, which is not where an edge connects, so the script
// refuses there by the same markers RunsInContainer reads (/.dockerenv,
// /run/.containerenv), exit 2, refused "container"; the plane asks the host's
// node instead.
//
// No owner switch: it reads no log and no content. Not redacted: every value
// is a number, a TCP state name or a listener's own address.
func init() {
	Register(Primitive{
		Name:        "net_health",
		Class:       ClassObserve,
		Machine:     true,
		Description: "Whether this machine is dropping packets or connections: kernel TCP and network counters read twice ten seconds apart, the connection table, connection counts by state on the web ports and the web listeners' queues; counts only, host only.",

		// Empty on purpose. See the review above.
		Params: nil,

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  netHealthScript,
			Args:        nil,
			StdinFrom:   nil,
			Redact:      false,
		},

		// Ten seconds of sampling, two ss runs the script bounds at ten
		// seconds each.
		Timeout: 1 * time.Minute,
	})
}

// netHealthScript is the shipped reader, site-root relative.
const netHealthScript = "maintenance_scripts/sysadmin_tools/net_health.sh"
