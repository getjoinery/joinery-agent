package primitives

import "time"

// listening_sockets: which addresses and ports this machine listens on, and
// which program and systemd unit holds each.
//
// The word specs/agent_recipes_and_vocabulary.md's running list asked for on
// 2026-10-12. Allow mail apps failed with "the gateway did not start
// listening on 993 and 465" while the gateway's own journal said it listened
// on [::]:993; the cause, no IPv4 listener, was found by reading the gateway's
// source and reproducing it on dev, because the node could not say which
// addresses its services were bound to.
//
// A SCRIPT WORD, because it needs ss. What runs is
// maintenance_scripts/sysadmin_tools/listening_sockets.sh, verified against
// the signed release manifest before it runs as root, with no argv and no
// stdin.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word?
// Learn which ports the machine listens on and which program holds each: what
// a port scan from outside already shows, plus the listeners bound to the
// loopback (PostgreSQL on 127.0.0.1:5432). That is reconnaissance of the
// grade host_report already grants, which names the machine's units and jails.
//
// What it cannot do:
//
//   - Point anywhere. NO PARAMETERS: not a port, not an address, not a
//     process. Params is nil and Args is nil.
//   - See a connection. Listening TCP sockets and bound UDP sockets only:
//     never a peer, never a remote address, so it says nothing about who
//     talks to this machine.
//   - Read a process. A program's name and the unit its cgroup names; never a
//     pid, a command line, an environment or a file.
//   - Flood the plane. A hundred rows, capped in the script, with the agent's
//     64 KiB cap above as a backstop that is never the thing that bounds it.
//   - Change anything. ss and /proc/<pid>/cgroup are reads.
//
// No owner switch: it reads no log and no content. Not redacted: every value
// is an address, a port or a name the script reduced to a safe character
// set, and the redactor masks IP literals, which here ARE the answer.
//
// OBSERVE, and the classification does real work: a node whose policy accepts
// only observe words has to be able to trust that this one writes nothing.
func init() {
	Register(Primitive{
		Name:        "listening_sockets",
		Class:       ClassObserve,
		Machine:     true,
		Description: "The addresses and ports this machine listens on (TCP listeners, bound UDP), each with its family and the program and unit that hold it; no connections, no remote addresses.",

		// Empty on purpose. See the review above.
		Params: nil,

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  listeningSocketsScript,
			Args:        nil,
			StdinFrom:   nil,
			Redact:      false,
		},

		// One ss and a cgroup read per holder; the script bounds ss at ten
		// seconds.
		Timeout: 1 * time.Minute,
	})
}

// listeningSocketsScript is the shipped reader, site-root relative. A constant
// so the test asserts the same string the registration uses.
const listeningSocketsScript = "maintenance_scripts/sysadmin_tools/listening_sockets.sh"
