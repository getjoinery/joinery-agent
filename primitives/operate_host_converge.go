package primitives

import "time"

// host_converge: run host_housekeeping.sh — fail2ban's jails and drop-ins, the
// trusted-proxy list, the rest of the host's daily housekeeping — through the
// same root runner the host timer uses, and return the transcript.
//
// It is the first OPERATE word of specs/agent_tier1_recipes.md and the repair
// step recipe fail2ban will call. Built here on its own, plane-dispatched, so
// the --only path, the manifest check, the runner lock and the compiled
// constant are all proven under the job model — where every run is already
// ledgered with who asked — before any loop exists to call it unasked.
//
// WHAT RUNS is _plugin_installers_start.sh --only=host_housekeeping.sh: the
// runner takes its lock (waiting, bounded, for the timer's tick or an upgrade
// ahead of it), asserts the tree is the owner's, checks the installer is
// trusted, runs that one installer with the runner's own two arguments, and
// exits. No stamp, no last-run record, no permissions sweep, no plugin loop,
// no root requests: none of those describe a run that converged the host, and
// the timer's next tick is unaffected by this one (specs/agent_tier1_recipes.md,
// "The runner lock").
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// The wire carries the name host_converge and nothing else. Params is nil, so
// a job carrying any field at all is refused on the node before the script is
// reached. The one argv element, --only=host_housekeeping.sh, is a package
// constant compiled into this binary: it is not a "{param}" slot, it is not
// built by an ArgsFrom, and TestHostConvergeArgvIsTheCompiledConstant fails if
// it ever becomes either. So the element exists in the binary and never on the
// wire, and the question "which installer" was answered by the person who
// wrote this file, reviewed by the person who read it, and shipped in a signed
// release — the only three parties rule 1 allows to answer it.
//
// Why a compiled constant is not a wire-supplied argument, spelled out,
// because run_plugin_installers passes NO argv and a reader may ask why this
// one may pass one:
//
//   - The plane cannot vary it. A hostile plane sends {"primitive":
//     "host_converge"}; it has no field through which to send anything else,
//     and if it invents one the job is refused for the unknown key. The argv
//     the runner sees is the same on every node for every job, forever, until
//     a person changes this file.
//   - The runner refuses the rest anyway. --only accepts only a name in
//     CORE_INSTALLERS (five names, declared at the top of the runner) and
//     refuses anything else with exit 2 before the lock is taken and before
//     anything is touched. So even a hypothetical future edit that let a
//     value reach this element could only choose among five reviewed
//     installers, never a path, never a script the tree does not ship.
//   - The runner itself is verified. The script the interpreter receives is
//     checked against the signed release manifest before it starts, exactly
//     as run_plugin_installers is; a runner the web user rewrote does not run.
//
// What a compromised management node CAN do with this word: make the node run
// its own fail2ban housekeeping now. That installer is idempotent, is what the
// host timer already runs daily on its own clock, and rewrites only the files
// it owns (the fail2ban drop-ins and the trusted-proxy conf) from the shipped
// tree; running it twice, or a hundred times, leaves the host in the state the
// release defines. The cost is a bounded amount of root CPU and, on a host
// that has never had fail2ban installed, one apt install of a package the
// release already requires. The runner lock keeps two such runs from
// overlapping each other or the timer.
//
// What it CANNOT do: choose an installer (the name is compiled here and
// checked against CORE_INSTALLERS there), a path, a tree or a site (the runner
// derives its own root from its own location); run anything not in the signed
// manifest; touch the converge stamp or the timer's last-run record; reach the
// plugin loop or the root-request queue; or pass anything to the installer
// beyond the runner's own two arguments.
//
// SUCCESS IS NOT THE EXIT CODE. The runner is fail-safe zero by contract: an
// installer that fails, a missing installer, an untrusted installer and a lock
// it could not get after ten minutes all exit 0, deliberately, so the same
// runner can never block a container from starting. The transcript is the
// record — "core installers: host_housekeeping.sh: ok", or a WARNING, or a
// refusal, or "another run holds the lock" — and the framework carries every
// byte of it into the result under "output". The caller (today the plane's
// JobResultProcessor, later the fail2ban recipe) reads the transcript and
// verifies the aspect it asked for; nothing here summarises it into a verdict.
//
// OPERATE, not observe: it changes the host. Not destructive: it rewrites
// configuration the release owns, in a way the timer already performs
// unattended every day, and destroys nothing a person made.
func init() {
	Register(Primitive{
		Name:        "host_converge",
		Class:       ClassOperate,
		Description: "Run host_housekeeping.sh (fail2ban and the host's daily housekeeping) through the host runner, and return the transcript.",

		// Empty on purpose. See the review above: every parameter not declared
		// here is one the plane can never abuse.
		Params: nil,

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",

			// The same runner run_plugin_installers invokes, site-root
			// relative and outside public_html, verified against the
			// manifest at the site root before it runs as root.
			ScriptPath: pluginInstallersRunner,

			// One element, a compiled constant. Not a "{param}" slot: there
			// is no parameter for a slot to name, and the test pins that the
			// template contains none.
			Args: []string{hostConvergeOnly},

			// No stdin. The runner reads none.
			StdinFrom: nil,
		},

		// The runner waits up to ten minutes for its lock (flock -w 600) when
		// the timer's tick or an upgrade holds it, and housekeeping on a host
		// that has never had fail2ban runs one apt install. Fifteen minutes
		// covers the wait plus the work; one still going after that is stuck,
		// not busy, and the process group is killed.
		Timeout: 15 * time.Minute,
	})
}

// hostConvergeOnly is the whole argv this word passes the runner: the
// single-installer mode naming the one installer it exists to run. A constant
// rather than a literal in the registration so the test asserts the
// registration uses this exact value and nothing else, and so the value has
// one home a reviewer can find. The name after --only= must be one of the
// runner's CORE_INSTALLERS or the runner refuses it with exit 2.
const hostConvergeOnly = "--only=host_housekeeping.sh"
