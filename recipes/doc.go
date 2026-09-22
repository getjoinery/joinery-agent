// Package recipes is the agent's tier 1 composer: the short list of fixed
// sentences the agent runs on its own clock, with no plane and no operator —
// check, repair, verify, retry policy, hold, escalate — one compiled recipe per
// aspect of the host it keeps correct (specs/agent_recipes_and_vocabulary.md,
// "Tier 1"; specs/agent_tier1_recipes.md, "The recipe contract").
//
// It sits beside primitives the way that package sits beside the agent: a
// registry of Go values populated only by init functions in this package,
// pinned by a gate test so that a recipe cannot arrive without a human writing
// its name into registry_test.go. A recipe composes exactly two words from the
// primitives registry — an observe word as its check and one operate word as
// its repair — and runs them in-process through primitives.Execute under the
// same policy and the same manifest verification a plane-dispatched job gets.
// A check-only recipe (Recipe.NoRepair) composes the observe word alone: it
// runs nothing that changes the machine, and its first failing check opens a
// case for a person, because what it watches has no safe automatic answer.
// Nothing in this package starts a process; only primitives/script.go may.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// The review question for a word is "what is the worst a compromised
// management node can do with this". A recipe has no caller on the wire at
// all — it is the first thing the agent does UNASKED — so the question here
// is broader: what is the worst that anything outside this source can make
// the loop do, and what is the worst the loop can do on its own.
//
// What the wire can do: nothing. The plane learns the recipe list and its mode
// at poll (Report) and cannot answer back. There is no field in a claim, a
// job or a result that names, starts, stops, arms or tunes a recipe. A recipe
// has no parameters, and the Recipe struct has no field a parameter could
// live in; registry_test.go reflects over the struct to pin that.
//
// What the disk can do: make the agent do LESS, never more. Exactly two
// files are read, and both only narrow:
//
//   - The hold marker, /etc/joinery-agent/hold/<recipe>. Present, in a
//     directory owned by root and writable by root alone, it stops the
//     repair and nothing else — the check still runs and the ledger and the
//     log say "held" on every failing tick, so an operator who set the marker
//     is told it is working and one who did not is told it exists. A marker
//     in a directory anything else could write is ignored, and the ledger
//     says why; a marker only ever narrows, but a marker that was not root's
//     is a stated refusal rather than a quiet one.
//   - The ledger this package wrote itself, /etc/joinery-agent/ledger/
//     <recipe>.jsonl, read back for one purpose: the attempt budget and the
//     open escalation. A forged ledger could only add attempts (fewer repairs)
//     or an open escalation (no repairs). It cannot subtract: the directory
//     must be root's and unwritable by anyone else, or the loop refuses to
//     ledger and, because an attempt that cannot be ledgered cannot be
//     budgeted, refuses to repair — it keeps checking and says so. The
//     outward copy under the site's cache directory is written and never
//     read, because the web user can write there and a forged "no attempts
//     yet" would widen the agent from a file on disk.
//
// No file is read for instructions. There is no recipe list on disk, no
// schedule, no policy of the loop's own; the cadence, the budget, the backoff,
// the two-tick rule and the report-only switch are constants in this package,
// and arming the repair is a release, never a setting.
//
// What the loop can do on its own, at worst: run the recipe's one operate word
// three times in an hour, spaced ten and thirty minutes apart, each under the
// shared job lock and the job marker so it never overlaps a plane job or a
// self-update, and then stop and say so. The words it may run are the two the
// recipe names, both compiled, both reviewed in their own headers
// (operate_host_converge.go: idempotent housekeeping the host timer already
// runs daily). A check never repairs on an answer it cannot read — unknown is
// not failed — and never on the first failing tick, so a transient, a reboot,
// an operator's reload or an apt upgrade restarting a unit is seen twice, ten
// minutes apart, before anything acts. A repair that kills the agent leaves an
// attempt with no outcome, which the next process counts as a failed attempt
// against the same budget, so a restart cannot reset the loop into a fourth.
//
// What it cannot do: run a word it does not name, run one outside the signed
// manifest (Execute verifies the script the same way for a recipe as for a
// job), run one the node's own policy refuses (Execute checks the class the
// same way), pass a parameter to either (Register refuses a recipe whose
// words take any), overlap a job (TryLock, never Lock — a lost lock is a
// ledger line, not a wait), repair while held, repair while escalated, or
// repair a fourth time.
//
// Report-only, this release: the repair step records the attempt with the
// outcome "report-only" and runs nothing, while the two-tick rule, the budget
// and the escalation count exactly as if it had run. The burn-in ledger
// therefore shows the path the armed loop would have taken, on every node,
// with nothing acting (specs/agent_tier1_recipes.md, "Burn-in").
//
// The case (case.go) is the escalation given a body and a delivery, and it
// changes none of the above. It is the one thing the node pushes at the
// plane on its own initiative, so the review runs the other way for it: the
// plane is told, and a compromised node may write what it likes into every
// field. Here the fields are capped before they leave, so a lie is a bounded
// lie; on the plane every field is capped again on intake and escaped on
// render, and nothing in a case reaches a shell, a template or a link. The
// claim response is not read for anything about cases: the plane cannot
// close one, reopen one, or tell this node a fault is gone — the recipe's
// own check passing is the only close. The rendered copy written outward
// under the site's cache directory is written and never read, like the
// outward ledger, so a forged one is a lie to the site's admin and one mail,
// and nothing root acts on. A report-only escalation opens a case just the
// same: the burn-in's product is exactly those cases.
package recipes
