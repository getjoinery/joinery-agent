package recipes

// ReportOnly is the loop's repair switch, and it is a compiled constant on
// purpose: arming the repair step is a release, reviewed and signed, never a
// setting a file or a plane could flip (specs/agent_tier1_recipes.md,
// "Burn-in").
//
// It is false: this release is armed. The loop repairs on the second
// consecutive failing tick, three attempts per failing run spaced by the
// backoff, then it escalates and a person is the next actor. Armed on
// 2026-09-16 (agent 1.33.0) after the burn-in ledger from dev, jeremytunnell
// and the docker-prod host was read and the case proof ran end to end on
// agent 1.32.0 (the spec's "Burn-in" section carries both).
//
// While it was true the loop did everything but the repair: the check ran,
// the two-tick rule, the backoff, the hold, the busy skip and the budget all
// applied, an attempt was ledgered when it would have started and completed
// with the outcome "report-only", and the third attempt escalated. That path
// still exists (Loop.reportOnly, set only by tests) so the report-only
// posture stays proven should a later release need to disarm; and
// registry_test.go pins the value, so changing it is a deliberate edit to two
// files, not a slip.
const ReportOnly = false
