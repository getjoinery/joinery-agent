package recipes

// ReportOnly is the loop's repair switch, and it is a compiled constant on
// purpose: arming the repair step is a release, reviewed and signed, never a
// setting a file or a plane could flip (specs/agent_tier1_recipes.md,
// "Burn-in").
//
// While it is true the loop does everything but the repair: the check runs,
// the two-tick rule, the backoff, the hold, the busy skip and the budget all
// apply, an attempt is ledgered when it would have started and completed with
// the outcome "report-only", a fourth attempt in the hour escalates. The ledger
// from that cycle is what the owner reads before this line changes — and
// registry_test.go pins the value, so changing it is a deliberate edit to two
// files, not a slip.
//
// Report-only attempts count against the budget and toward escalation
// (assumption recorded 2026-09-14, owner may reverse): that is what makes the
// burn-in ledger show the path the armed loop would have taken, including
// where it would have given up.
const ReportOnly = true
