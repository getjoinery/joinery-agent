package recipes

import "sync"

// The last verdict of every recipe, for the claim.
//
// A recipe's mode says whether it acts; it says nothing about whether its
// subject is right. During the case proof (2026-09-16) the docker-prod host
// failed its fail2ban check every ten minutes for three hours and read as
// healthy on the plane the whole time, because the claim carried only
// "fail2ban:report-only". So the claim carries the verdict too:
// "fail2ban:armed:fail". The board is the loop's memory of what each check
// last said, in this process; before the first check a recipe has no verdict
// and the claim says only its mode. Nothing is read back from disk — a
// verdict is only ever the most recent one this process reached, and the
// plane shows it beside when the node last polled.
var verdicts = struct {
	mu   sync.Mutex
	last map[string]Kind
}{last: map[string]Kind{}}

// noteVerdict records what a recipe's check last said.
func noteVerdict(recipe string, k Kind) {
	verdicts.mu.Lock()
	defer verdicts.mu.Unlock()
	verdicts.last[recipe] = k
}

// LastVerdict is what a recipe's check last said in this process, or "" when
// it has not been checked yet.
func LastVerdict(recipe string) Kind {
	verdicts.mu.Lock()
	defer verdicts.mu.Unlock()
	return verdicts.last[recipe]
}

// ResetVerdictsForTests forgets every verdict. Tests only.
func ResetVerdictsForTests() {
	verdicts.mu.Lock()
	defer verdicts.mu.Unlock()
	verdicts.last = map[string]Kind{}
}
