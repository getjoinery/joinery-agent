package primitives

import (
	"regexp"
	"time"
)

// managed_domain_prepare: make this node mail-ready for one managed domain, and
// say what DNS that requires.
//
// Someone buys hosting and, in the same checkout, types the domain name they
// want. The management node buys the name and publishes the zone; but only THIS
// machine knows what belongs in that zone — its receive topology, its SPF shape,
// its DKIM key, whether it speaks Joinery Direct. A management node that
// computed those records itself would publish a plausible set this box does not
// match, and the mismatch shows up as mail silently failing authentication.
//
// So the split is: this prints desired state and the plane publishes it. That
// split is the design and does not change here. What changed is the transport:
// the plane used to reach in with proc_open(['ssh', ...]) from PHP, composing a
// `docker exec -i <container> bash -c 'cd <site dir> && php <utility> <domain>'`
// from columns in its own database. Now it names this primitive.
//
// ONE PARAMETER, AND IT IS THE ONLY THING THAT COULD BE ONE. The domain is what
// the buyer typed; everything else the old command carried was the plane's
// BELIEF about this node — the container name, the site directory, the path to
// the utility — and every one of them is something the node knows for itself.
// The agent resolves its own SiteRoot, the script path is compiled in, and the
// utility reads the site's own database through the platform. There is no site
// name on the wire and no credential on the wire, for the same reason
// run_plugin_installers takes nothing at all: a node told its own name by a
// remote party is a node whose identity is only as correct as a row somebody
// else can edit — and, since the name becomes a filesystem path, only as safe.
//
// OPERATE, NOT OBSERVE, AND THAT IS NOT A JUDGMENT CALL. registry.go defines
// ClassObserve as "reads: collectors, status, list. No state changes", and
// preparing a domain registers it for receiving and mints a DKIM signing key.
// policy.go lets a node accept CLASSES rather than individual primitives, so a
// node whose policy accepts only observe has to be able to trust that an observe
// primitive writes nothing. This writes.
//
// THE UTILITY IS IDEMPOTENT BY DESIGN, which is what makes it safe to retry —
// and it will be retried, because the plane's provisioning phase takes one step
// per tick and re-dispatches an attempt that did not land. Re-running it for a
// prepared domain changes nothing and just reprints the plan.
//
// SUCCESS IS NOT THE EXIT CODE HERE EITHER. The utility exits 0 and prints
// {"ok":false,"error":...} for a domain it could not prepare, and exits 0 with
// {"ok":true,"dkim_ready":false,...} for one that is publishable but not
// finished — MX and SPF make mail arrive, the signing key comes later. The
// verdict is the JSON line, which the framework carries back in full under
// "output", and the plane parses it. Nothing here may summarise it.
func init() {
	Register(Primitive{
		Name:        "managed_domain_prepare",
		Class:       ClassOperate,
		Description: "Make this node mail-ready for one managed domain and report the DNS records it needs.",
		Params: []ParamSpec{
			{Name: "domain", Type: ParamString, Required: true, MaxLen: 253, Pattern: managedDomainPattern},
		},
		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",

			// Inside a plugin, so it verifies against the MAILBOX plugin's own
			// signed manifest rather than the site-root one — the artifact that
			// shipped it is the artifact that speaks for it.
			ScriptPath: managedDomainPrepareScript,

			// The domain, and nothing else. Argv goes to the kernel as a list,
			// so a domain containing a semicolon is a domain containing a
			// semicolon; there is no shell to parse it. The pattern below means
			// it cannot contain one anyway.
			Args: []string{"{domain}"},

			// No stdin. The utility reads none.
			StdinFrom: nil,
		},
		// Registering a domain for receiving and minting a DKIM key are local
		// database and key work measured in seconds. Five minutes is a ceiling
		// on a wedged process, not a target — and it sits under the plane's
		// 900s claim floor, so this needs no PRIMITIVE_CLAIM_BUDGETS entry.
		Timeout: 5 * time.Minute,
	})
}

// managedDomainPrepareScript is the mailbox plugin's own utility, site-root
// relative. Named as a constant so the test asserts the same string the
// registration uses rather than a copy of it that can drift.
const managedDomainPrepareScript = "public_html/plugins/mailbox/utils/managed_domain_prepare.php"

// managedDomainPattern is the same shape managed_domain_prepare.php checks for
// itself, deliberately: a name that would be refused by the utility should be
// refused before a root process starts, and a second, looser definition here
// would be a way for the two to disagree.
//
// Lowercase only, because the utility lowercases before it validates and a
// managed domain is written in the zone in one case. Both ends therefore agree
// that one name has one spelling.
var managedDomainPattern = regexp.MustCompile(`^[a-z0-9.-]+\.[a-z]{2,}$`)
