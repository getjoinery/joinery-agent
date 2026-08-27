package primitives

import (
	"regexp"
	"time"
)

// provision_certificate: issue or re-issue this node's own origin TLS
// certificate for one domain.
//
// BARE METAL ONLY, AND THE PLANE MUST HONOUR THAT — see the contract note at
// the bottom of this file, which is the one thing about this primitive that
// must not be got wrong.
//
// It replaces the certbot half of the SSH `provision_ssl` job. That job was
// never one operation: it branched on a Cloudflare check made on the plane, and
// its Cloudflare arm interleaved node steps with a plane-side fetch that proves
// a domain routes here (ssl_probe_place / ssl_probe_clear are the node's half of
// that, and the fetch stays on the plane, where a routing proof has to be made
// by somebody other than the node being proved). What is left, once the probe
// pair is carved out, is this: get a certificate onto this machine.
//
// IT INVOKES THE PLATFORM'S OWN SCRIPT RATHER THAN COMPOSING A CERTBOT ARGV.
// maintenance_scripts/sysadmin_tools/setup_ssl.sh is the operator-facing "issue
// the cert for this domain" command, and it already knows more than the SSH
// steps did: it installs certbot when missing, compares the domain's A and AAAA
// records against this host's own addresses to decide whether HTTP-01 can work
// at all, falls back to DNS-01 through whichever provider plugin the domain's
// nameservers imply, and reloads Apache afterwards. Reimplementing that in Go
// would be a fourth copy of the platform's certbot logic and the only one not
// covered by the release manifest.
//
// The apt-get is inside that script, which is where it belongs: "install certbot
// if it is missing" is not an operation an operator asks for, so it is not a
// primitive. The SSH job made it a separate step; a step is not the same thing
// as an operation.
//
// ONE PARAMETER, AND IT IS THE ONLY THING THAT COULD BE ONE. A certificate is
// for a name, the name comes from the domain being provisioned, and there is no
// second value the plane is entitled to supply — the challenge path, the
// credentials, the webroot, the Apache config are all the node's own business
// and the script works them out from the node itself.
func init() {
	Register(Primitive{
		Name:        "provision_certificate",
		Class:       ClassOperate,
		Description: "Issue or re-issue this node's origin TLS certificate for one domain.",
		Params: []ParamSpec{
			{Name: "domain", Type: ParamString, Required: true, MaxLen: 253, Pattern: certificateDomainPattern},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  provisionCertificateScript,
			Args:        []string{"{domain}"},
		},
		// The SSH steps budgeted 120s for the apt install and 300s for certbot,
		// and this script can also install a DNS provider plugin and make a
		// DNS-01 attempt after an HTTP-01 failure. Ten minutes covers the slow
		// path with room; it is a ceiling on a wedged root process, not a
		// target.
		Timeout: 10 * time.Minute,
	})
}

// provisionCertificateScript is the operator-facing SSL command, site-root
// relative. Outside public_html, so it verifies against the core manifest.
const provisionCertificateScript = "maintenance_scripts/sysadmin_tools/setup_ssl.sh"

// certificateDomainPattern is a hostname a certificate can actually be issued
// for: dot-separated labels ending in an alphabetic TLD.
//
// The strictness is not tidiness. It refuses a bare IP address (the last label
// would be numeric) and a single-label name like "localhost", neither of which
// any CA will certify — and a request for one is not a harmless no-op. Let's
// Encrypt allows five FAILED VALIDATIONS per hostname per hour, a budget
// arm_ssl_retry.sh is built around conserving, so a job that cannot possibly
// succeed still spends something the next, correct attempt needs. Refusing it
// here costs nothing and spends nothing.
//
// It also excludes a wildcard: "*" is not in the character class. HTTP-01
// cannot satisfy a wildcard, and a job asking for one would fail after burning
// exactly the budget above.
//
// The TLD alternation is what makes "alphabetic" true without being wrong. A
// plain alphabetic rule is the usual shorthand and it refuses every
// internationalised TLD, which are punycode and therefore carry digits —
// .xn--p1ai is a real TLD a real node could be on, and a node refused its
// certificate for a reason nobody could guess is worse than one that fails at
// the CA. Both alternatives still exclude a numeric last label, which is what
// keeps a bare IP address out.
var certificateDomainPattern = regexp.MustCompile(
	`^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)$`)

// --- What the plane must do, and what it must not ----------------------------
//
// BARE METAL ONLY. This is a contract the node cannot enforce and the plane can.
// On a container node the agent runs INSIDE the container (install_agent.sh runs
// from _plugin_installers_start.sh at container start), while Apache, certbot
// and /etc/letsencrypt live on the HOST — which is why every certbot step in the
// SSH job carried on_host => $is_docker. Dispatching this to a container node
// does not simply fail: certbot could install and issue INSIDE the container,
// writing /etc/letsencrypt to a filesystem the next rebuild discards, while
// spending one of the five certificates per domain per week that Let's Encrypt
// allows. A wrong dispatch is therefore worse than no dispatch, and it is
// recoverable only by waiting out a rate limit.
//
// The node cannot refuse it on its own: "am I in a container" has only heuristic
// answers (/.dockerenv, /proc/1/cgroup), and a heuristic that misfires would
// refuse certificates on legitimate machines. The plane already holds the
// non-heuristic answer in mgn_container_name. So the gate belongs there, and
// this comment is here because a contract nobody wrote down is a contract
// somebody breaks.
//
// The Docker-host half of provision_ssl stays blocked on host identity:
// ManagedHost carries only SSH connection columns, with no key, fingerprint or
// pairing, so there is no agent to dispatch a host primitive to. That is a Step
// 3 blocker — the release that destroys the shared SSH key is the release after
// which Docker-node certificate provisioning has no executor at all.
//
// THE PROTO PATCH DOES NOT APPLY HERE, and this is why no site name crosses.
// The SSH job's third step rewrote X-Forwarded-Proto from "http" to "https" in
// /etc/apache2/sites-enabled/{SITE}-proxy-le-ssl.conf, which is what put the
// site name back in the sentence as a path fragment. It is a Docker-host
// concern: only default_proxy_vhost.conf SETS that header, and a bare-metal node
// has no proxy vhost — its own default_virtualhost.conf only reads the header in
// a RewriteCond. The SSH step already treated a missing conf as informational on
// bare metal. So the step is not migrated, and the parameter it would have
// needed does not exist.
//
// SUCCESS IS NOT THE EXIT CODE, again. setup_ssl.sh returns 0 whether it issued
// a certificate, failed HTTP-01 and then DNS-01, or found no challenge path at
// all: provision_origin_cert ends `return 0` on every branch by design, so that
// a site without a certificate stays on HTTP rather than failing an install.
// Only a broken Apache config makes the script exit non-zero. The output is the
// record — "Issued LE certificate for X" versus "No origin cert issued for X" —
// and it reaches the result in full.
//
// The right verification is not a step inside this primitive. It is to ask the
// node afterwards, with an observe primitive, whether the certificate is there:
// that is a question about the node's state rather than about this job's exit
// code, and it is equally true whether the certificate arrived from here, from
// arm_ssl_retry.sh's timer, or from an operator at a keyboard. The SSH
// check_status job already collected exactly that (SSL_CERT_FOUND with an expiry
// date, or SSL_CERT_MISSING); the agent's check_status collector does not
// yet, and adding it there retires the old job's fourth step properly.
