package primitives

import (
	"regexp"
	"time"
)

// remove_site_certificate: remove one site's HTTPS certificate from this
// machine once no enabled Apache site uses it — the Let's Encrypt lineage
// through certbot delete, and the placeholder directory install.sh mints
// beside it.
//
// Why it exists: removing a site took its vhost and left its certificate, so
// certbot kept renewing a domain that had moved to another server, failing
// every time, and the host kept reporting a certificate for a site that was
// gone. remove_account.sh now removes the certificates its vhost named; this
// word removes one that a removal before that left behind.
//
// A SCRIPT WORD: maintenance_scripts/sysadmin_tools/remove_site_certificate.sh,
// verified against the signed release manifest (on a Docker host, the
// support bundle's), with one argv element.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Remove a certificate no enabled site serves with. Nothing on the machine
// stops working, and a certificate is issued again by asking for it.
// Accepted.
//
// What it cannot do:
//
//   - Remove a certificate anything on the machine uses. The script refuses,
//     touching nothing, while any file Apache loads or could enable names the
//     lineage or the placeholder directory, while any other file under /etc
//     names either (a mail server, another web server), while Apache's
//     configuration does not load, and while the machine serves the
//     certificate on 443 for its domain. Deleting one an unguarded vhost
//     names would stop Apache reloading for every site on the machine.
//     Nothing is moved aside to test: a run that died mid-test would strand
//     a live certificate where nobody can reach it as root.
//   - Name a path. `name` is a DNS name with certbot's optional -NNNN suffix;
//     every path is composed in the script from compiled-in roots.
//   - Issue, renew, read or print a certificate or key. It prints which parts
//     it removed.
func init() {
	Register(Primitive{
		Name:        "remove_site_certificate",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Remove one HTTPS certificate (its Let's Encrypt lineage and placeholder) that nothing on this machine uses or serves.",
		Params: []ParamSpec{
			{Name: "name", Type: ParamString, Required: true, MaxLen: 253, Pattern: removeSiteCertificateName},
		},

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  removeSiteCertificateScript,
			Args:        []string{"{name}"},
			StdinFrom:   nil,
		},

		Timeout: 4 * time.Minute,
	})
}

// removeSiteCertificateName is a certificate name: a DNS name, as certbot
// names a lineage, with its optional -NNNN suffix. The script re-checks it.
var removeSiteCertificateName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+(-[0-9]{4})?$`)

const removeSiteCertificateScript = "maintenance_scripts/sysadmin_tools/remove_site_certificate.sh"
