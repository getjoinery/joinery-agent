package primitives

import "time"

// suspended_page: show the plain "This site is suspended" page for one of
// this Docker host's sites in place of the site, or take it down again
// (specs/multi_tenant_docker_hosts.md WP8).
//
// Why it exists: suspending a site on a shared host stops its container
// (hold_container), and the host's proxy then answers its name with Apache's
// own "Service Unavailable", which says nothing about why. Whoever reported
// the site should see that it was acted on. Each site's proxy vhost carries a
// switch for a page that says so (default_proxy_vhost.conf 1.05), read when
// Apache loads its configuration; this word throws it.
//
// A SCRIPT WORD: maintenance_scripts/sysadmin_tools/suspended_page.sh,
// verified against the signed release manifest (on a Docker host, the
// support bundle's), with two argv elements: show|clear and the site name.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Put the suspended page in front of one of the host's own sites: its
// visitors see that page until clear. The site, its container and its data
// are untouched, and clear takes the page down. The same outage hold_container
// can already cause. Accepted.
//
// What it cannot do:
//
//   - Name anything but a site behind this host's proxy. `name` must match the
//     site pattern here, and the script refuses a name with no enabled proxy
//     vhost carrying the switch.
//   - Write anything but the mark /etc/joinery/sites/{site}/suspended, or do
//     anything but test Apache's configuration and reload it. A
//     configuration Apache refuses puts the mark back and reloads nothing.
//   - Read anything. It prints compiled states.
func init() {
	Register(Primitive{
		Name:        "suspended_page",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Show the 'This site is suspended' page for one of this host's sites on its proxy, in place of the site, or take it down again.",
		Params: []ParamSpec{
			{Name: "action", Type: ParamEnum, Required: true, Values: []string{"show", "clear"}},
			{Name: "name", Type: ParamString, Required: true, MaxLen: 50, Pattern: holdContainerName},
		},

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  suspendedPageScript,
			Args:        []string{"{action}", "{name}"},
			StdinFrom:   nil,
		},

		// A configuration test, a graceful reload, and up to six asks of the
		// proxy of five seconds each.
		Timeout: 2 * time.Minute,
	})
}

const suspendedPageScript = "maintenance_scripts/sysadmin_tools/suspended_page.sh"
