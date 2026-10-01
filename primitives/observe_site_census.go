package primitives

// site_census: count what this site holds (specs/site_copy.md WP3, step 5).
//
// Rows in every table, files, directories and bytes under each top-level
// directory of the site, and whether its sealed secrets open, as one CENSUS=
// line. Run on a source and on its copy, the management node compares the two
// (SiteCensus::compare): informational while the source is live, exact at the
// final copy with the source frozen. The same check verifies any restore.
//
// IT INVOKES THE NODE'S OWN SHIPPED SCRIPT, as recovery_key_report does. What
// is counted and what each machine keeps as its own (its config, its ledger,
// its logs) is one list, in SiteCensus.php; a Go copy would be a second list
// that drifts from the first, and a census that counts something the other
// side left out reports a copy as broken, or one that leaves out too much
// reports a broken copy as whole.
//
// OBSERVE: it reads and writes nothing. So it runs on any site in any state,
// a dormant copy and a frozen source included (quietAllows passes every
// observe word), which is where it is needed.
//
// No parameters: the plane cannot point it at a directory or a database, or
// ask it to leave anything out.
//
// Redact stays off: the per-directory digests are hex runs the redactor masks,
// and a masked digest compares equal to any other masked digest, which would
// hide a renamed file or two size changes that cancel.

import "time"

func init() {
	Register(Primitive{
		Name:        "site_census",
		Class:       ClassObserve,
		Description: "Count this site's table rows, files and sealed secrets, for checking a copy against its source.",
		Params:      nil,
		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",
			ScriptPath:  "maintenance_scripts/sysadmin_tools/site_census.php",
			Args:        []string{},
		},
		// A count of every row and every directory entry; about a second on the
		// development site. Under the plane's default claim budget (900 s).
		Timeout: 10 * time.Minute,
	})
}
