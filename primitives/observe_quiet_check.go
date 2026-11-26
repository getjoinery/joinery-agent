package primitives

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// quiet_check: is anyone busy on this machine right now?
//
// The word specs/automatic_reboot_when_quiet.md WP1 asked for. A machine that
// owes a reboot (a kernel fix waits for one) is rebooted by the management
// node's Reboot When Quiet task at the first moment this word says nobody is
// busy: no one logged in to it, no one signed in and using its site, no
// browser sending a form, no package run, installer, backup, task run or
// long database query, no mail a person sent.
//
// A SCRIPT WORD. What runs is maintenance_scripts/sysadmin_tools/quiet_check.sh,
// verified against the signed release manifest before it runs as root. A
// signal that applies and cannot be read counts as busy: quiet is proved.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word?
// Learn whether the machine is busy and roughly how busy: counts of logins,
// signed-in sessions, page views, writes and long queries in the last 15
// minutes. Not who, not what, not from where.
//
// What it cannot do:
//
//   - Point anywhere. NO PARAMETERS. Its first argument is the site root,
//     which ArgsFrom takes from the node's own config (ExecEnv.SiteRoot),
//     never from the wire, and only when it is a plain absolute path. Its
//     second is the count of long queries, which ArgsFrom reads itself over
//     the agent's own database connection with one fixed statement: a
//     number, "unknown" or "not_reported", never text from the database. The
//     window is fixed in the script.
//   - Read a request, a session, a query or a message. The script counts
//     lines and files; it passes on numbers and signal names only.
//   - Change anything. It reads logs, the session folder's file times and
//     one marker in each, the process list, two lock files without taking
//     them for longer than a try; the agent reads one count from
//     pg_stat_activity over its own connection (the site's credentials: the
//     postgres role takes a password over the local socket, so psql as
//     postgres cannot).
//
// Where it runs: anywhere. A site container's agent answers for its own site;
// a host's agent for the host and the site it serves, if any; a machine with
// no site reports the site's signals as not reported.
//
// No owner switch: no log text and no content leave the machine. Not
// redacted: every value is a number or a fixed name.
func init() {
	Register(Primitive{
		Name:        "quiet_check",
		Class:       ClassObserve,
		Machine:     true,
		Description: "Whether anyone is busy on this machine right now, for a reboot when it is quiet: logins, signed-in site sessions and browser writes in the last 15 minutes, package runs, installers, backups and task runs, long database queries, and mail a person sent; counts only, an unreadable signal counting as busy.",

		// Empty on purpose. See the review above.
		Params: nil,

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  quietCheckScript,
			ArgsFrom:    quietCheckArgs,
			StdinFrom:   nil,
			Redact:      false,
		},

		// A tail of two logs, a find over the session folder, a process list
		// and one bounded query: the script bounds each command at ten seconds.
		Timeout: 1 * time.Minute,
	})
}

// quietCheckScript is the shipped reader, site-root relative.
const quietCheckScript = "maintenance_scripts/sysadmin_tools/quiet_check.sh"

var quietCheckRoot = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,250}$`)

// quietCheckLongQuerySeconds is how long a running query must have run to
// count as work under way.
const quietCheckLongQuerySeconds = 5

// quietCheckLongQueries is one fixed statement: the client queries running
// longer than quietCheckLongQuerySeconds, other than this one.
const quietCheckLongQueries = "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend' " +
	"AND state = 'active' AND pid <> pg_backend_pid() AND now() - query_start > make_interval(secs => $1)"

// quietCheckArgs passes the site root, from the node's own config, and the
// count of long queries read over the agent's own database connection; nothing
// when the machine has no site or the path is not a plain absolute one.
func quietCheckArgs(ctx context.Context, env *ExecEnv, params Params) ([]string, error) {
	if env == nil || !quietCheckRoot.MatchString(env.SiteRoot) || strings.Contains(env.SiteRoot, "..") {
		return []string{}, nil
	}
	return []string{env.SiteRoot, quietCheckDbCount(ctx, env)}, nil
}

// quietCheckDbCount is the long-query count as the script takes it: a number,
// or "unknown" when the database cannot be asked. Unknown counts as busy.
func quietCheckDbCount(ctx context.Context, env *ExecEnv) string {
	if env.DB == nil {
		return "unknown"
	}
	db, err := env.DB()
	if err != nil || db == nil {
		return "unknown"
	}
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var n int64
	if err := db.QueryRowContext(qctx, quietCheckLongQueries, quietCheckLongQuerySeconds).Scan(&n); err != nil || n < 0 {
		return "unknown"
	}
	return strconv.FormatInt(n, 10)
}
