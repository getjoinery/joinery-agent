package primitives

import (
	"context"
	"regexp"
	"time"
)

// web_workers: is the web tier out of workers, now and over the last day?
//
// The word specs/slow_request_diagnosis_words.md WP3 asked for. Whether
// Apache or PHP-FPM had a free worker when a request hung could only be
// inferred, from a request sent straight at the machine answering quickly at
// the same moment.
//
// A SCRIPT WORD. What runs is maintenance_scripts/sysadmin_tools/web_workers.sh,
// verified against the signed release manifest before it runs as root. It
// reads two status pages the site vhost answers to local callers only
// (default_virtualhost.conf 2.10: mod_status's /server-status?auto and
// PHP-FPM's /fpm-status?json from its own status listener), the pool's
// configured ceiling, and how often PHP-FPM's log says the ceiling was hit.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word?
// Learn worker counts: how loaded the site is, not what it serves.
//
// What it cannot do:
//
//   - Point anywhere. NO PARAMETERS. Its one argument is the site's own
//     domain, which ArgsFrom takes from the node's own config
//     (ExecEnv.SiteDomain), never from the wire, and only when it is a host
//     name; the script asks only that name, pinned to loopback.
//   - Read a request. ?auto and ?json carry counts; the script never asks for
//     ?full, which lists each worker's request URI and query string (rule 8),
//     and passes on only named numeric fields.
//   - Open anything. Both status pages already exist and stay Require local;
//     the word adds no listener.
//   - Change anything. Two loopback GETs and two file reads.
//
// Where it runs: wherever the site's PHP runs. A site container's agent
// answers for its own Apache and PHP-FPM, which is the site's; a host's agent
// answers for the host's own site. On a machine with no site the script says
// apache and fpm are not reported.
//
// No owner switch: no log text and no content leave the machine (the FPM log
// is counted, never sent). Not redacted: every value is a number or a name
// reduced to a safe set.
func init() {
	Register(Primitive{
		Name:        "web_workers",
		Class:       ClassObserve,
		Machine:     true,
		Description: "Whether the web tier is out of workers: Apache's scoreboard and PHP-FPM's pool (active, idle, listen queue, max children reached, its configured ceiling) read over loopback, and how often the ceiling was hit in the last day; counts only.",

		// Empty on purpose. See the review above.
		Params: nil,

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  webWorkersScript,
			ArgsFrom:    webWorkersArgs,
			StdinFrom:   nil,
			Redact:      false,
		},

		// Two loopback GETs the script bounds at eight seconds each, tried
		// over https and then http, and two small file reads.
		Timeout: 1 * time.Minute,
	})
}

// webWorkersScript is the shipped reader, site-root relative.
const webWorkersScript = "maintenance_scripts/sysadmin_tools/web_workers.sh"

var webWorkersDomain = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// webWorkersArgs passes the site's own domain, read from its config, and
// nothing when the machine has none or the name is not a host name.
func webWorkersArgs(ctx context.Context, env *ExecEnv, params Params) ([]string, error) {
	if env == nil || !webWorkersDomain.MatchString(env.SiteDomain) {
		return []string{}, nil
	}
	return []string{env.SiteDomain}, nil
}
