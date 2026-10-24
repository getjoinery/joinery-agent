package primitives

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"joinery-agent/redact"
)

// site_log: the last lines of one of the site's own log files, redacted on this
// machine before they leave it (specs/agent_log_access.md §2.1).
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word? Read,
// on a node whose owner has left the switch on, the last 200 lines of one of
// five site logs, with credential values, the personal half of email
// addresses, IP literals and opaque tokens already masked. That is the
// "redacted log excerpts" cell of the accepted-limits table
// (implemented/agent_on_node_architecture.md §3.7), no wider.
//
// What it cannot do:
//
//   - Name a file. `file` is an ENUM of seven names compiled here. Six resolve
//     to SiteRoot/logs/<name>.log; postgresql resolves to the newest cluster
//     log in /var/log/postgresql, a directory and a glob both compiled here.
//     `previous` selects a file's most recent rotation (.log.1) and nothing
//     else. There is no path parameter, no wire-supplied glob, no way to reach
//     a compressed rotation, a config file, or anything outside those two
//     places.
//
//     The database log is the widest thing on this list and is named as such:
//     PostgreSQL logs errors, and an error line can carry the statement that
//     failed and the values bound to it. That is the same grade of exposure as
//     the site's own error log, which has been on this list since it began —
//     both are behind the owner's switch, both are redacted on this machine,
//     and both are capped. It earns its place because a disk that fills, a
//     connection that dies and a write that is refused are all the database
//     saying so in its own words, and nothing else on this node records them.
//
//     The access log is the one file NOT returned as it is written. Its lines
//     carry every visitor's address, the page they came from, their browser,
//     and whole request targets, and a target can carry a token in its query
//     string or in its path: /s/{token} is a Drive share link whose token is
//     the capability (specs/slow_request_diagnosis_words.md WP1a). So each
//     line is parsed on this machine and rebuilt as a compiled shape: time,
//     method, path, status, bytes, duration. Address, Referer, user agent and
//     query string are dropped. Each path segment outside a compiled safe
//     shape (letters, digits, - _ ., at most 64 characters) or that looks like a token (20 or more characters with letters and two digits) becomes <cut>,
//     and everything after /s/ is cut whatever it looks like. The redactor
//     then runs over the rebuilt lines as it does over every other file. A
//     line that does not parse is counted, never carried.
//
//   - Read without the owner's leave. The switch is checked FIRST, before a
//     stat: off means the pinned refusal and nothing read. The rule is
//     log_access.go's and is not repeated here.
//
//   - Flood the plane. At most 200 lines and 32 KiB before redaction, cut to a
//     line boundary; the framework's 64 KiB cap sits above it as a backstop.
//
//   - Learn who a member is. The redactor runs on the tail before it is
//     returned; addresses never leave the node. (Free-text redaction masks
//     shapes, not names — stated in the spec and on the owner's switch.)
//
//   - Change anything. One stat and one bounded read; no process is started.
//
// OBSERVE, and the classification does real work: a node whose policy accepts
// only observe words has to be able to trust that this one writes nothing.
func init() {
	Register(Primitive{
		Name:        "site_log",
		Class:       ClassObserve,
		Description: "The last lines of one of the site's own log files (error, cron, AI worker, install executor, host converger, access as a compiled shape) or of the PostgreSQL cluster log, redacted on the node; refused unless the site's owner allows log access.",
		Params: []ParamSpec{
			{Name: "file", Type: ParamEnum, Required: true, Values: siteLogFiles},
			{Name: "previous", Type: ParamBool},
			{Name: "lines", Type: ParamInt, Min: 1, Max: siteLogMaxLines},
		},
		RequiresLogAccess: true,
		Run:               runSiteLog,
		Timeout:           1 * time.Minute,
	})
}

// siteLogFiles is the closed list. All but one are SiteRoot/logs/<name>.log;
// postgresql is the exception and is resolved by siteLogPath. The access log
// is carried only as accessLogShape rebuilds it: never a visitor's address,
// never a query string, never a path segment that could be a token.
var siteLogFiles = []string{
	"access",
	"error",
	"cron_scheduled_tasks",
	"joinery_ai_worker",
	"install_executor",
	"host_converger",
	"postgresql",
}

// postgresLogDir is where a Debian or Ubuntu PostgreSQL writes, compiled in.
// The only directory this word reaches outside the site tree.
const postgresLogDir = "/var/log/postgresql"

// postgresLogPattern matches the cluster logs in that directory, and nothing
// else in it. One glob, compiled: postgresql-16-main.log, postgresql-17-main.log.
const postgresLogPattern = "postgresql-*-main.log"

const (
	siteLogMaxLines     = 200
	siteLogDefaultLines = 100
	// siteLogMaxBytes bounds what is read before redaction, cut forward to a
	// line boundary. Under the framework's 64 KiB cap with room for the
	// redactor to lengthen a line.
	siteLogMaxBytes = 32 * 1024
)

// siteLogPath resolves an enum value to the one file it may mean. The enum has
// already been validated; the name is a compiled constant, never wire text.
//
// postgresql is the one entry that does not live in the site's log directory,
// because the database does not write there: Debian and Ubuntu put the cluster
// log under /var/log/postgresql, one file per cluster. The directory and the
// glob are both compiled, the match is taken from that directory alone, and
// the newest cluster wins — so a machine running two clusters answers about
// the one in use rather than refusing. Nothing from the wire reaches either.
func siteLogPath(siteRoot, name string, previous bool) string {
	if name == "postgresql" {
		return postgresLogPath(previous)
	}
	file := name + ".log"
	if previous {
		file += ".1"
	}
	return filepath.Join(siteRoot, "logs", file)
}

// postgresLogPath picks the newest cluster log in the compiled directory, or
// returns the directory-joined pattern itself when there is none — a path that
// cannot open, which the caller reports as present: false, exactly as it
// reports a site log that is not there.
func postgresLogPath(previous bool) string {
	matches, err := filepath.Glob(filepath.Join(postgresLogDir, postgresLogPattern))
	if err != nil || len(matches) == 0 {
		return filepath.Join(postgresLogDir, postgresLogPattern)
	}
	// Sorted lexically, the highest major version is last:
	// postgresql-16-main.log before postgresql-17-main.log.
	sort.Strings(matches)
	path := matches[len(matches)-1]
	if previous {
		path += ".1"
	}
	return path
}

func runSiteLog(ctx context.Context, env *ExecEnv, p Params) (map[string]interface{}, error) {
	name := p.String("file")
	previous := p.Bool("previous")
	lines := int(p.Int("lines"))
	if !p.Has("lines") {
		lines = siteLogDefaultLines
	}

	result := map[string]interface{}{
		"file":           name,
		"previous":       previous,
		"present":        false,
		"size_bytes":     int64(0),
		"modified_time":  "",
		"lines_returned": 0,
		"truncated":      false,
		"text":           "",
	}
	if env == nil || env.SiteRoot == "" {
		return result, nil
	}

	path := siteLogPath(env.SiteRoot, name, previous)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return result, nil
		}
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	result["present"] = true
	result["size_bytes"] = info.Size()
	result["modified_time"] = info.ModTime().UTC().Format(time.RFC3339)

	text, truncatedBytes, err := tailBytes(f, info.Size(), siteLogMaxBytes)
	if err != nil {
		return nil, err
	}
	if name == "access" {
		shaped, unparsed := accessLogShape(text)
		text = shaped
		result["unparsed_lines"] = unparsed
	}
	kept, truncatedLines := lastLines(text, lines)
	result["truncated"] = truncatedBytes || truncatedLines
	result["lines_returned"] = countLines(kept)
	result["text"] = redact.Text(kept)
	return result, nil
}

// accessLogLine reads Apache's combined format and the site vhost's
// joinery_timed (combined with %D after the byte count): time, method,
// target, status, bytes and, when present, the duration in microseconds.
// Nothing after the duration (Referer, user agent) is captured.
var accessLogLine = regexp.MustCompile(`^\S+ \S+ \S+ \[([^\]]{1,40})\] "([A-Z]{1,10}) ([^" ]+)(?: [^"]*)?" ([0-9]{3}) ([0-9]+|-)(?: ([0-9]+))?(?: |$)`)

// accessPathSegment is the shape a path segment must have to be carried.
var accessPathSegment = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// accessTokenLike is a segment that could be a credential even inside the safe
// shape: 20 characters or more with letters and at least two digits, which is
// what bin2hex(random_bytes(n)) and most base64url tokens look like. Route and
// action names are words and underscores, at most one digit
// (login_2fa_passkey_verify), and survive. A token with fewer than two digits
// is what the prefix list below is for.
var accessHasLetter = regexp.MustCompile(`[A-Za-z]`)

func accessTokenLike(seg string) bool {
	return len(seg) >= 20 && accessHasLetter.MatchString(seg) && strings.Count(seg, "0")+strings.Count(seg, "1")+
		strings.Count(seg, "2")+strings.Count(seg, "3")+strings.Count(seg, "4")+strings.Count(seg, "5")+
		strings.Count(seg, "6")+strings.Count(seg, "7")+strings.Count(seg, "8")+strings.Count(seg, "9") >= 2
}

// accessLogShape rebuilds each access log line as
// "TIME METHOD PATH STATUS BYTES DURATION_US" ("-" where a field is absent),
// and counts the lines it could not parse, which are left out.
func accessLogShape(text string) (string, int) {
	var out []string
	unparsed := 0
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if line == "" {
			continue
		}
		m := accessLogLine.FindStringSubmatch(line)
		if m == nil {
			unparsed++
			continue
		}
		duration := m[6]
		if duration == "" {
			duration = "-"
		}
		out = append(out, strings.Join([]string{"[" + m[1] + "]", m[2], accessPath(m[3]), m[4], m[5], duration}, " "))
	}
	if len(out) == 0 {
		return "", unparsed
	}
	return strings.Join(out, "\n") + "\n", unparsed
}

// accessPath keeps a request target's path, without its query string, segment
// by segment: a segment outside accessPathSegment, or one that looks like a
// token (accessTokenLike), becomes <cut>, and everything after /s/ (a share
// link's capability) is cut.
//
// A route that puts a credential in its path adds its prefix here, beside
// /s/: the token heuristic is the second line of defence, not the first.
func accessPath(target string) string {
	if i := strings.IndexAny(target, "?#"); i >= 0 {
		target = target[:i]
	}
	if !strings.HasPrefix(target, "/") {
		return "<cut>"
	}
	segs := strings.Split(target[1:], "/")
	for i, seg := range segs {
		if i > 0 && segs[0] == "s" {
			segs = append(segs[:1], "<cut>")
			break
		}
		if seg != "" && (!accessPathSegment.MatchString(seg) || accessTokenLike(seg)) {
			segs[i] = "<cut>"
		}
	}
	return "/" + strings.Join(segs, "/")
}

// tailBytes reads at most max bytes from the end of f, cut forward to a line
// boundary so the first line carried is a whole one. Reports whether anything
// earlier was left behind.
func tailBytes(f io.ReaderAt, size int64, max int) (string, bool, error) {
	if size <= 0 {
		return "", false, nil
	}
	start := int64(0)
	truncated := false
	if size > int64(max) {
		start = size - int64(max)
		truncated = true
	}
	buf := make([]byte, size-start)
	n, err := f.ReadAt(buf, start)
	if err != nil && err != io.EOF {
		return "", false, err
	}
	text := string(buf[:n])
	if truncated {
		if nl := strings.IndexByte(text, '\n'); nl >= 0 && nl+1 < len(text) {
			text = text[nl+1:]
		}
	}
	return text, truncated, nil
}

// lastLines keeps the last n lines of text (a trailing newline does not count
// as an empty line). Reports whether lines were dropped.
func lastLines(text string, n int) (string, bool) {
	trimmed := strings.TrimSuffix(text, "\n")
	if trimmed == "" {
		return "", false
	}
	parts := strings.Split(trimmed, "\n")
	if len(parts) <= n {
		return text, false
	}
	return strings.Join(parts[len(parts)-n:], "\n") + "\n", true
}

func countLines(text string) int {
	trimmed := strings.TrimSuffix(text, "\n")
	if trimmed == "" {
		return 0
	}
	return strings.Count(trimmed, "\n") + 1
}
