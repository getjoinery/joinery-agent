package primitives

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"joinery-agent/redact"
)

// site_log_count: how many times each of a compiled list of markers appears in
// the site's error log and its scheduled-task log since a given time, read back
// through the rotations as far as that time — and how far back the read
// actually reached.
//
// site_log answers "what are the last lines"; a check after an upgrade asks
// "did this appear between then and now", and on a busy site the last 200
// lines no longer reach "then". This word answers the second question whole,
// or says plainly that it could not: covers_since is false, with the reason,
// whenever the oldest line it read in either log is newer than `since`.
//
// Two logs, because PHP writes a line to whichever one its process has. A web
// request's error_log() line reaches Apache's error.log. The scheduled-task
// runner is PHP on the command line, with no error_log of its own, so its
// lines go to stderr, which the site's cron entry appends to
// cron_scheduled_tasks.log, bare and untimed between the runner's own stamped
// lines. A queued send, a scheduled DNS publish: everything that runs from
// cron is only in the second log.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word? On a
// node whose owner has left log access on: learn how many times each compiled
// marker appeared in the two logs in a window, and read at most
// siteLogCountSamples redacted lines per marker, each cut to
// siteLogCountSampleBytes. That is narrower than site_log, which hands over 200
// lines of whatever either log holds.
//
// What it cannot do:
//
//   - Name a file or a pattern. The files are the site's error log and its
//     scheduled-task log and their numbered rotations (error.log,
//     error.log.1, error.log.N.gz; the same for cron_scheduled_tasks.log),
//     paths compiled here. The markers are compiled here; there is no grep, no
//     regular expression and no free text from the wire.
//
//   - Read without the owner's leave. RequiresLogAccess: the switch is
//     checked before anything is opened.
//
//   - Exhaust the machine. At most siteLogCountMaxFiles files per log and
//     siteLogCountMaxBytes bytes in all (after decompression) are read,
//     streamed a line at a time; each log's read stops at its first rotation
//     older than `since`. Hitting either cap ends that read with covers_since
//     false.
//
//   - Change anything. Opens and reads; no process is started.
func init() {
	Register(Primitive{
		Name:        "site_log_count",
		Class:       ClassObserve,
		Description: "How many times each known problem marker (missing serve.php, PHP fatal, CRITICAL, undefined column, permission denied, open transaction, GET write, mail left unsigned, a DNS read falling back to the system resolver, a DNS record write failing) appears in the site's error log and scheduled-task log since a time, read back through their rotations, with how far back each read reached; refused unless the site's owner allows log access.",
		Params: []ParamSpec{
			// Unix seconds. The window's start; the end is now.
			{Name: "since", Type: ParamInt, Required: true, Min: 1, Max: 1 << 40},
		},
		RequiresLogAccess: true,
		Run:               runSiteLogCount,
		Timeout:           2 * time.Minute,
	})
}

// siteLogMarker is one compiled thing to count: a line counts when it holds
// every one of All.
type siteLogMarker struct {
	Name string
	All  []string
}

// siteLogMarkers is the closed list, in the order they are reported. A MIRROR
// of SITE_LOG_COUNT_MARKERS on the plane (JobCommandBuilder).
var siteLogMarkers = []siteLogMarker{
	// The request found no front controller: the code tree was being replaced.
	{"entry_script_missing", []string{"Failed opening required", "serve.php"}},
	{"primary_script_unknown", []string{"Primary script unknown"}},
	{"permission_denied", []string{"Permission denied"}},
	{"php_fatal", []string{"PHP Fatal error"}},
	{"critical", []string{`"level":"CRITICAL"`}},
	{"error_logged", []string{`"level":"ERROR"`}},
	{"undefined_column", []string{"Undefined column"}},
	{"transaction_left_open", []string{"TRANSACTION_LEFT_OPEN"}},
	{"get_write", []string{"[GET_WRITE]"}},
	{"get_mutation", []string{"[GET_MUTATION]"}},
	// MailboxDkimSigner sent a message with no DKIM signature.
	{"dkim_unsigned", []string{"MailboxDkimSigner:", "leaving UNSIGNED"}},
	// AuthoritativeDns could not read a zone cleanly and asked the system
	// resolver, a cache (FALLBACK_LOG_PREFIX).
	{"authoritative_dns_fallback", []string{"AuthoritativeDns: fallback to system resolver for "}},
	// DnsReconciler's write of one record failed (FAILURE_LOG_PREFIX).
	{"dns_reconciler_failed", []string{"DnsReconciler: record failed: "}},
}

const (
	siteLogCountMaxFiles    = 15
	siteLogCountMaxBytes    = 1 << 30
	siteLogCountSamples     = 3
	siteLogCountSampleBytes = 400
	siteLogCountMaxLine     = 1 << 20
)

// apacheTimeLayout parses the bracketed time an Apache error log line starts
// with: [Thu Oct 22 23:13:52.679400 2026]. _2 takes a padded or unpadded day.
const apacheTimeLayout = "Mon Jan _2 15:04:05.999999 2006"

// cronTimeLayout parses the bracketed time the scheduled-task runner stamps
// its own lines with: [2026-11-14 17:34:02], PHP's date() under the
// date.timezone = UTC every install sets.
const cronTimeLayout = "2006-01-02 15:04:05"

// lineTime reads the time at the start of an Apache error log line. ok is
// false for a line that does not start with one (a continuation line).
func lineTime(line string, loc *time.Location) (time.Time, bool) {
	return bracketTime(line, apacheTimeLayout, loc)
}

// cronLineTime reads the time at the start of a scheduled-task runner line. ok
// is false for a bare line some task's PHP wrote to stderr.
func cronLineTime(line string) (time.Time, bool) {
	return bracketTime(line, cronTimeLayout, time.UTC)
}

func bracketTime(line, layout string, loc *time.Location) (time.Time, bool) {
	if !strings.HasPrefix(line, "[") {
		return time.Time{}, false
	}
	end := strings.IndexByte(line, ']')
	if end < 0 || end > 40 {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation(layout, line[1:end], loc)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// logPaths lists a log and its rotations, newest first: NAME, NAME.1,
// NAME.2.gz ... Compiled names only.
func logPaths(siteRoot, name string) []string {
	dir := filepath.Join(siteRoot, "logs")
	paths := []string{filepath.Join(dir, name), filepath.Join(dir, name+".1")}
	for i := 2; len(paths) < siteLogCountMaxFiles; i++ {
		paths = append(paths, filepath.Join(dir, fmt.Sprintf("%s.%d.gz", name, i)))
	}
	return paths
}

// siteLogCountPaths lists the error log and its rotations, newest first.
func siteLogCountPaths(siteRoot string) []string {
	return logPaths(siteRoot, "error.log")
}

type markerTally struct {
	Count   int
	First   time.Time
	Last    time.Time
	Samples []string
}

// countedLog is one of the two compiled logs: its reported name, its file
// name, and how a line's own time is read.
type countedLog struct {
	Name  string
	File  string
	Times func(string) (time.Time, bool)
}

func runSiteLogCount(ctx context.Context, env *ExecEnv, p Params) (map[string]interface{}, error) {
	return siteLogCount(ctx, env, time.Unix(p.Int("since"), 0), time.Local)
}

// siteLogCount reads both logs into one set of tallies. loc is the zone the
// Apache error log is written in (the machine's own); the scheduled-task log
// is UTC. The top-level answer covers the window only when both logs do; logs
// says which one did not, and why.
func siteLogCount(ctx context.Context, env *ExecEnv, since time.Time, loc *time.Location) (map[string]interface{}, error) {
	result := map[string]interface{}{
		"file":            "error",
		"since":           since.UTC().Format(time.RFC3339),
		"present":         false,
		"covers_since":    false,
		"covered_from":    "",
		"not_covered":     "",
		"files_read":      []string{},
		"bytes_read":      int64(0),
		"lines_in_window": 0,
		"logs":            map[string]interface{}{},
		"markers":         map[string]interface{}{},
	}
	if env == nil || env.SiteRoot == "" {
		result["not_covered"] = "no site on this machine"
		return result, nil
	}

	tallies := map[string]*markerTally{}
	for _, m := range siteLogMarkers {
		tallies[m.Name] = &markerTally{}
	}
	logs := []countedLog{
		{Name: "error", File: "error.log", Times: func(l string) (time.Time, bool) { return lineTime(l, loc) }},
		{Name: "cron_scheduled_tasks", File: "cron_scheduled_tasks.log", Times: cronLineTime},
	}

	var bytesRead int64
	linesInWindow := 0
	filesRead := []string{}
	perLog := map[string]interface{}{}
	allCover := true
	anyPresent := false
	errorPresent := false
	var coveredFrom time.Time
	reasons := []string{}

	for _, lg := range logs {
		one, err := countOneLog(ctx, env.SiteRoot, lg, since, tallies, &linesInWindow, &bytesRead)
		if err != nil {
			return nil, err
		}
		perLog[lg.Name] = map[string]interface{}{
			"present":      one.present,
			"covers_since": one.covers,
			"covered_from": formatTime(one.oldest),
			"not_covered":  one.notCovered,
			"files_read":   one.files,
		}
		filesRead = append(filesRead, one.files...)
		if one.present {
			anyPresent = true
			if lg.Name == "error" {
				errorPresent = true
			}
		}
		// A site with no scheduled-task log has run nothing from cron: there
		// is no line to miss. A missing error log is still reported, as
		// before.
		if !one.covers && (one.present || lg.Name == "error") {
			allCover = false
			if one.notCovered != "" {
				reasons = append(reasons, lg.File+": "+one.notCovered)
			}
		}
		if one.present && !one.oldest.IsZero() && (coveredFrom.IsZero() || one.oldest.After(coveredFrom)) {
			coveredFrom = one.oldest
		}
	}

	result["present"] = errorPresent || anyPresent
	result["covers_since"] = allCover && errorPresent
	result["covered_from"] = formatTime(coveredFrom)
	if !errorPresent && !anyPresent {
		result["not_covered"] = "the site has no error log"
	} else if !(allCover && errorPresent) {
		result["not_covered"] = strings.Join(reasons, "; ")
	}
	result["files_read"] = filesRead
	result["bytes_read"] = bytesRead
	result["lines_in_window"] = linesInWindow
	result["logs"] = perLog

	markers := map[string]interface{}{}
	for _, m := range siteLogMarkers {
		t := tallies[m.Name]
		entry := map[string]interface{}{"count": t.Count, "first": "", "last": "", "samples": t.Samples}
		if t.Samples == nil {
			entry["samples"] = []string{}
		}
		if t.Count > 0 {
			entry["first"] = t.First.UTC().Format(time.RFC3339)
			entry["last"] = t.Last.UTC().Format(time.RFC3339)
		}
		markers[m.Name] = entry
	}
	result["markers"] = markers
	return result, nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

type oneLogRead struct {
	present    bool
	covers     bool
	oldest     time.Time
	notCovered string
	files      []string
}

// countOneLog walks one log newest file first. Each file is read whole; the
// walk stops at the first file whose oldest line is at or before `since`,
// because everything older lies outside the window. bytesRead is shared, so
// the byte cap covers both logs together.
func countOneLog(ctx context.Context, siteRoot string, lg countedLog, since time.Time,
	tallies map[string]*markerTally, inWindow *int, bytesRead *int64) (oneLogRead, error) {
	out := oneLogRead{files: []string{}}
	current := filepath.Join(siteRoot, "logs", lg.File)
	for _, path := range logPaths(siteRoot, lg.File) {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		// logs/ is the web user's: only a regular file, never through a link
		// (openPlainFile).
		f, err := openPlainFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				if len(out.files) == 0 && path == current {
					continue // no current file yet: the rotation may still answer
				}
				if out.present {
					out.notCovered = "no older rotation to read: " + filepath.Base(path) + " is not there"
				}
				break
			}
			return out, err
		}
		var r io.Reader = f
		if strings.HasSuffix(path, ".gz") {
			gz, gerr := gzip.NewReader(f)
			if gerr != nil {
				f.Close()
				out.notCovered = filepath.Base(path) + " could not be read: " + gerr.Error()
				break
			}
			r = gz
		}
		out.present = true
		out.files = append(out.files, filepath.Base(path))

		fileOldest, n, capped, rerr := scanSiteLog(ctx, r, since, lg.Times, tallies, inWindow, siteLogCountMaxBytes-*bytesRead)
		f.Close()
		*bytesRead += n
		if rerr != nil {
			return out, rerr
		}
		if !fileOldest.IsZero() && (out.oldest.IsZero() || fileOldest.Before(out.oldest)) {
			out.oldest = fileOldest
		}
		if capped {
			out.notCovered = fmt.Sprintf("stopped at the %d-byte read cap", siteLogCountMaxBytes)
			break
		}
		if !out.oldest.IsZero() && !out.oldest.After(since) {
			break
		}
		if len(out.files) >= siteLogCountMaxFiles {
			out.notCovered = fmt.Sprintf("stopped after %d files", siteLogCountMaxFiles)
			break
		}
	}
	out.covers = !out.oldest.IsZero() && !out.oldest.After(since)
	if !out.present {
		out.notCovered = "not there"
	} else if out.covers {
		out.notCovered = ""
	} else if out.notCovered == "" {
		out.notCovered = "the oldest line read is after since"
	}
	return out, nil
}

// scanSiteLog streams one file, tallying the marker lines at or after since. A
// line with no time of its own takes the time of the line before it. Returns
// the file's oldest time, the bytes read, and whether the byte budget ran out.
func scanSiteLog(ctx context.Context, r io.Reader, since time.Time, times func(string) (time.Time, bool), tallies map[string]*markerTally, inWindow *int, budget int64) (time.Time, int64, bool, error) {
	br := bufio.NewReaderSize(r, 64*1024)
	var oldest, current time.Time
	var n int64
	lines := 0
	for {
		line, err := br.ReadString('\n')
		n += int64(len(line))
		if len(line) > 0 {
			if len(line) > siteLogCountMaxLine {
				line = line[:siteLogCountMaxLine]
			}
			if t, ok := times(line); ok {
				current = t
				if oldest.IsZero() {
					oldest = t
				}
			}
			if !current.IsZero() && !current.Before(since) {
				*inWindow++
				for _, m := range siteLogMarkers {
					if lineHasAll(line, m.All) {
						tallyLine(tallies[m.Name], current, line)
					}
				}
			}
		}
		if n >= budget {
			return oldest, n, true, nil
		}
		if err == io.EOF {
			return oldest, n, false, nil
		}
		if err != nil {
			return oldest, n, false, err
		}
		lines++
		if lines%4096 == 0 {
			if cerr := ctx.Err(); cerr != nil {
				return oldest, n, false, cerr
			}
		}
	}
}

func lineHasAll(line string, all []string) bool {
	for _, s := range all {
		if !strings.Contains(line, s) {
			return false
		}
	}
	return true
}

func tallyLine(t *markerTally, at time.Time, line string) {
	t.Count++
	if t.First.IsZero() || at.Before(t.First) {
		t.First = at
	}
	if at.After(t.Last) {
		t.Last = at
	}
	if len(t.Samples) < siteLogCountSamples {
		s := strings.TrimRight(line, "\n")
		if len(s) > siteLogCountSampleBytes {
			s = s[:siteLogCountSampleBytes]
		}
		t.Samples = append(t.Samples, redact.Text(s))
	}
}
