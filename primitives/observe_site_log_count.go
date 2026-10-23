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
// the site's error log since a given time, read back through the rotations as
// far as that time — and how far back the read actually reached.
//
// site_log answers "what are the last lines"; a check after an upgrade asks
// "did this appear between then and now", and on a busy site the last 200
// lines no longer reach "then". This word answers the second question whole,
// or says plainly that it could not: covers_since is false, with the reason,
// whenever the oldest line it read is newer than `since`.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word? On a
// node whose owner has left log access on: learn how many times each compiled
// marker appeared in the error log in a window, and read at most
// siteLogCountSamples redacted lines per marker, each cut to
// siteLogCountSampleBytes. That is narrower than site_log, which hands over 200
// lines of whatever the log holds.
//
// What it cannot do:
//
//   - Name a file or a pattern. The file is the site's error log and its
//     numbered rotations (error.log, error.log.1, error.log.N.gz), paths
//     compiled here. The markers are compiled here; there is no grep, no
//     regular expression and no free text from the wire.
//
//   - Read without the owner's leave. RequiresLogAccess: the switch is
//     checked before anything is opened.
//
//   - Exhaust the machine. At most siteLogCountMaxFiles files and
//     siteLogCountMaxBytes bytes (after decompression) are read, streamed a
//     line at a time; the read stops at the first rotation older than `since`.
//     Hitting either cap ends the read with covers_since false.
//
//   - Change anything. Opens and reads; no process is started.
func init() {
	Register(Primitive{
		Name:        "site_log_count",
		Class:       ClassObserve,
		Description: "How many times each known problem marker (missing serve.php, PHP fatal, CRITICAL, undefined column, permission denied, open transaction, GET write) appears in the site's error log since a time, read back through its rotations, with how far back the read reached; refused unless the site's owner allows log access.",
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

// siteLogMarkers is the closed list, in the order they are reported.
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

// lineTime reads the time at the start of an Apache error log line. ok is
// false for a line that does not start with one (a continuation line).
func lineTime(line string, loc *time.Location) (time.Time, bool) {
	if !strings.HasPrefix(line, "[") {
		return time.Time{}, false
	}
	end := strings.IndexByte(line, ']')
	if end < 0 || end > 40 {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation(apacheTimeLayout, line[1:end], loc)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// siteLogCountPaths lists the error log and its rotations, newest first:
// error.log, error.log.1, error.log.2.gz ... Compiled names only.
func siteLogCountPaths(siteRoot string) []string {
	dir := filepath.Join(siteRoot, "logs")
	paths := []string{filepath.Join(dir, "error.log"), filepath.Join(dir, "error.log.1")}
	for i := 2; len(paths) < siteLogCountMaxFiles; i++ {
		paths = append(paths, filepath.Join(dir, fmt.Sprintf("error.log.%d.gz", i)))
	}
	return paths
}

type markerTally struct {
	Count   int
	First   time.Time
	Last    time.Time
	Samples []string
}

func runSiteLogCount(ctx context.Context, env *ExecEnv, p Params) (map[string]interface{}, error) {
	return siteLogCount(ctx, env, time.Unix(p.Int("since"), 0), time.Local)
}

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
	var oldest time.Time
	var bytesRead int64
	linesInWindow := 0
	filesRead := []string{}
	notCovered := ""

	// Newest file first. Each file is read whole; the walk stops at the first
	// file whose oldest line is at or before `since`, because everything older
	// lies outside the window.
	for _, path := range siteLogCountPaths(env.SiteRoot) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				if len(filesRead) == 0 && path == filepath.Join(env.SiteRoot, "logs", "error.log") {
					continue // no current file yet: the rotation may still answer
				}
				notCovered = "no older rotation to read: " + filepath.Base(path) + " is not there"
				break
			}
			return nil, err
		}
		var r io.Reader = f
		if strings.HasSuffix(path, ".gz") {
			gz, gerr := gzip.NewReader(f)
			if gerr != nil {
				f.Close()
				notCovered = filepath.Base(path) + " could not be read: " + gerr.Error()
				break
			}
			r = gz
		}
		result["present"] = true
		filesRead = append(filesRead, filepath.Base(path))

		fileOldest, n, capped, rerr := scanSiteLog(ctx, r, since, loc, tallies, &linesInWindow, siteLogCountMaxBytes-bytesRead)
		f.Close()
		bytesRead += n
		if rerr != nil {
			return nil, rerr
		}
		if !fileOldest.IsZero() && (oldest.IsZero() || fileOldest.Before(oldest)) {
			oldest = fileOldest
		}
		if capped {
			notCovered = fmt.Sprintf("stopped at the %d-byte read cap", siteLogCountMaxBytes)
			break
		}
		if !oldest.IsZero() && !oldest.After(since) {
			break
		}
		if len(filesRead) >= siteLogCountMaxFiles {
			notCovered = fmt.Sprintf("stopped after %d files", siteLogCountMaxFiles)
			break
		}
	}

	covers := !oldest.IsZero() && !oldest.After(since)
	if !result["present"].(bool) {
		notCovered = "the site has no error log"
	} else if !covers && notCovered == "" {
		notCovered = "the oldest line read is after since"
	}
	if covers {
		notCovered = ""
	}
	result["covers_since"] = covers
	if !oldest.IsZero() {
		result["covered_from"] = oldest.UTC().Format(time.RFC3339)
	}
	result["not_covered"] = notCovered
	result["files_read"] = filesRead
	result["bytes_read"] = bytesRead
	result["lines_in_window"] = linesInWindow

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

// scanSiteLog streams one file, tallying the marker lines at or after since. A
// line with no time of its own takes the time of the line before it. Returns
// the file's oldest time, the bytes read, and whether the byte budget ran out.
func scanSiteLog(ctx context.Context, r io.Reader, since time.Time, loc *time.Location, tallies map[string]*markerTally, inWindow *int, budget int64) (time.Time, int64, bool, error) {
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
			if t, ok := lineTime(line, loc); ok {
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
