package primitives

import (
	"context"
	"io"
	"os"
	"path/filepath"
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
//   - Name a file. `file` is an ENUM of five names compiled here, each
//     resolved to SiteRoot/logs/<name>.log; `previous` selects that file's
//     most recent rotation (.log.1) and nothing else. There is no path
//     parameter, no glob, no way to reach a compressed rotation, a config
//     file, or anything outside the site's log directory.
//   - Read without the owner's leave. The switch is checked FIRST, before a
//     stat: off means the pinned refusal and nothing read. The rule is
//     log_access.go's and is not repeated here.
//   - Flood the plane. At most 200 lines and 32 KiB before redaction, cut to a
//     line boundary; the framework's 64 KiB cap sits above it as a backstop.
//   - Learn who a member is. The redactor runs on the tail before it is
//     returned; addresses never leave the node. (Free-text redaction masks
//     shapes, not names — stated in the spec and on the owner's switch.)
//   - Change anything. One stat and one bounded read; no process is started.
//
// OBSERVE, and the classification does real work: a node whose policy accepts
// only observe words has to be able to trust that this one writes nothing.
func init() {
	Register(Primitive{
		Name:        "site_log",
		Class:       ClassObserve,
		Description: "The last lines of one of the site's own log files (error, cron, AI worker, install executor, host converger), redacted on the node; refused unless the site's owner allows log access.",
		Params: []ParamSpec{
			{Name: "file", Type: ParamEnum, Required: true, Values: siteLogFiles},
			{Name: "previous", Type: ParamBool},
			{Name: "lines", Type: ParamInt, Min: 1, Max: siteLogMaxLines},
		},
		Run:     runSiteLog,
		Timeout: 1 * time.Minute,
	})
}

// siteLogFiles is the closed list. Each is SiteRoot/logs/<name>.log. The
// access log is deliberately absent: visitor addresses and URLs by the
// megabyte, wanted by no diagnosis on the list.
var siteLogFiles = []string{
	"error",
	"cron_scheduled_tasks",
	"joinery_ai_worker",
	"install_executor",
	"host_converger",
}

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
func siteLogPath(siteRoot, name string, previous bool) string {
	file := name + ".log"
	if previous {
		file += ".1"
	}
	return filepath.Join(siteRoot, "logs", file)
}

func runSiteLog(ctx context.Context, env *ExecEnv, p Params) (map[string]interface{}, error) {
	if err := requireLogAccess(ctx, env); err != nil {
		return nil, err
	}
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
	kept, truncatedLines := lastLines(text, lines)
	result["truncated"] = truncatedBytes || truncatedLines
	result["lines_returned"] = countLines(kept)
	result["text"] = redact.Text(kept)
	return result, nil
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
