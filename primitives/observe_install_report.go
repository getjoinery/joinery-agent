package primitives

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// install_report: how this machine's first-boot install went, from the logs
// the install left behind.
//
// It exists because of an afternoon spent reading /var/log/stackscript.log over
// a root password. A Linode StackScript deploy had "not worked": the site was
// serving, the certificate was deferred, and the reason — the DNS zone lived
// in a Linode account the supplied token could not see — was on one line of a
// three-thousand-line log that only a shell on the box could reach. The plane
// could ask the node for its disk and memory (check_status) but not for the
// one document that says whether the install finished and why DNS or the
// certificate did not.
//
// IT ANSWERS FOR AN INSTALL THAT REACHED THIS AGENT. An install that died
// before the agent was installed, or a first-boot install on a machine nobody
// has paired yet, has no agent to ask; that log is reachable only from the
// console. What this covers is the quieter failure — an install that finished,
// serves a site, and went wrong somewhere inside — for as long as the log stays
// on disk, however long after the fact the node is paired.
//
// OBSERVE, and it runs no command: it reads a compiled-in list of files. The
// paths are not parameters, deliberately — an observe primitive that took a
// path would be "read this file for me", which is the shape of a disclosure
// primitive whatever its name. What the install wrote there is the whole
// answer; a node whose install ran some other way simply has no such file and
// says so.
//
// THE VERDICTS ARE READ OFF MARKER LINES the installer prints, and those lines
// are a contract: tests/unit/installer_contract_test.php on the platform pins
// the scripts to them, and observe_install_report_test.go pins this reader to
// the same strings. Change one side and the other's test says where.
//
// BOUNDED. The tail of each log is capped, and the whole result stays well
// inside the channel's request body cap: a log that grew unexpectedly must not
// make the report about it undeliverable.
func init() {
	Register(Primitive{
		Name:        "install_report",
		Class:       ClassObserve,
		Description: "Whether the first-boot install finished, how its DNS and certificate steps ended, and the tail of the install log.",
		Params:      nil,
		Run:         runInstallReport,
	})
}

// installLogPaths are the logs a first-boot install can leave, in the order
// they are worth reading. The Linode StackScript wrapper writes the first; a
// cloud-init driven image writes the second. A machine installed by hand from
// a shell writes neither, and the report says so rather than guessing.
var installLogPaths = []string{
	"/var/log/stackscript.log",
	"/var/log/cloud-init-output.log",
}

// sslRetryDir is where arm_ssl_retry.sh leaves one conf per domain whose
// certificate is still waiting on DNS. Existence is the armed signal; nothing
// inside the file is needed here.
const sslRetryDir = "/etc/joinery/ssl-retry"

// installTailBytes caps what is carried back per log. Enough for the closing
// summary and the steps before it, small enough that two logs and the
// verdicts fit the channel's 256 KiB request cap several times over.
const installTailBytes = 24 * 1024

// installWarningsKept bounds the warning and error line lists. A log with two
// hundred warnings has said "read the tail", not "carry them all".
const installWarningsKept = 12

// Marker lines. Each is a string the installer prints on purpose, matched
// after ANSI colour codes are stripped.
const (
	markerInstallStarted  = "=== Joinery first-boot install: "
	markerInstallFinished = "=== Joinery is installed ==="
	markerInstallStopped  = "Install stopped. Nothing further will run."
	markerDnsFailed       = "DNS setup failed: "
	markerDnsCreated      = "A record created: "
	markerDnsUpdated      = "A record updated: "
	markerDnsSkipped      = "Skipping DNS creation"
	// The two ways the DNS step reported a refusal before it printed the
	// failed marker itself. Every log written by an earlier installer has one
	// of these and nothing else, and a report that read "not attempted" off a
	// log that says "Linode returned HTTP 400 creating the zone" would be
	// wrong about the one thing it was asked. Both only ever print on failure.
	markerDnsRefused    = "Linode returned HTTP "
	markerDnsNoPublicIP = "Could not determine this instance's public IP"
	markerCertIssued    = "Issued LE certificate for "
	markerCertDeferred  = "No SSL certificate was issued"
	markerWarn          = "[WARN]"
	markerError         = "ERROR"
)

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func runInstallReport(_ context.Context, _ *ExecEnv, _ Params) (map[string]interface{}, error) {
	return installReportFrom(installLogPaths, sslRetryDir, time.Now()), nil
}

// installReportFrom is the body, with the paths as arguments so a test can
// point it at a temp tree. Every caller outside a test passes the compiled-in
// lists above; a job has no way to reach this.
func installReportFrom(logPaths []string, retryDir string, now time.Time) map[string]interface{} {
	logs := []map[string]interface{}{}
	var primary *installLog
	for _, path := range logPaths {
		entry := readInstallLog(path)
		logs = append(logs, entry.describe(now))
		if entry.present && primary == nil {
			primary = entry
		}
	}

	result := map[string]interface{}{
		"logs":            logs,
		"install":         "unknown",
		"dns":             "unknown",
		"certificate":     "unknown",
		"ssl_retry_armed": false,
	}

	if domains := armedRetryDomains(retryDir); len(domains) > 0 {
		result["ssl_retry_armed"] = true
		result["ssl_retry_domains"] = domains
	}

	if primary == nil {
		result["output"] = "No first-boot install log on this machine (" + strings.Join(logPaths, ", ") + ").\n" +
			"The site here was installed some other way, or the log has been removed.\n"
		return result
	}

	verdicts := readInstallVerdicts(primary.text)
	for k, v := range verdicts {
		result[k] = v
	}

	var summary strings.Builder
	fmt.Fprintf(&summary, "Install log: %s (%d bytes, last written %s)\n",
		primary.path, primary.size, primary.modified.UTC().Format(time.RFC3339))
	if s, ok := verdicts["install_started_at"]; ok {
		fmt.Fprintf(&summary, "Started:     %s\n", s)
	}
	fmt.Fprintf(&summary, "Install:     %s\n", verdicts["install"])
	fmt.Fprintf(&summary, "DNS:         %s\n", describeVerdict(verdicts, "dns", "dns_detail"))
	fmt.Fprintf(&summary, "Certificate: %s\n", describeVerdict(verdicts, "certificate", "certificate_detail"))
	if result["ssl_retry_armed"] == true {
		fmt.Fprintf(&summary, "Certificate retry timer: armed for %s\n",
			strings.Join(result["ssl_retry_domains"].([]string), ", "))
	}
	if warnings, ok := verdicts["warnings"].([]string); ok && len(warnings) > 0 {
		fmt.Fprintf(&summary, "Warnings (%d):\n", verdicts["warning_count"])
		for _, w := range warnings {
			fmt.Fprintf(&summary, "  %s\n", w)
		}
	}
	if errs, ok := verdicts["errors"].([]string); ok && len(errs) > 0 {
		fmt.Fprintf(&summary, "Errors (%d):\n", verdicts["error_count"])
		for _, e := range errs {
			fmt.Fprintf(&summary, "  %s\n", e)
		}
	}
	summary.WriteString("\n=== Tail of " + primary.path + " ===\n")
	summary.WriteString(primary.tail)
	result["output"] = summary.String()
	return result
}

type installLog struct {
	path     string
	present  bool
	size     int64
	modified time.Time
	text     string // the whole file, ANSI stripped, for verdicts
	tail     string // the bounded tail, ANSI stripped, for reading
	err      string
}

func readInstallLog(path string) *installLog {
	entry := &installLog{path: path}
	info, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			entry.err = err.Error()
		}
		return entry
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		entry.err = err.Error()
		return entry
	}
	entry.present = true
	entry.size = info.Size()
	entry.modified = info.ModTime()
	entry.text = ansiEscape.ReplaceAllString(string(raw), "")
	entry.tail = tailOf(entry.text, installTailBytes)
	return entry
}

func (l *installLog) describe(now time.Time) map[string]interface{} {
	out := map[string]interface{}{"path": l.path, "present": l.present}
	if l.err != "" {
		out["error"] = l.err
	}
	if l.present {
		out["size"] = l.size
		out["modified"] = l.modified.UTC().Format(time.RFC3339)
		out["age_seconds"] = int64(now.Sub(l.modified).Seconds())
	}
	return out
}

// tailOf keeps the last max bytes, cut forward to a line boundary so the first
// line carried is a whole one.
func tailOf(text string, max int) string {
	if len(text) <= max {
		return text
	}
	cut := text[len(text)-max:]
	if nl := strings.IndexByte(cut, '\n'); nl >= 0 && nl+1 < len(cut) {
		cut = cut[nl+1:]
	}
	return "[... earlier output omitted ...]\n" + cut
}

// readInstallVerdicts turns marker lines into the four facts an operator asks
// first. Later markers win over earlier ones for the same fact, so a log that
// records a retry reports the retry's outcome.
func readInstallVerdicts(text string) map[string]interface{} {
	out := map[string]interface{}{
		"install":     "running",
		"dns":         "not_attempted",
		"certificate": "unknown",
	}
	warnings := []string{}
	errors := []string{}
	warningCount, errorCount := 0, 0

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, markerInstallStarted):
			out["install_started_at"] = strings.TrimSuffix(strings.TrimPrefix(trimmed, markerInstallStarted), " ===")
		case trimmed == markerInstallFinished:
			out["install"] = "finished"
		case trimmed == markerInstallStopped:
			out["install"] = "failed"
		}

		if i := strings.Index(trimmed, markerDnsFailed); i >= 0 {
			out["dns"] = "failed"
			out["dns_detail"] = strings.TrimSpace(trimmed[i+len(markerDnsFailed):])
		} else if i := strings.Index(trimmed, markerDnsCreated); i >= 0 {
			out["dns"] = "written"
			out["dns_detail"] = "created " + strings.TrimSpace(trimmed[i+len(markerDnsCreated):])
		} else if i := strings.Index(trimmed, markerDnsUpdated); i >= 0 {
			out["dns"] = "written"
			out["dns_detail"] = "updated " + strings.TrimSpace(trimmed[i+len(markerDnsUpdated):])
		} else if strings.HasPrefix(trimmed, markerDnsRefused) || strings.HasPrefix(trimmed, markerDnsNoPublicIP) {
			// Before the skipped check: the listing refusal ends in "Skipping
			// DNS creation", and a refusal is the fact, the skip its effect.
			out["dns"] = "failed"
			out["dns_detail"] = trimmed
		} else if strings.Contains(trimmed, markerDnsSkipped) {
			out["dns"] = "skipped"
			out["dns_detail"] = trimmed
		}

		if i := strings.Index(trimmed, markerCertIssued); i >= 0 {
			out["certificate"] = "issued"
			out["certificate_detail"] = strings.TrimSpace(trimmed[i+len(markerCertIssued):])
		} else if strings.Contains(trimmed, markerCertDeferred) {
			out["certificate"] = "deferred"
			out["certificate_detail"] = strings.TrimSpace(strings.SplitN(trimmed, "—", 2)[len(strings.SplitN(trimmed, "—", 2))-1])
		}

		if strings.Contains(trimmed, markerWarn) {
			warningCount++
			if len(warnings) < installWarningsKept {
				warnings = append(warnings, strings.TrimSpace(strings.Replace(trimmed, markerWarn, "", 1)))
			}
		} else if strings.HasPrefix(trimmed, markerError) || strings.Contains(trimmed, "["+markerError+"]") {
			errorCount++
			if len(errors) < installWarningsKept {
				errors = append(errors, trimmed)
			}
		}
	}
	out["warning_count"] = warningCount
	out["error_count"] = errorCount
	if len(warnings) > 0 {
		out["warnings"] = warnings
	}
	if len(errors) > 0 {
		out["errors"] = errors
	}
	return out
}

func describeVerdict(v map[string]interface{}, key, detailKey string) string {
	s, _ := v[key].(string)
	if d, ok := v[detailKey].(string); ok && d != "" {
		return s + " (" + d + ")"
	}
	return s
}

// armedRetryDomains lists the domains whose certificate retry timer is armed:
// one <domain>.conf per domain in the retry directory. Absent directory, or
// one this process cannot read, is simply "none armed".
func armedRetryDomains(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".conf" {
			continue
		}
		out = append(out, strings.TrimSuffix(e.Name(), ".conf"))
	}
	sort.Strings(out)
	return out
}
