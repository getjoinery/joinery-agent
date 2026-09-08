package primitives

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// install_report reads verdicts off lines the installer prints on purpose.
// These pin the reader to those exact strings (the platform's
// installer_contract_test pins the scripts to the same ones), the bound on
// what is carried back, and what an absent log means.

const installFixtureFailedDns = "=== Joinery first-boot install: Tue Sep  8 20:25:53 UTC 2026 ===\n" +
	"\x1b[0;34m[INFO]\x1b[0m Mode: bare-metal\n" +
	"=== Creating the DNS record at Linode ===\n" +
	"No zone for 'example.org' in this Linode account — creating one.\n" +
	"DNS setup failed: the zone for example.org is held by another Linode account\n" +
	"\x1b[1;33m[WARN]\x1b[0m This run is not from a sudo account, so root password login is the only way in.\n" +
	"\x1b[1;33mNo SSL certificate was issued — DNS did not point here during install.\x1b[0m\n" +
	"\x1b[0;32m[OK]\x1b[0m Site is responding with HTTP 200\n" +
	"\n=== Joinery is installed ===\n" +
	"Sign in at: example.org/login\n"

func writeInstallLog(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInstallReportReadsTheVerdictsOffMarkerLines(t *testing.T) {
	dir := t.TempDir()
	log := writeInstallLog(t, dir, "stackscript.log", installFixtureFailedDns)

	r := installReportFrom([]string{log, filepath.Join(dir, "absent.log")}, filepath.Join(dir, "no-retry"), time.Now())

	if r["install"] != "finished" {
		t.Errorf("install = %v, want finished", r["install"])
	}
	if r["install_started_at"] != "Tue Sep  8 20:25:53 UTC 2026" {
		t.Errorf("install_started_at = %v", r["install_started_at"])
	}
	if r["dns"] != "failed" {
		t.Errorf("dns = %v, want failed", r["dns"])
	}
	if r["dns_detail"] != "the zone for example.org is held by another Linode account" {
		t.Errorf("dns_detail = %v", r["dns_detail"])
	}
	if r["certificate"] != "deferred" {
		t.Errorf("certificate = %v, want deferred", r["certificate"])
	}
	if r["warning_count"] != 1 {
		t.Errorf("warning_count = %v, want 1", r["warning_count"])
	}
	warnings, _ := r["warnings"].([]string)
	if len(warnings) != 1 || strings.Contains(warnings[0], "\x1b") {
		t.Errorf("warnings should be one ANSI-free line, got %#v", warnings)
	}
	if r["ssl_retry_armed"] != false {
		t.Errorf("no retry dir means not armed, got %v", r["ssl_retry_armed"])
	}

	logs := r["logs"].([]map[string]interface{})
	if len(logs) != 2 || logs[0]["present"] != true || logs[1]["present"] != false {
		t.Fatalf("logs should describe both paths, present then absent: %#v", logs)
	}
	output, _ := r["output"].(string)
	for _, want := range []string{"DNS:         failed (the zone for example.org", "Certificate: deferred", "=== Tail of "} {
		if !strings.Contains(output, want) {
			t.Errorf("output lacks %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "\x1b") {
		t.Error("output carries ANSI escapes")
	}
}

func TestInstallReportLaterMarkersWinAndWrittenDnsIsWritten(t *testing.T) {
	dir := t.TempDir()
	log := writeInstallLog(t, dir, "stackscript.log",
		"=== Joinery first-boot install: x ===\n"+
			"A record updated: example.org -> 203.0.113.5\n"+
			"[OK] Issued LE certificate for example.org (HTTP-01)\n"+
			"ERROR: could not fetch the release archive\n"+
			"Install stopped. Nothing further will run.\n")
	retry := filepath.Join(dir, "ssl-retry")
	os.MkdirAll(retry, 0755)
	os.WriteFile(filepath.Join(retry, "example.org.conf"), []byte("x"), 0600)
	os.WriteFile(filepath.Join(retry, "notes.txt"), []byte("x"), 0600)

	r := installReportFrom([]string{log}, retry, time.Now())

	if r["install"] != "failed" {
		t.Errorf("install = %v, want failed", r["install"])
	}
	if r["dns"] != "written" || r["dns_detail"] != "updated example.org -> 203.0.113.5" {
		t.Errorf("dns = %v / %v", r["dns"], r["dns_detail"])
	}
	if r["certificate"] != "issued" {
		t.Errorf("certificate = %v, want issued", r["certificate"])
	}
	if r["error_count"] != 1 {
		t.Errorf("error_count = %v, want 1", r["error_count"])
	}
	if r["ssl_retry_armed"] != true {
		t.Errorf("a .conf in the retry dir means armed")
	}
	if domains := r["ssl_retry_domains"].([]string); len(domains) != 1 || domains[0] != "example.org" {
		t.Errorf("only .conf files name domains, got %#v", domains)
	}
}

// A log written by an installer that predates the failed marker still says
// how DNS went, in the wording of the day. The reader must not call that
// "not attempted".
func TestInstallReportReadsTheOlderDnsRefusalWording(t *testing.T) {
	dir := t.TempDir()
	log := writeInstallLog(t, dir, "stackscript.log",
		"=== Joinery first-boot install: x ===\n"+
			"No zone for 'example.org' in this Linode account — creating one.\n"+
			"Linode returned HTTP 400 creating the zone — it most likely exists already but is not visible to this token.\n"+
			"=== Joinery is installed ===\n")
	r := installReportFrom([]string{log}, dir, time.Now())
	if r["dns"] != "failed" {
		t.Errorf("dns = %v, want failed", r["dns"])
	}
	if !strings.HasPrefix(r["dns_detail"].(string), "Linode returned HTTP 400 creating the zone") {
		t.Errorf("dns_detail = %v", r["dns_detail"])
	}
	// The listing refusal and the no-public-IP case are the same fact.
	for _, line := range []string{
		"Linode returned HTTP 401 listing zones — the token probably lacks the Domains Read/Write scope. Skipping DNS creation.",
		"Could not determine this instance's public IP — skipping DNS creation.",
	} {
		log := writeInstallLog(t, dir, "s2.log", "=== Joinery first-boot install: x ===\n"+line+"\n")
		r := installReportFrom([]string{log}, dir, time.Now())
		if r["dns"] != "failed" {
			t.Errorf("%q: dns = %v, want failed", line, r["dns"])
		}
	}
}

func TestInstallReportTailIsBoundedAndWhole(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("=== Joinery first-boot install: x ===\n")
	for i := 0; i < 4000; i++ {
		b.WriteString("line of installer output number 0000000000\n")
	}
	b.WriteString("=== Joinery is installed ===\n")
	log := writeInstallLog(t, dir, "stackscript.log", b.String())

	r := installReportFrom([]string{log}, dir, time.Now())

	output := r["output"].(string)
	if len(output) > installTailBytes+2048 {
		t.Errorf("output is %d bytes; the tail must stay near %d", len(output), installTailBytes)
	}
	if !strings.Contains(output, "[... earlier output omitted ...]\nline of installer output") {
		t.Error("a cut tail must start on a whole line and say it was cut")
	}
	// The verdict is read from the WHOLE file, not the tail: the start marker
	// sits far above the cut.
	if r["install_started_at"] != "x" {
		t.Errorf("verdicts must read the whole log, got started_at=%v", r["install_started_at"])
	}
	if r["install"] != "finished" {
		t.Errorf("install = %v", r["install"])
	}
}

func TestInstallReportWithNoLogSaysSo(t *testing.T) {
	dir := t.TempDir()
	r := installReportFrom([]string{filepath.Join(dir, "a.log"), filepath.Join(dir, "b.log")}, dir, time.Now())
	if r["install"] != "unknown" || r["dns"] != "unknown" {
		t.Errorf("no log means unknown, got install=%v dns=%v", r["install"], r["dns"])
	}
	if !strings.Contains(r["output"].(string), "No first-boot install log on this machine") {
		t.Errorf("output = %q", r["output"])
	}
}

func TestInstallReportIsAnObservePrimitiveWithNoParams(t *testing.T) {
	p, ok := registry["install_report"]
	if !ok {
		t.Fatal("install_report is not registered")
	}
	if p.Class != ClassObserve {
		t.Errorf("class = %v, want observe", p.Class)
	}
	if len(p.Params) != 0 {
		t.Errorf("install_report must take no parameters; a path parameter would be a disclosure primitive")
	}
}
