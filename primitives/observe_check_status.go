package primitives

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// check_status is the migration's first primitive, and it is an observe one on
// purpose: it proves the channel harmlessly (§6, Phase 2 ordering).
//
// It answers the same questions the SSH path answered with eight shell steps
// and the management API answers in PHP, and it does so without running a
// single command — disk comes from statfs, memory and load and uptime from
// /proc, and the Joinery version and database list from the node's own
// database. The result keys match the management API's stats endpoint, so a node
// reached over this channel and a node reached over the API leave
// mgn_last_status_data looking the same — with ONE deliberate exception, the
// ssl_ keys below, which the API transport cannot ever produce because
// /etc/letsencrypt/live is root-only and PHP runs as the web user. That is not a
// parity bug to be closed; it is the first thing this transport can answer that
// the other structurally cannot, and pretending otherwise would mean either
// dropping a real answer or claiming the API could give it.
func init() {
	Register(Primitive{
		Name:        "check_status",
		Class:       ClassObserve,
		Description: "Disk, memory, load, uptime, PostgreSQL liveness, Joinery version, database list.",
		Params:      nil, // takes none, so any param at all is refused
		Run:         runCheckStatus,
	})
}

func runCheckStatus(ctx context.Context, env *ExecEnv, _ Params) (map[string]interface{}, error) {
	result := map[string]interface{}{}

	target := env.WebRoot
	if target == "" {
		target = env.SiteRoot
	}
	if target != "" {
		collectDisk(target, result)
	}
	collectMemory(result)
	collectLoad(result)
	collectUptime(result)
	collectCertificates(letsEncryptLiveDir, time.Now(), result)
	if env.DB != nil {
		collectDatabase(ctx, env, result)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("nothing could be collected on this node")
	}
	return result, nil
}

// collectDisk reports the filesystem holding the web root, which is what a site
// operator actually cares about — "/" can be roomy while the site's volume is full.
func collectDisk(path string, result map[string]interface{}) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(path, &fs); err != nil {
		return
	}
	blockSize := uint64(fs.Bsize)
	total := fs.Blocks * blockSize
	// Available to an unprivileged writer — what df reports as "Avail", and
	// what PHP's disk_free_space returns. Used is derived from it rather than
	// from Bfree so that used + available == total: the management API's stats
	// endpoint does the same arithmetic, and this transport promising an
	// identical key set means promising identical numbers in it. Using Bfree
	// here instead silently counts the root-reserved blocks as used, and the
	// three figures stop adding up.
	available := fs.Bavail * blockSize
	if total == 0 {
		return
	}
	used := total - available
	result["disk_usage_percent"] = int(((used * 100) + total/2) / total)
	result["disk_total"] = formatSize(total)
	result["disk_used"] = formatSize(used)
	result["disk_available"] = formatSize(available)
}

func collectMemory(result map[string]interface{}) {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}
	var totalKB, availKB int64
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			totalKB = parseMeminfoKB(line)
		case strings.HasPrefix(line, "MemAvailable:"):
			availKB = parseMeminfoKB(line)
		}
	}
	if totalKB <= 0 {
		return
	}
	totalMB := (totalKB + 512) / 1024
	freeMB := (availKB + 512) / 1024
	result["memory_total_mb"] = totalMB
	result["memory_free_mb"] = freeMB
	if used := totalMB - freeMB; used > 0 {
		result["memory_used_mb"] = used
	} else {
		result["memory_used_mb"] = int64(0)
	}
}

func parseMeminfoKB(line string) int64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	n, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func collectLoad(result map[string]interface{}) {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 3 {
		return
	}
	for i, key := range []string{"load_1m", "load_5m", "load_15m"} {
		if v, err := strconv.ParseFloat(fields[i], 64); err == nil {
			result[key] = v
		}
	}
}

func collectUptime(result map[string]interface{}) {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 1 {
		return
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || secs <= 0 {
		return
	}
	result["uptime"] = formatUptime(int64(secs))
}

// collectDatabase asks the node's own database the three questions the SSH path
// used psql for. Read-only, and every statement is a fixed literal.
func collectDatabase(ctx context.Context, env *ExecEnv, result map[string]interface{}) {
	// Resolving can fail outright now — the agent starts without a database and
	// keeps running through an outage. "Not accepting connections" is exactly
	// what the operator needs to see in that case, and it is a finding, not an
	// error: this collector's job is to report the node's health, and an
	// unreachable database IS the health report.
	db, err := env.DB()
	if err != nil || db == nil {
		result["postgres_status"] = "not accepting connections"
		return
	}

	var current string
	if err := db.QueryRowContext(ctx, "SELECT current_database()").Scan(&current); err != nil {
		result["postgres_status"] = "not accepting connections"
		return
	}
	result["postgres_status"] = "accepting connections"
	result["current_db"] = current

	rows, err := db.QueryContext(ctx,
		"SELECT datname FROM pg_database WHERE datistemplate = false AND datname NOT IN ('postgres') ORDER BY datname")
	if err == nil {
		defer rows.Close()
		var names []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err == nil {
				names = append(names, name)
			}
		}
		if len(names) > 0 {
			result["databases"] = names
		}
	}

	var version string
	if err := db.QueryRowContext(ctx,
		"SELECT stg_value FROM stg_settings WHERE stg_name = 'system_version'").Scan(&version); err == nil && version != "" {
		result["joinery_version"] = version
	}

	var cronLastRun string
	if err := db.QueryRowContext(ctx,
		"SELECT stg_value FROM stg_settings WHERE stg_name = 'scheduled_tasks_last_cron_run'").Scan(&cronLastRun); err == nil && cronLastRun != "" {
		result["cron_last_run"] = cronLastRun
	}
}

// formatSize renders bytes the way df -h does, so the fleet view reads the same
// whichever transport produced it.
func formatSize(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit && exp < 4; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(bytes)/float64(div), "KMGTP"[exp])
}

func formatUptime(seconds int64) string {
	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60
	switch {
	case days > 0:
		return fmt.Sprintf("%d days, %d hours", days, hours)
	case hours > 0:
		return fmt.Sprintf("%d hours, %d minutes", hours, minutes)
	default:
		return fmt.Sprintf("%d minutes", minutes)
	}
}

// --- TLS certificates --------------------------------------------------------

// letsEncryptLiveDir is where certbot keeps the current certificate of each
// lineage. It is the ONLY place worth looking: both shipped vhost templates
// point SSLCertificateFile at /etc/letsencrypt/live/{domain}/fullchain.pem and
// wrap the whole :443 block in <IfFile> on that exact path, so a certificate
// anywhere else is a certificate Apache is not serving.
const letsEncryptLiveDir = "/etc/letsencrypt/live"

// Bounds on what one node may report. A result travels inside a body the plane
// caps, and a node with an unusual number of lineages should return a truncated
// answer that says it was truncated rather than one the far end refuses whole.
const (
	maxReportedCertificates = 25
	maxReportedDomains      = 10
)

// collectCertificates reports every certificate this node holds, and when each
// one expires.
//
// WHY THE NODE ENUMERATES RATHER THAN BEING ASKED ABOUT A DOMAIN. The SSH step
// this replaces was handed a domain computed on the plane from mgn_site_url, and
// answered SSL_CERT_FOUND or SSL_CERT_MISSING about that one name. So it could
// only ever see what the plane already believed, and a node with a certificate
// under a lineage the plane did not name looked to it exactly like a node with
// no certificate at all. That failure has a specific shape here: certbot
// re-issuing into a fresh lineage writes {domain}-0001 and leaves the vhost
// pointing at {domain}, so a node can hold a current certificate that Apache is
// not serving and a stale one that it is. Listing the lineages is what makes
// that visible; being asked about one name is what hides it.
//
// THESE ARE FACTS, NOT A VERDICT. The node says what is on its disk and when it
// runs out. Whether the site "has SSL" is the plane's to decide, because it also
// knows about the edge — a Cloudflare-terminated site is served over HTTPS with
// no origin certificate at all, which is a healthy state this collector has no
// way to see and must not report as a problem.
//
// Symlinks are FOLLOWED here, deliberately, which is the opposite of the rule
// the probe primitives apply. The difference is direction and ownership: this
// reads, in a root-only directory, a path certbot itself maintains as a symlink
// into ../../archive. Refusing to follow it would report every certbot-managed
// certificate as missing.
func collectCertificates(dir string, now time.Time, result map[string]interface{}) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// No certbot on this machine. Zero is a real answer, and a
			// different one from "could not look".
			result["ssl_certificate_count"] = 0
		} else {
			// Root should be able to read this. Failing to is itself worth
			// reporting rather than rendering as an absence.
			result["ssl_certificates_unreadable"] = true
		}
		return
	}

	var certs []map[string]interface{}
	truncated := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if len(certs) >= maxReportedCertificates {
			truncated = true
			break
		}
		summary := summariseCertificate(filepath.Join(dir, entry.Name(), "fullchain.pem"), now)
		if summary == nil {
			continue
		}
		summary["name"] = entry.Name()
		certs = append(certs, summary)
	}

	result["ssl_certificate_count"] = len(certs)
	if truncated {
		result["ssl_certificates_truncated"] = true
	}
	if len(certs) == 0 {
		return
	}

	// Soonest first: the one that matters is the one about to lapse, and a
	// fleet view sorting on a single number is what turns "eight days left on a
	// node whose renewal timer is dead" into something anyone notices.
	sort.Slice(certs, func(i, j int) bool {
		return certs[i]["expires_in_days"].(int) < certs[j]["expires_in_days"].(int)
	})
	result["ssl_certificates"] = certs
	result["ssl_soonest_expiry"] = certs[0]["not_after"]
	result["ssl_soonest_expiry_days"] = certs[0]["expires_in_days"]
}

// summariseCertificate reads the leaf certificate of a fullchain file. It
// returns nil for anything it cannot make sense of — an empty lineage
// directory, a truncated file mid-renewal — because a node with one unreadable
// lineage should still report the others.
func summariseCertificate(path string, now time.Time) map[string]interface{} {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// The leaf is first in a fullchain; the rest is the issuer chain and says
	// nothing about when THIS site's certificate expires.
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}

	// Truncated toward zero, so the last day before expiry reads as 0 rather
	// than rounding up to a day that is not there, and an expired certificate
	// reads negative.
	days := int(cert.NotAfter.Sub(now) / (24 * time.Hour))

	summary := map[string]interface{}{
		"not_after":       cert.NotAfter.UTC().Format(time.RFC3339),
		"expires_in_days": days,
		"expired":         now.After(cert.NotAfter),
		// A self-signed placeholder is present, servable, and trusted by
		// nobody. Reported as its own fact because "a certificate exists" would
		// otherwise read as "TLS works here".
		"self_signed": bytes.Equal(cert.RawIssuer, cert.RawSubject),
	}
	if issuer := strings.TrimSpace(cert.Issuer.CommonName); issuer != "" {
		summary["issuer"] = issuer
	}
	if names := cert.DNSNames; len(names) > 0 {
		if len(names) > maxReportedDomains {
			names = names[:maxReportedDomains]
			summary["domains_truncated"] = true
		}
		// Copied rather than aliased: the slice above is a window into the
		// parsed certificate, and the result outlives it.
		summary["domains"] = append([]string(nil), names...)
	}
	return summary
}
