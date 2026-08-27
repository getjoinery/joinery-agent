package primitives

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// check_status is the migration's first primitive, and it is an observe one on
// purpose: it proves the channel harmlessly (§6, Phase 2 ordering).
//
// It answers the same questions the SSH path answered with eight shell steps
// and the management API answers in PHP, and it does so without running a
// single command — disk comes from statfs, memory and load and uptime from
// /proc, and the Joinery version and database list from the node's own
// database. The result keys are exactly the ones the management API's stats
// endpoint returns, so a node reached over this channel and a node reached over
// the API leave mgn_last_status_data looking identical.
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
