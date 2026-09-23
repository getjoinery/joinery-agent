package primitives

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"joinery-agent/redact"
)

// file_head {file, lines, site}: the first lines of one host configuration
// file from a compiled list, redacted on the node.
//
// specs/agent_recipes_and_vocabulary.md, First words and "Host files: what
// may be read and what may be reset". The list below IS that section's
// readable table: a file parameter is a NAME from it, never a path. Where a
// file belongs to a site, the agent builds the path from the site's slug —
// this node's own by default, or `site`, validated by the compiled pattern,
// for the per-site vhosts a Docker host keeps for its containers.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word? On
// a node whose owner has left log access on, read the host's configuration:
// which ports, which jails, which PHP limits, which mail settings. The owner
// set the line 2026-09-23: configuration is not private (rule 8). What would
// be private is a secret inside a configuration file, and two things stop it:
//
//   - The files that ARE secrets are not on the list and cannot be named:
//     the maps main.cf points at (joinery-domains.cf holds a database
//     password), OpenDKIM's keys and tables, letsencrypt/live, the agent's
//     env file, Globalvars_site.php, sudoers, crypttab, passwd, shadow, and
//     /etc/ssh. TestFileHeadNeverNamesASecret pins that no path here reaches
//     one.
//   - Every line goes through redact.Config: a line whose key names a
//     credential comes back as the key alone, whatever the separator, and a
//     secret named later in the line loses its value. Rule 2's test for each
//     file lives beside the redactor (redact/config_test.go).
//
// What it cannot do: name a path, a glob or a directory; read through a
// symlink planted in place of a listed file (the leaf is Lstat'd and must be
// a regular file - the directories above it are root's, so only root could
// plant one higher up); read more than
// fileHeadMaxLines lines or fileHeadMaxBytes bytes; read a file the switch has
// not allowed (RequiresLogAccess); or change anything.
func init() {
	Register(Primitive{
		Name:        "file_head",
		Class:       ClassObserve,
		Machine:     true,
		Description: "The first lines of one host configuration file from a compiled list (fail2ban, Apache, PHP, journald, logrotate, cron, apt, docker, sysctl, mail settings), redacted on the node; refused unless the site's owner allows log access.",
		Params: []ParamSpec{
			{Name: "file", Type: ParamEnum, Required: true, Values: fileHeadNames()},
			{Name: "lines", Type: ParamInt, Min: 1, Max: fileHeadMaxLines},
			{Name: "site", Type: ParamString, MaxLen: 50, Pattern: fileHeadSite},
		},
		RequiresLogAccess: true,
		Run:               runFileHead,
		Timeout:           1 * time.Minute,
	})
}

// fileHeadFile is one row of the readable table. Path may carry {site}, which
// the agent fills from the validated slug, or {php}, which it fills from the
// PHP version installed here.
type fileHeadFile struct {
	Path string
	// EffectiveOnly drops full-line comments and blank lines: php.ini is two
	// thousand lines, most of them documentation, and its first hundred say
	// nothing about the limits that were set.
	EffectiveOnly bool
}

var fileHeadFiles = map[string]fileHeadFile{
	"fail2ban_jail_local":     {Path: "/etc/fail2ban/jail.local"},
	"fail2ban_joinery_sshd":   {Path: "/etc/fail2ban/jail.d/joinery-sshd.local"},
	"fail2ban_joinery_apache": {Path: "/etc/fail2ban/jail.d/joinery-apache.local"},
	"apache_site":             {Path: "/etc/apache2/sites-available/{site}.conf"},
	"apache_site_ssl":         {Path: "/etc/apache2/sites-available/{site}-le-ssl.conf"},
	"apache2_conf":            {Path: "/etc/apache2/apache2.conf"},
	"apache_mpm_event":        {Path: "/etc/apache2/mods-available/mpm_event.conf"},
	"apache_remoteip":         {Path: "/etc/apache2/conf-available/joinery-remoteip.conf"},
	"php_fpm_ini":             {Path: "/etc/php/{php}/fpm/php.ini", EffectiveOnly: true},
	"journald_size_limit":     {Path: "/etc/systemd/journald.conf.d/size-limit.conf"},
	"logrotate_site":          {Path: "/etc/logrotate.d/joinery-{site}"},
	"cron_site":               {Path: "/etc/cron.d/joinery-{site}"},
	"cron_agent":              {Path: "/etc/cron.d/joinery-agent"},
	"cron_certbot":            {Path: "/etc/cron.d/certbot"},
	"apt_auto_upgrades":       {Path: "/etc/apt/apt.conf.d/20auto-upgrades"},
	"apt_unattended_upgrades": {Path: "/etc/apt/apt.conf.d/50unattended-upgrades"},
	"docker_daemon":           {Path: "/etc/docker/daemon.json"},
	"sysctl_security":         {Path: "/etc/sysctl.d/99-security.conf"},
	"postfix_main":            {Path: "/etc/postfix/main.cf"},
	"postfix_master":          {Path: "/etc/postfix/master.cf"},
	"opendkim_conf":           {Path: "/etc/opendkim.conf"},
	"opendmarc_conf":          {Path: "/etc/opendmarc.conf"},
	"rspamd_actions":          {Path: "/etc/rspamd/local.d/actions.conf"},
	"rspamd_classifier_bayes": {Path: "/etc/rspamd/local.d/classifier-bayes.conf"},
	"rspamd_milter_headers":   {Path: "/etc/rspamd/local.d/milter_headers.conf"},
	"rspamd_redis":            {Path: "/etc/rspamd/local.d/redis.conf"},
	"rspamd_worker_proxy":     {Path: "/etc/rspamd/local.d/worker-proxy.inc"},
}

func fileHeadNames() []string {
	out := make([]string, 0, len(fileHeadFiles))
	for name := range fileHeadFiles {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

const (
	fileHeadMaxLines     = 400
	fileHeadDefaultLines = 200
	fileHeadMaxBytes     = 48 * 1024
	fileHeadMaxLineBytes = 512
)

var fileHeadSite = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,49}$`)

// fileHeadRoot prefixes every path; "/" on a machine, a fixture in a test.
var fileHeadRoot = "/"

// phpVersionDir is a directory under /etc/php that is a version.
var phpVersionDir = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)

// installedPHP is the highest PHP version with an FPM php.ini here, or "".
func installedPHP() string {
	matches, _ := filepath.Glob(filepath.Join(fileHeadRoot, "etc/php/*/fpm/php.ini"))
	best, bestMajor, bestMinor := "", -1, -1
	for _, m := range matches {
		v := filepath.Base(filepath.Dir(filepath.Dir(m)))
		if !phpVersionDir.MatchString(v) {
			continue
		}
		parts := strings.SplitN(v, ".", 2)
		major, _ := strconv.Atoi(parts[0])
		minor, _ := strconv.Atoi(parts[1])
		if major > bestMajor || (major == bestMajor && minor > bestMinor) {
			best, bestMajor, bestMinor = v, major, minor
		}
	}
	return best
}

// fileHeadPath resolves a listed name to its path on this machine. It
// returns "" with a refusal when a placeholder cannot be filled.
func fileHeadPath(env *ExecEnv, name string, p Params) (string, error) {
	f := fileHeadFiles[name]
	path := f.Path
	if strings.Contains(path, "{site}") {
		site := p.String("site")
		if site == "" && env != nil && env.SiteRoot != "" {
			site = filepath.Base(env.SiteRoot)
		}
		if !fileHeadSite.MatchString(site) {
			return "", refusedf("file_head: %s belongs to a site; name one (a machine with no site of its own has no default)", name)
		}
		path = strings.ReplaceAll(path, "{site}", site)
	}
	if strings.Contains(path, "{php}") {
		v := installedPHP()
		if v == "" {
			// Absent, not guessed: the resolved path simply does not exist.
			v = "none"
		}
		path = strings.ReplaceAll(path, "{php}", v)
	}
	return filepath.Join(fileHeadRoot, path), nil
}

func runFileHead(ctx context.Context, env *ExecEnv, p Params) (map[string]interface{}, error) {
	name := p.String("file")
	lines := int(p.Int("lines"))
	if !p.Has("lines") {
		lines = fileHeadDefaultLines
	}
	path, err := fileHeadPath(env, name, p)
	if err != nil {
		return nil, err
	}
	result := map[string]interface{}{
		"file":           name,
		"path":           strings.TrimPrefix(path, strings.TrimSuffix(fileHeadRoot, "/")),
		"present":        false,
		"size_bytes":     int64(0),
		"modified_time":  "",
		"lines_returned": 0,
		"truncated":      false,
		"text":           "",
	}

	// The resolved path must be the listed path: a symlink planted in place
	// of a listed file would otherwise turn a name into any path.
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return result, nil
		}
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, refusedf("file_head: %s is not a regular file here (a link or a directory is never followed)", result["path"])
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	result["present"] = true
	result["size_bytes"] = info.Size()
	result["modified_time"] = info.ModTime().UTC().Format(time.RFC3339)

	var out strings.Builder
	kept, read := 0, 0
	truncated := false
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		read += len(sc.Bytes()) + 1
		line := sc.Text()
		if fileHeadFiles[name].EffectiveOnly {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, ";") || strings.HasPrefix(t, "#") {
				continue
			}
		}
		if kept >= lines || out.Len() >= fileHeadMaxBytes {
			truncated = true
			break
		}
		if len(line) > fileHeadMaxLineBytes {
			line = line[:fileHeadMaxLineBytes]
		}
		out.WriteString(redact.Config(line))
		out.WriteByte('\n')
		kept++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	result["lines_returned"] = kept
	result["truncated"] = truncated
	result["text"] = out.String()
	return result, nil
}
