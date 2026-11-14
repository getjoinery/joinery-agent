package primitives

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"joinery-agent/redact"
)

// What each plugin's host installer did here, for check_status's plugin rows
// (specs/agent_recipes_and_vocabulary.md, 2026-11-14: office_editor's New >
// Document never showed, and "active" said nothing about whether the plugin's
// machine half was installed).
//
// The installer runner (_plugin_installers_start.sh) leaves one record per
// plugin on every run, in root's directory for the site,
// /var/lib/joinery/sites/{site}/plugin_installers/{plugin}.json, or the
// fixture layout's {site root}/cache/plugin_installers (RootState). The
// Plugins page reads the same record (PluginInstallerStatus). This reads it,
// the plugin's own plugin.json for whether it declares a host_installer, and
// the request queue for a run_plugin_installer request still waiting.
//
// HOSTILE-CALLER REVIEW: check_status takes no parameters, so nothing here is
// chosen by the plane. Every path is built from the site root and a plugin
// name the site's own registry gave, held to the plugin-name pattern. Files
// are read only when they are regular files (never through a link the web
// user planted: plugin.json and the queue are the web user's), each capped.
// The reason is the installer's own last line of output, redacted on the node
// and cut to 240 characters.

// installerRecordBase is root's state directory for every site; a test points
// it at a scratch directory.
var installerRecordBase = "/var/lib/joinery/sites"

var pluginNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,49}$`)
var siteDirNamePattern = regexp.MustCompile(`(?i)^[a-z0-9][a-z0-9_.-]{0,63}$`)

const installerFileMax = 256 * 1024

// installerStateDirs are the record directory and the request queue for the
// site, as RootState lays them out.
func installerStateDirs(siteRoot string) (records, queue string) {
	root := strings.TrimRight(siteRoot, "/")
	name := filepath.Base(root)
	if siteDirNamePattern.MatchString(name) {
		dir := filepath.Join(installerRecordBase, name)
		if fi, err := os.Lstat(dir); err == nil && fi.IsDir() {
			return filepath.Join(dir, "plugin_installers"), filepath.Join(dir, "root_requests")
		}
	}
	return filepath.Join(root, "cache", "plugin_installers"), filepath.Join(root, "cache", "root_requests")
}

// readRegular reads a regular file, never a link, up to installerFileMax.
func readRegular(path string) ([]byte, bool) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > installerFileMax {
		return nil, false
	}
	b, err := os.ReadFile(path)
	return b, err == nil
}

// declaresHostInstaller reads the plugin's plugin.json in the site's tree.
func declaresHostInstaller(siteRoot, plugin string) bool {
	b, ok := readRegular(filepath.Join(siteRoot, "public_html", "plugins", plugin, "plugin.json"))
	if !ok {
		return false
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	s, _ := m["host_installer"].(string)
	return strings.TrimSpace(s) != ""
}

// queuedInstallerRequests is the set of plugins a waiting run_plugin_installer
// request names.
func queuedInstallerRequests(queue string) map[string]bool {
	out := map[string]bool{}
	entries, err := os.ReadDir(queue)
	if err != nil {
		return out
	}
	for i, e := range entries {
		if i >= 200 {
			break
		}
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, ok := readRegular(filepath.Join(queue, e.Name()))
		if !ok {
			continue
		}
		var r struct {
			Kind string `json:"kind"`
			Args struct {
				Plugin string `json:"plugin"`
			} `json:"args"`
		}
		if json.Unmarshal(b, &r) == nil && r.Kind == "run_plugin_installer" && pluginNamePattern.MatchString(r.Args.Plugin) {
			out[r.Args.Plugin] = true
		}
	}
	return out
}

// installerOutcomeStates maps the runner's outcome words to the state
// check_status reports.
var installerOutcomeStates = map[string]string{
	"ok":                "installed",
	"refused":           "refused",
	"failed":            "failed",
	"refused-untrusted": "refused_untrusted",
	"refused-unsigned":  "refused_unsigned",
	"missing":           "missing",
	"inactive":          "inactive",
}

// pluginInstallerState is one plugin's installer state, or nil for a plugin
// that declares no host installer.
func pluginInstallerState(siteRoot, records string, queued map[string]bool, plugin string) map[string]interface{} {
	if !pluginNamePattern.MatchString(plugin) || !declaresHostInstaller(siteRoot, plugin) {
		return nil
	}
	out := map[string]interface{}{"state": "not_run", "reason": "", "finished_at": "", "release": "", "queued": queued[plugin]}
	b, ok := readRegular(filepath.Join(records, plugin+".json"))
	if ok {
		var rec struct {
			Outcome    string `json:"outcome"`
			FinishedAt string `json:"finished_at"`
			Release    string `json:"release"`
			Reason     string `json:"reason"`
		}
		if json.Unmarshal(b, &rec) == nil && rec.Outcome != "" {
			state, known := installerOutcomeStates[rec.Outcome]
			if !known {
				state = "other"
			}
			out["state"] = state
			out["finished_at"] = safeWord(rec.FinishedAt, 25)
			out["release"] = safeWord(rec.Release, 32)
			out["reason"] = installerReason(rec.Reason)
		}
	}
	return out
}

// installerReason is the installer's last line, redacted, printable only,
// capped.
func installerReason(s string) string {
	s = redact.Text(s)
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		}
		if b.Len() >= 240 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// addInstallerStates gives each plugin row its installer state, where the
// plugin declares a host installer.
func addInstallerStates(siteRoot string, plugins []map[string]interface{}) {
	if siteRoot == "" {
		return
	}
	records, queue := installerStateDirs(siteRoot)
	queued := queuedInstallerRequests(queue)
	for _, p := range plugins {
		name, _ := p["name"].(string)
		if st := pluginInstallerState(siteRoot, records, queued, name); st != nil {
			p["installer"] = st
		}
	}
}
