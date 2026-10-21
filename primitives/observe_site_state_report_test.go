package primitives

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// site_state_report: every site state directory's entries, the plain records'
// values, never a secret's, never through a link.

func stateReportFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := SiteStateDir
	SiteStateDir = dir
	t.Cleanup(func() { SiteStateDir = old })
	return dir
}

func writeStateFixture(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func runStateReport(t *testing.T, env *ExecEnv) (map[string]interface{}, string) {
	t.Helper()
	out, err := runSiteStateReport(context.Background(), env, Params{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return out, string(raw)
}

// stateEntries is one site's entries by name.
func stateEntries(t *testing.T, out map[string]interface{}, site string) map[string]map[string]interface{} {
	t.Helper()
	for _, s := range out["sites"].([]interface{}) {
		m := s.(map[string]interface{})
		if m["site"] != site {
			continue
		}
		byName := map[string]map[string]interface{}{}
		for _, e := range m["entries"].([]interface{}) {
			em := e.(map[string]interface{})
			byName[em["name"].(string)] = em
		}
		return byName
	}
	t.Fatalf("no site %q in the report", site)
	return nil
}

func TestSiteStateReportIsAnObserveWordWithNoParameters(t *testing.T) {
	p := mustLookup(t, "site_state_report")
	if p.Class != ClassObserve || p.Params != nil || p.Script != nil || p.Run == nil || !p.Machine {
		t.Fatalf("site_state_report: class %v, params %v, script %v, machine %v", p.Class, p.Params, p.Script, p.Machine)
	}
}

func TestSiteStateReportNamesADormantCopysRecordsAndReadsOnlyThePlainOnes(t *testing.T) {
	dir := stateReportFixture(t)
	site := filepath.Join(dir, "src3")
	const secret = "s3cr3tLookValue0123456789abcdef"
	writeStateFixture(t, filepath.Join(site, "state"), "quiet copy\n", 0o644)
	writeStateFixture(t, filepath.Join(site, "copy_of"), "37\n", 0o644)
	writeStateFixture(t, filepath.Join(site, "copy_of_key"), "AAAAkeyAAAAkeyAAAAkeyAAAAkeyAAAAkeyAAAAkey0=\n", 0o644)
	writeStateFixture(t, filepath.Join(site, "look_secret"), secret+"\n", 0o600)
	writeStateFixture(t, filepath.Join(site, "vouched"), strings.Repeat("a", 64)+" chain-20261020_040000\n", 0o600)
	writeStateFixture(t, filepath.Join(site, "held", "cron.d", "joinery-src3"), "* * * * * root true\n", 0o644)
	writeStateFixture(t, filepath.Join(dir, ".networks.lock"), "", 0o600)

	out, raw := runStateReport(t, &ExecEnv{SiteRoot: "/var/www/html/src3"})

	reading := out["reading"].(map[string]interface{})
	if reading["site"] != "src3" || reading["reason"] != "copy" || reading["copy_of"] != int64(37) {
		t.Fatalf("the agent's reading: %v", reading)
	}
	if out["exists"] != true || out["truncated"] != false {
		t.Fatalf("exists %v, truncated %v", out["exists"], out["truncated"])
	}
	if n := len(out["sites"].([]interface{})); n != 1 {
		t.Fatalf("%d sites reported; the network lock is not a site: %s", n, raw)
	}
	e := stateEntries(t, out, "src3")
	if e["state"]["value"] != "quiet copy" || e["copy_of"]["value"] != "37" {
		t.Fatalf("plain records' values: state %v, copy_of %v", e["state"], e["copy_of"])
	}
	for _, name := range []string{"look_secret", "copy_of_key", "vouched"} {
		if e[name] == nil || e[name]["kind"] != "file" || e[name]["bytes"] == nil {
			t.Fatalf("%s should be named and sized: %v", name, e[name])
		}
		if _, ok := e[name]["value"]; ok {
			t.Fatalf("%s's content was read: %v", name, e[name])
		}
	}
	if e["look_secret"]["mode"] != "0600" {
		t.Fatalf("look_secret mode: %v", e["look_secret"]["mode"])
	}
	for _, name := range []string{"held", "held/cron.d", "held/cron.d/joinery-src3"} {
		if e[name] == nil {
			t.Fatalf("%s missing from the walk: %s", name, raw)
		}
	}
	if e["held"]["kind"] != "dir" {
		t.Fatalf("held kind: %v", e["held"]["kind"])
	}
	if strings.Contains(raw, secret) || strings.Contains(raw, "keyAAAA") || strings.Contains(raw, "root true") {
		t.Fatalf("a record's content reached the report: %s", raw)
	}
}

func TestSiteStateReportShowsACopyOfLeftWithoutAState(t *testing.T) {
	dir := stateReportFixture(t)
	writeStateFixture(t, filepath.Join(dir, "src3", "copy_of"), "37\n", 0o644)

	out, _ := runStateReport(t, &ExecEnv{SiteRoot: "/var/www/html/src3"})
	reading := out["reading"].(map[string]interface{})
	if reading["reason"] != "" {
		t.Fatalf("no state file reads as live: %v", reading)
	}
	if e := stateEntries(t, out, "src3"); e["copy_of"]["value"] != "37" {
		t.Fatalf("a leftover copy_of must be seen: %v", e)
	}
}

func TestSiteStateReportNeverFollowsALinkOrPrintsAnUnsafeValue(t *testing.T) {
	dir := stateReportFixture(t)
	site := filepath.Join(dir, "s1")
	outside := filepath.Join(t.TempDir(), "elsewhere")
	writeStateFixture(t, outside, "secret-through-a-link\n", 0o600)
	if err := os.MkdirAll(site, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(site, "state")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(site, "held")); err != nil {
		t.Fatal(err)
	}
	writeStateFixture(t, filepath.Join(site, "forward"), "1.2.3.4\"; rm -rf /\n", 0o644)
	writeStateFixture(t, filepath.Join(site, "copy_of"), strings.Repeat("9", 65)+"\n", 0o644)

	out, raw := runStateReport(t, nil)
	if _, ok := out["reading"]; ok {
		t.Fatalf("a machine with no site has no reading: %v", out["reading"])
	}
	e := stateEntries(t, out, "s1")
	if e["state"]["kind"] != "symlink" || e["held"]["kind"] != "symlink" {
		t.Fatalf("links must be reported as links: state %v, held %v", e["state"], e["held"])
	}
	if e["held/elsewhere"] != nil || strings.Contains(raw, "secret-through-a-link") {
		t.Fatalf("a link was followed: %s", raw)
	}
	if _, ok := e["forward"]["value"]; ok {
		t.Fatalf("an unsafe value was printed: %v", e["forward"])
	}
	if _, ok := e["copy_of"]["value"]; ok {
		t.Fatalf("a value longer than 64 bytes was printed: %v", e["copy_of"])
	}
}

func TestSiteStateReportIsBounded(t *testing.T) {
	dir := stateReportFixture(t)
	for i := 0; i < stateReportMaxEntries+6; i++ {
		writeStateFixture(t, filepath.Join(dir, "big", fmt.Sprintf("f%03d", i)), "x", 0o600)
	}
	writeStateFixture(t, filepath.Join(dir, "deep", "a", "b", "c", "d"), "x", 0o600)

	out, _ := runStateReport(t, nil)
	if out["truncated"] != true {
		t.Fatalf("the entry cap must say it cut the answer short")
	}
	if n := len(stateEntries(t, out, "big")); n != stateReportMaxEntries {
		t.Fatalf("%d entries, cap %d", n, stateReportMaxEntries)
	}
	deep := stateEntries(t, out, "deep")
	if deep["a/b/c"] == nil || deep["a/b/c/d"] != nil {
		t.Fatalf("the walk goes three levels and no further: %v", deep)
	}
}

func TestSiteStateReportOnAMachineWithNoStateDirectory(t *testing.T) {
	old := SiteStateDir
	SiteStateDir = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { SiteStateDir = old })
	out, _ := runStateReport(t, &ExecEnv{SiteRoot: "/var/www/html/live"})
	if out["exists"] != false || len(out["sites"].([]interface{})) != 0 {
		t.Fatalf("no directory: %v", out)
	}
	if r := out["reading"].(map[string]interface{}); r["reason"] != "" {
		t.Fatalf("a live site: %v", r)
	}
}
