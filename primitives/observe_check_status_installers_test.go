package primitives

import (
	"context"
	"database/sql/driver"
	"os"
	"path/filepath"
	"testing"
)

// A plugin's installer state comes from root's record, its plugin.json and the
// request queue, read only as regular files; a plugin with no host installer
// gets no state at all.
func TestPluginInstallerStates(t *testing.T) {
	base := t.TempDir()
	old := installerRecordBase
	installerRecordBase = filepath.Join(base, "state")
	defer func() { installerRecordBase = old }()

	site := filepath.Join(base, "mysite")
	write := func(path, body string) {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	plugin := func(name, manifest string) {
		write(filepath.Join(site, "public_html", "plugins", name, "plugin.json"), manifest)
	}
	plugin("office_editor", `{"host_installer":"provisioning/install_office_editor.sh"}`)
	plugin("mailbox", `{"host_installer":"provisioning/install_email.sh"}`)
	plugin("bookings", `{"name":"bookings"}`)
	plugin("fresh", `{"host_installer":"provisioning/x.sh"}`)
	// A plugin.json the web user replaced with a link is not read.
	write(filepath.Join(base, "elsewhere.json"), `{"host_installer":"x"}`)
	os.MkdirAll(filepath.Join(site, "public_html", "plugins", "linked"), 0o755)
	os.Symlink(filepath.Join(base, "elsewhere.json"), filepath.Join(site, "public_html", "plugins", "linked", "plugin.json"))

	rec := filepath.Join(installerRecordBase, "mysite", "plugin_installers")
	write(filepath.Join(rec, "office_editor.json"), `{"outcome":"refused","exit_code":78,"finished_at":"2026-11-14T18:00:00Z","release":"0.8.610","reason":"office editor: this server has under 2 GB of memory and no swap - nothing installed.\u0007"}`)
	write(filepath.Join(rec, "mailbox.json"), `{"outcome":"ok","finished_at":"2026-11-14T17:00:00Z","release":"0.8.610"}`)
	write(filepath.Join(installerRecordBase, "mysite", "root_requests", "1-a.json"), `{"kind":"run_plugin_installer","args":{"plugin":"fresh"}}`)
	write(filepath.Join(installerRecordBase, "mysite", "root_requests", "1-b.json"), `{"kind":"something_else","args":{"plugin":"mailbox"}}`)

	plugins := []map[string]interface{}{
		{"name": "office_editor"}, {"name": "mailbox"}, {"name": "bookings"}, {"name": "fresh"}, {"name": "linked"},
	}
	addInstallerStates(site, plugins)

	oe, _ := plugins[0]["installer"].(map[string]interface{})
	if oe == nil || oe["state"] != "refused" || oe["release"] != "0.8.610" ||
		oe["reason"] != "office editor: this server has under 2 GB of memory and no swap - nothing installed." {
		t.Errorf("office_editor: %+v", oe)
	}
	mb, _ := plugins[1]["installer"].(map[string]interface{})
	if mb == nil || mb["state"] != "installed" || mb["queued"] != false {
		t.Errorf("mailbox: %+v (another kind of request does not count as queued)", mb)
	}
	if _, has := plugins[2]["installer"]; has {
		t.Error("a plugin with no host installer gets no installer state")
	}
	fr, _ := plugins[3]["installer"].(map[string]interface{})
	if fr == nil || fr["state"] != "not_run" || fr["queued"] != true {
		t.Errorf("fresh: %+v", fr)
	}
	if _, has := plugins[4]["installer"]; has {
		t.Error("a plugin.json that is a link is not read")
	}
}

// With no root directory for the site, the fixture layout under the site root
// is read, as RootState does.
func TestPluginInstallerStatesFixtureLayout(t *testing.T) {
	base := t.TempDir()
	old := installerRecordBase
	installerRecordBase = filepath.Join(base, "none")
	defer func() { installerRecordBase = old }()
	site := filepath.Join(base, "fx")
	records, queue := installerStateDirs(site)
	if records != filepath.Join(site, "cache", "plugin_installers") || queue != filepath.Join(site, "cache", "root_requests") {
		t.Errorf("fixture layout: %s %s", records, queue)
	}
}

// check_status carries the site's themes from thm_themes, as its plugins.
func TestCollectThemesReadsTheRegistry(t *testing.T) {
	cols := []string{"thm_name", "thm_version", "thm_is_active", "thm_status", "thm_kind"}
	provider := fakeDB(map[string]fakeRows{
		"FROM thm_themes": {columns: cols, rows: [][]driver.Value{
			{"default", "1.1.2", true, "active", "page"},
			{"jeremytunnell-html5", "1.0.11", false, "installed", "page"},
			{"odd<name>", nil, nil, nil, nil},
		}},
	}, nil)
	db, err := provider()
	if err != nil {
		t.Fatal(err)
	}
	got, ok := collectThemes(context.Background(), db)
	if !ok || len(got) != 3 {
		t.Fatalf("want 3 themes, got %v %v", ok, got)
	}
	if got[0]["name"] != "default" || got[0]["version"] != "1.1.2" || got[0]["active"] != true || got[0]["kind"] != "page" {
		t.Errorf("default read wrong: %v", got[0])
	}
	if got[1]["active"] != false || got[2]["name"] != "oddname" || got[2]["active"] != false || got[2]["version"] != "" {
		t.Errorf("inactive and odd rows read wrong: %v %v", got[1], got[2])
	}
}
