package primitives

import (
	"strings"
	"testing"
)

// check_status carries the site's recorded plugin checks as plugin_checks. The
// site writes the record; the agent only decides whether it is a record at all.
func TestParsePluginFleetReport(t *testing.T) {
	good := `{"checked":"2026-09-22 18:00:00","checks":[{"plugin":"mailbox","key":"search_index_storage","label":"x","state":"unmet","reason":"1 copy"}]}`
	report, ok := parsePluginFleetReport(good)
	if !ok {
		t.Fatal("a well-formed record was refused")
	}
	checks, _ := report["checks"].([]interface{})
	if len(checks) != 1 {
		t.Fatalf("want one check, got %d", len(checks))
	}
	first, _ := checks[0].(map[string]interface{})
	if first["state"] != "unmet" || first["key"] != "search_index_storage" {
		t.Fatalf("the check did not survive intact: %v", first)
	}
	if report["checked"] != "2026-09-22 18:00:00" {
		t.Fatalf("the checked time did not survive: %v", report["checked"])
	}

	empty, ok := parsePluginFleetReport(`{"checked":"2026-09-22 18:00:00","checks":[]}`)
	if !ok || len(empty["checks"].([]interface{})) != 0 {
		t.Fatal("a record with no checks is still a record")
	}

	for name, raw := range map[string]string{
		"empty":      "",
		"not json":   "{nope",
		"no checks":  `{"checked":"x"}`,
		"checks map": `{"checks":{"a":1}}`,
		"array root": `[1,2]`,
		"oversized":  `{"checks":[],"pad":"` + strings.Repeat("a", pluginFleetReportMax) + `"}`,
	} {
		if _, ok := parsePluginFleetReport(raw); ok {
			t.Errorf("%s: accepted, want refused", name)
		}
	}
}
