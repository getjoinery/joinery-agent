package recipes

import (
	"errors"
	"testing"
)

func rawReport(json string) map[string]interface{} {
	return map[string]interface{}{"output": json}
}

func TestServiceHealthVerdicts(t *testing.T) {
	cases := []struct {
		name, json string
		kind       Kind
		unit       string
	}{
		{"all answer",
			`{"expected_units":{"apache2":"active","php-fpm":"active","postgresql":"active"},"answers":{"apache2":"yes","php-fpm":"yes","postgresql":"yes"}}`,
			Pass, ""},
		{"php runs and does not answer",
			`{"expected_units":{"apache2":"active","php-fpm":"active","postgresql":"active"},"answers":{"apache2":"yes","php-fpm":"no","postgresql":"yes"}}`,
			Fail, "php-fpm"},
		{"postgres first, in dependency order",
			`{"expected_units":{"apache2":"active","php-fpm":"active","postgresql":"active"},"answers":{"apache2":"no","php-fpm":"no","postgresql":"no"}}`,
			Fail, "postgresql"},
		{"systemd gave up on apache",
			`{"expected_units":{"apache2":"failed","php-fpm":"active","postgresql":"active"},"answers":{"apache2":"no","php-fpm":"unknown","postgresql":"yes"}}`,
			Fail, "apache2"},
		{"a database on another host is not ours to restart",
			`{"expected_units":{"apache2":"active","php-fpm":"active","postgresql":"absent"},"answers":{"apache2":"yes","php-fpm":"yes","postgresql":"no"}}`,
			Pass, ""},
		{"an older report without answers is not reported, never no",
			`{"expected_units":{"apache2":"failed"}}`,
			Unknown, ""},
		{"nothing readable",
			`{"expected_units":{},"answers":{"apache2":"unknown","php-fpm":"unknown","postgresql":"unknown"}}`,
			Unknown, ""},
		{"not JSON", `garbage`, Unknown, ""},
	}
	for _, c := range cases {
		v, unit := serviceHealthVerdict(rawReport(c.json), nil)
		if v.Kind != c.kind || unit != c.unit {
			t.Errorf("%s: got %s %q (%s), want %s %q", c.name, v.Kind, unit, v.Reason, c.kind, c.unit)
		}
	}
	if v, _ := serviceHealthVerdict(nil, errors.New("boom")); v.Kind != Unknown {
		t.Error("a failed check word is unknown, never a repair")
	}
}

func TestContainerHealthVerdicts(t *testing.T) {
	cases := []struct {
		name, json string
		kind       Kind
		target     string
	}{
		{"no docker", `{"containers":"none"}`, Pass, ""},
		{"not root", `{"containers":"unknown"}`, Unknown, ""},
		{"absent key", `{}`, Unknown, ""},
		{"all good", `{"containers":[{"name":"a","state":"running","answers":"yes"},{"name":"b","state":"running","answers":"unknown"}]}`, Pass, ""},
		{"exited", `{"containers":[{"name":"a","state":"running","answers":"yes"},{"name":"b","state":"exited","answers":"no"}]}`, Fail, "b"},
		{"runs, does not answer", `{"containers":[{"name":"a","state":"running","answers":"no"}]}`, Fail, "a"},
	}
	for _, c := range cases {
		v, name := containerHealthVerdict(rawReport(c.json), nil)
		if v.Kind != c.kind || name != c.target {
			t.Errorf("%s: got %s %q (%s), want %s %q", c.name, v.Kind, name, v.Reason, c.kind, c.target)
		}
	}
}

func TestCertificateVerdicts(t *testing.T) {
	cases := []struct {
		name, json string
		kind       Kind
		domain     string
	}{
		{"healthy", `{"served_certificates":[{"domain":"a.example","days_left":80},{"domain":"www.a.example","days_left":60}]}`, Pass, ""},
		{"an alias failing renews the ServerName", `{"served_certificates":[{"domain":"a.example","days_left":80,"primary":true},{"domain":"www.a.example","days_left":3,"primary":false}]}`, Fail, "a.example"},
		{"expired", `{"served_certificates":[{"domain":"a.example","days_left":-2,"primary":true}]}`, Fail, "a.example"},
		{"no ServerName marked: not repaired", `{"served_certificates":[{"domain":"a.example","days_left":2}]}`, Unknown, ""},
		{"exactly 14 is enough", `{"served_certificates":[{"domain":"a.example","days_left":14}]}`, Pass, ""},
		{"none served", `{"served_certificates":[]}`, Pass, ""},
		{"no openssl", `{"served_certificates":"unknown"}`, Unknown, ""},
		{"older report", `{}`, Unknown, ""},
	}
	for _, c := range cases {
		v, d := certificateVerdict(rawReport(c.json), nil)
		if v.Kind != c.kind || d != c.domain {
			t.Errorf("%s: got %s %q (%s), want %s %q", c.name, v.Kind, d, v.Reason, c.kind, c.domain)
		}
	}
}

func TestRestartOutcome(t *testing.T) {
	if _, err := restartOutcome("restart_unit", "apache2", rawReport(`{"unit":"apache2.service","absent":false,"restarted":true,"after":{"active_state":"active"}}`), nil); err != nil {
		t.Errorf("an accepted restart is a repair: %v", err)
	}
	for _, bad := range []string{
		`{"unit":"x","absent":true,"restarted":false}`,
		`{"unit":"x","absent":false,"restarted":false}`,
		`nope`,
	} {
		if _, err := restartOutcome("restart_unit", "x", rawReport(bad), nil); err == nil {
			t.Errorf("%s must not count as a repair", bad)
		}
	}
}
