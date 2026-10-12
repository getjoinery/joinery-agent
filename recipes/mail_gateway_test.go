package recipes

import (
	"errors"
	"testing"
)

func TestMailGatewayVerdicts(t *testing.T) {
	site := func(imap, submission string) string {
		return `{"site":"shop","name":"mail.shop.example","imap":"` + imap + `","submission":"` + submission + `","days_left":60}`
	}
	cases := []struct {
		name, json string
		kind       Kind
	}{
		{"not installed", `{"mail_gateway":"none"}`, Pass},
		{"installed, no site on, stopped", `{"mail_gateway":{"state":"inactive","sites":[]}}`, Pass},
		{"running and greeting", `{"mail_gateway":{"state":"active","sites":[` + site("ok", "ok") + `]}}`, Pass},
		{"a site on and the unit stopped", `{"mail_gateway":{"state":"inactive","sites":[` + site("no_answer", "no_answer") + `]}}`, Fail},
		{"systemd gave up", `{"mail_gateway":{"state":"failed","sites":[` + site("no_answer", "no_answer") + `]}}`, Fail},
		{"runs and does not greet IMAP", `{"mail_gateway":{"state":"active","sites":[` + site("no_answer", "ok") + `]}}`, Fail},
		{"runs and does not greet submission", `{"mail_gateway":{"state":"active","sites":[` + site("ok", "no_answer") + `]}}`, Fail},
		{"an older report without the key is not reported, never failed", `{"expected_units":{}}`, Unknown},
		{"garbage", `{"mail_gateway":7}`, Unknown},
	}
	for _, c := range cases {
		v := mailGatewayVerdict(rawReport(c.json), nil)
		if v.Kind != c.kind {
			t.Errorf("%s: got %v (%s), want %v", c.name, v.Kind, v.Reason, c.kind)
		}
	}
	if v := mailGatewayVerdict(nil, errors.New("timed out")); v.Kind != Unknown {
		t.Errorf("a host_report that failed must be unknown, got %v", v.Kind)
	}
}

func TestMailGatewayRepairsOnlyItsUnit(t *testing.T) {
	if mailGatewayUnit != "joinery-mail-gateway" {
		t.Fatalf("the recipe restarts %q", mailGatewayUnit)
	}
}
