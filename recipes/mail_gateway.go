package recipes

import (
	"context"
	"encoding/json"
	"fmt"
)

// The mail apps gateway (the mail_apps plugin's joinery-mail-gateway): while a
// site on this machine has mail apps turned on, the gateway runs and greets a
// mail program on 993 and 465 under that site's mail name; otherwise restart
// it. systemd already restarts a gateway that exits; this catches the one that
// stops answering while it still runs, and one left stopped. Its certificates
// are certbot's to renew and the plane's to alarm on (plane:mail_gateway), not
// a restart's to fix.
func init() {
	Register(Recipe{
		Name:        "mail_gateway",
		Scope:       ScopeHost,
		Description: "While a site has mail apps on, the mail apps gateway runs and greets mail programs on 993 and 465; otherwise restart it.",
		MinInterval: TickInterval,
		CheckWord:   "host_report",
		RepairWord:  "restart_unit",
		NodeDerived: true,
		Check: func(ctx context.Context, env *Env) Verdict {
			result, err := env.Run(ctx, "host_report")
			return mailGatewayVerdict(result, err)
		},
		Repair: func(ctx context.Context, env *Env) (string, error) {
			result, err := env.Run(ctx, "host_report")
			if v := mailGatewayVerdict(result, err); v.Kind != Fail {
				return "", fmt.Errorf("nothing to restart: %s", v.Reason)
			}
			out, err := env.RunDerived(ctx, "restart_unit", map[string]interface{}{"unit": mailGatewayUnit})
			return restartOutcome("restart_unit", mailGatewayUnit, out, err)
		},
	})
}

// mailGatewayUnit is the one unit this recipe restarts: a constant, so the
// repair's value is never read from the report.
const mailGatewayUnit = "joinery-mail-gateway"

// mailGatewayVerdict reads host_report's mail_gateway: Pass where it is not
// installed or no site has mail apps on; Fail where one has and the unit is
// not running, or a site's IMAP or submission does not greet.
func mailGatewayVerdict(result map[string]interface{}, err error) Verdict {
	r, bad := readHostReport(result, err)
	if bad != nil {
		return *bad
	}
	if len(r.MailGateway) == 0 {
		return Verdict{Unknown, "host_report does not report the mail gateway"}
	}
	var none string
	if json.Unmarshal(r.MailGateway, &none) == nil {
		if none == "none" {
			return Verdict{Pass, "no mail gateway on this machine"}
		}
		return Verdict{Unknown, "the mail gateway's state could not be read"}
	}
	var g struct {
		State string `json:"state"`
		Sites []struct {
			Site       string `json:"site"`
			Name       string `json:"name"`
			Imap       string `json:"imap"`
			Submission string `json:"submission"`
		} `json:"sites"`
	}
	if json.Unmarshal(r.MailGateway, &g) != nil {
		return Verdict{Unknown, "the mail gateway's state is not what it should be"}
	}
	if len(g.Sites) == 0 {
		return Verdict{Pass, "no site on this machine has mail apps on"}
	}
	if g.State != "active" && g.State != "unknown" {
		return Verdict{Fail, fmt.Sprintf("%s is %s while %d site(s) have mail apps on", mailGatewayUnit, orUnknown(g.State), len(g.Sites))}
	}
	for _, s := range g.Sites {
		name := s.Name
		if name == "" {
			name = s.Site
		}
		if s.Imap == "no_answer" {
			return Verdict{Fail, mailGatewayUnit + " runs and does not greet IMAP (993) for " + name}
		}
		if s.Submission == "no_answer" {
			return Verdict{Fail, mailGatewayUnit + " runs and does not greet submission (465) for " + name}
		}
	}
	return Verdict{Pass, fmt.Sprintf("the mail gateway answers for %d site(s)", len(g.Sites))}
}
