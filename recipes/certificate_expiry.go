package recipes

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Recipe certificate_expiry: every name this site serves has a certificate
// with at least 14 days left (specs/agent_recipes_and_vocabulary.md, Settled
// 2026-09-23).
//
// certbot renews at 30 days on its own timer, so fewer than 14 left means that
// timer has failed. The check is host_report's `served_certificates`: the
// certificate each of the site vhost's own names is handed over this
// machine's own connection. The repair is provision_certificate for the name
// with the fewest days left, by re-issuing the vhost's ServerName (the name
// host_report marks primary); the domain is one host_report read out of this
// node's own vhost file (rule 10, NodeDerived), and provision_certificate
// re-validates it against its own pattern. Verify is the check again: the
// served certificate, read a second time.
//
// Hourly: a certificate does not age by the ten minutes, and each repair is
// an ACME order against a rate-limited authority.
const certificateMinDays = 14

func init() {
	Register(Recipe{
		Name:        "certificate_expiry",
		Scope:       ScopeHost,
		Description: "Every name this site serves has a certificate with at least 14 days left; otherwise re-issue the one with the fewest.",
		MinInterval: time.Hour,
		CheckWord:   "host_report",
		RepairWord:  "provision_certificate",
		NodeDerived: true,
		Check: func(ctx context.Context, env *Env) Verdict {
			result, err := env.Run(ctx, "host_report")
			v, _ := certificateVerdict(result, err)
			return v
		},
		Repair: func(ctx context.Context, env *Env) (string, error) {
			result, err := env.Run(ctx, "host_report")
			v, domain := certificateVerdict(result, err)
			if v.Kind != Fail || domain == "" {
				return "", fmt.Errorf("nothing to renew: %s", v.Reason)
			}
			out, err := env.RunDerived(ctx, "provision_certificate", map[string]interface{}{"domain": domain})
			if err != nil {
				// A non-zero exit arrives here, with the transcript beside it.
				return "", fmt.Errorf("provision_certificate %s: %v (%s)", domain, err, lastLine(fmt.Sprint(out["output"])))
			}
			return "provision_certificate " + domain + ": " + lastLine(fmt.Sprint(out["output"])), nil
		},
	})
}

func certificateVerdict(result map[string]interface{}, err error) (Verdict, string) {
	r, bad := readHostReport(result, err)
	if bad != nil {
		return *bad, ""
	}
	if len(r.Served) == 0 {
		return Verdict{Unknown, "host_report does not report served certificates"}, ""
	}
	var list []struct {
		Domain   string `json:"domain"`
		DaysLeft int    `json:"days_left"`
		Primary  bool   `json:"primary"`
	}
	if json.Unmarshal(r.Served, &list) != nil {
		return Verdict{Unknown, "served certificates could not be read"}, ""
	}
	if len(list) == 0 {
		return Verdict{Pass, "this machine serves no certificate for a name of its own"}, ""
	}
	worst := list[0]
	for _, c := range list[1:] {
		if c.DaysLeft < worst.DaysLeft {
			worst = c
		}
	}
	if worst.DaysLeft < certificateMinDays {
		// The repair always re-issues the vhost's ServerName (review B15): an
		// alias the certbot vhost does not carry is served the default
		// vhost's certificate, and ordering a certificate for it alone
		// makes a lineage nothing references. No ServerName on the list
		// (a report from before it was marked) is not a repairable fail.
		primary := ""
		for _, c := range list {
			if c.Primary {
				primary = c.Domain
			}
		}
		reason := fmt.Sprintf("%s serves a certificate with %d day(s) left", worst.Domain, worst.DaysLeft)
		if primary == "" {
			return Verdict{Unknown, reason + "; the report does not say which name is the site's own, so nothing is renewed"}, ""
		}
		return Verdict{Fail, reason + "; renewing " + primary}, primary
	}
	return Verdict{Pass, fmt.Sprintf("%d name(s) served; the soonest, %s, has %d days left", len(list), worst.Domain, worst.DaysLeft)}, ""
}
