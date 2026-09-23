package recipes

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"joinery-agent/primitives"
)

// Recipes service_health and container_health: the services a site stands on
// ANSWER, not merely run (specs/agent_recipes_and_vocabulary.md, Settled
// 2026-09-23, Sentinel rungs 1–2).
//
// systemd already restarts a unit that crashes. What it cannot see is a unit
// that runs and does not answer, and one it has given up restarting. The check
// is host_report's `answers` (an HTTP request for the site's own name that must
// come back through PHP, and pg_isready) beside the expected units' states;
// the repair is restart_unit for the first failing service in dependency
// order — PostgreSQL, then PHP-FPM, then Apache — so a restart never lands on
// a service that was only failing because the one under it was.
//
// container_health is the same sentence for a Docker host's site containers:
// the check is host_report's `containers`, the repair restart_container.
// Two recipes rather than one because a recipe is one check word and one
// repair word (registry_test.go pins both), and a container is not a unit.
//
// Both are NodeDerived (rule 10): the unit is a name from host_report's own
// expected-units keys and the container a name from its own container list,
// both read out of the check word's answer on this machine. restart_unit and
// restart_container re-validate against their own compiled sets.
//
// The agent is not a service here: its own supervision is agent_supervision.
func init() {
	Register(Recipe{
		Name:        "service_health",
		Scope:       ScopeHost,
		Description: "PostgreSQL, PHP-FPM and Apache answer (not merely run); otherwise restart the first that does not, in that order.",
		MinInterval: TickInterval,
		CheckWord:   "host_report",
		RepairWord:  "restart_unit",
		NodeDerived: true,
		Check: func(ctx context.Context, env *Env) Verdict {
			result, err := env.Run(ctx, "host_report")
			v, _ := serviceHealthVerdict(result, err)
			return v
		},
		Repair: func(ctx context.Context, env *Env) (string, error) {
			result, err := env.Run(ctx, "host_report")
			v, unit := serviceHealthVerdict(result, err)
			if v.Kind != Fail || unit == "" {
				return "", fmt.Errorf("nothing to restart: %s", v.Reason)
			}
			out, err := env.RunDerived(ctx, "restart_unit", map[string]interface{}{"unit": unit})
			return restartOutcome("restart_unit", unit, out, err)
		},
	})
	Register(Recipe{
		Name:        "container_health",
		Scope:       ScopeHost,
		Description: "Each Joinery site container on this host is running and its site answers through PHP; otherwise restart the first that does not.",
		MinInterval: TickInterval,
		CheckWord:   "host_report",
		RepairWord:  "restart_container",
		NodeDerived: true,
		Check: func(ctx context.Context, env *Env) Verdict {
			result, err := env.Run(ctx, "host_report")
			v, _ := containerHealthVerdict(result, err)
			return v
		},
		Repair: func(ctx context.Context, env *Env) (string, error) {
			result, err := env.Run(ctx, "host_report")
			v, name := containerHealthVerdict(result, err)
			if v.Kind != Fail || name == "" {
				return "", fmt.Errorf("nothing to restart: %s", v.Reason)
			}
			out, err := env.RunDerived(ctx, "restart_container", map[string]interface{}{"name": name})
			return restartOutcome("restart_container", name, out, err)
		},
	})
}

// serviceOrder is the dependency order: a site needs its database, PHP needs
// to be up for Apache's answer to mean anything.
var serviceOrder = []string{"postgresql", "php-fpm", "apache2"}

type hostReportHealth struct {
	ExpectedUnits map[string]interface{} `json:"expected_units"`
	Answers       json.RawMessage        `json:"answers"`
	Containers    json.RawMessage        `json:"containers"`
	Served        json.RawMessage        `json:"served_certificates"`
}

func readHostReport(result map[string]interface{}, err error) (hostReportHealth, *Verdict) {
	var r hostReportHealth
	if err != nil {
		v := Verdict{Unknown, "host_report failed: " + err.Error()}
		if primitives.Refused(err) {
			v.Reason = "host_report refused: " + err.Error()
		}
		return r, &v
	}
	output, _ := result["output"].(string)
	if jerr := json.Unmarshal([]byte(strings.TrimSpace(output)), &r); jerr != nil {
		return r, &Verdict{Unknown, "host_report output is not the JSON object it should be"}
	}
	return r, nil
}

// serviceHealthVerdict reads a host_report into a verdict and, on Fail, the
// unit to restart: the first in dependency order that is failed (systemd gave
// up) or runs and does not answer. An absent unit is not this machine's
// service (a database on another host) and is skipped.
func serviceHealthVerdict(result map[string]interface{}, err error) (Verdict, string) {
	r, bad := readHostReport(result, err)
	if bad != nil {
		return *bad, ""
	}
	var answers map[string]string
	if len(r.Answers) == 0 || json.Unmarshal(r.Answers, &answers) != nil {
		// A host_report from before `answers` existed: not reported, not no.
		return Verdict{Unknown, "host_report does not say whether the services answer"}, ""
	}
	unknown := []string{}
	for _, unit := range serviceOrder {
		state, _ := r.ExpectedUnits[unit].(string)
		if state == "absent" {
			continue
		}
		if state == "failed" {
			return Verdict{Fail, unit + " is failed (systemd has given up on it)"}, unit
		}
		switch answers[unit] {
		case "no":
			return Verdict{Fail, unit + " is " + orUnknown(state) + " and does not answer"}, unit
		case "yes":
		default:
			unknown = append(unknown, unit)
		}
	}
	if len(unknown) == len(serviceOrder) {
		return Verdict{Unknown, "no service's answer could be read"}, ""
	}
	reason := "every service present answers"
	if len(unknown) > 0 {
		reason += "; unknown: " + strings.Join(unknown, ", ")
	}
	return Verdict{Pass, reason}, ""
}

// containerHealthVerdict reads host_report's containers: Pass when there are
// none or every one runs and answers, Fail naming the first that does not.
func containerHealthVerdict(result map[string]interface{}, err error) (Verdict, string) {
	r, bad := readHostReport(result, err)
	if bad != nil {
		return *bad, ""
	}
	var none string
	if len(r.Containers) == 0 {
		return Verdict{Unknown, "host_report does not list containers"}, ""
	}
	if json.Unmarshal(r.Containers, &none) == nil {
		if none == "none" {
			return Verdict{Pass, "this machine runs no containers"}, ""
		}
		return Verdict{Unknown, "the container list could not be read"}, ""
	}
	var list []struct {
		Name    string `json:"name"`
		State   string `json:"state"`
		Answers string `json:"answers"`
	}
	if json.Unmarshal(r.Containers, &list) != nil {
		return Verdict{Unknown, "the container list is not what it should be"}, ""
	}
	for _, c := range list {
		if c.State != "running" {
			return Verdict{Fail, "container " + c.Name + " is " + orUnknown(c.State)}, c.Name
		}
		if c.Answers == "no" {
			return Verdict{Fail, "container " + c.Name + " runs and its site does not answer"}, c.Name
		}
	}
	return Verdict{Pass, fmt.Sprintf("%d site container(s) running and answering", len(list))}, ""
}

// restartOutcome reads restart_unit's or restart_container's object: the
// restart must have been accepted. The loop then runs the check again.
func restartOutcome(word, target string, result map[string]interface{}, err error) (string, error) {
	if err != nil {
		if primitives.Refused(err) {
			return "", fmt.Errorf("%s %s refused: %v", word, target, err)
		}
		return "", fmt.Errorf("%s %s failed: %v", word, target, err)
	}
	output, _ := result["output"].(string)
	var obj struct {
		Restarted bool `json:"restarted"`
		Absent    bool `json:"absent"`
		After     struct {
			ActiveState string `json:"active_state"`
			State       string `json:"state"`
		} `json:"after"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(output)), &obj) != nil {
		return "", fmt.Errorf("%s %s printed no object", word, target)
	}
	if obj.Absent {
		return "", fmt.Errorf("%s: %s is not on this machine", word, target)
	}
	if !obj.Restarted {
		return "", fmt.Errorf("%s: the restart of %s was not accepted", word, target)
	}
	after := obj.After.ActiveState + obj.After.State
	return fmt.Sprintf("%s %s: restarted, now %s", word, target, orUnknown(after)), nil
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
