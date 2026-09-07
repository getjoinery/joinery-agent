package primitives

import (
	"encoding/json"
	"regexp"
	"time"
)

// hosted_plan_notice: tell this site's admins where its hosting stands.
//
// A site somebody else runs and pays for carries five settings nothing local
// edits — the billing state, the date the current state runs to, a sentence the
// operator wants read, how much of each allowance is used, and where the owner
// manages it. HostedPlanNotice renders that banner from them, and an EMPTY
// state renders nothing at all, which is what keeps every self-hosted install
// silent.
//
// THE FIVE SETTING NAMES ARE COMPILED INTO THE NODE-SIDE SCRIPT, NOT SENT. The
// same shape as managed_domain_notice, whose comment carries the full argument.
// The short version: a primitive that took a name and a value would hand
// whatever is on the other end of this channel every row in stg_settings.
//
// WHAT THIS ONE MAY SAY IS DELIBERATELY INERT. Every value here renders as text
// on an admin page. The worst a compromised plane achieves through it is a
// misleading sentence about somebody's billing — which is why the mail
// credentials are NOT here but in hosted_mail_settings, and why the general
// settings writer that briefly carried both was removed rather than gated.
//
// STATE IS AN ENUM OVER THE BILLING STATES PLUS EMPTY. Sending suspension and a
// paused backup shelf are not among them: they are independent of whether the
// customer is paying, and folding them in would lose one fact to say the other.
// They arrive as the notice sentence.
func init() {
	Register(Primitive{
		Name:        "hosted_plan_notice",
		Class:       ClassOperate,
		Description: "Set this site's hosting-banner facts (five fixed settings; the names are not on the wire).",
		Params: []ParamSpec{
			// Where the hosting stands. Empty is a real value and is what
			// returns a box to silence.
			{Name: "state", Type: ParamEnum, Values: []string{
				"trial", "subscribed", "grace", "shutdown", "",
			}},

			// The date the current state runs to. The shape the platform
			// stores and the banner counts down to.
			{Name: "until_time", Type: ParamString, MaxLen: 32, Pattern: hostedPlanTimePattern},

			// One sentence for the site's admins. Printable text on one line:
			// it is rendered escaped, and a line break here is the start of a
			// second sentence nobody wrote.
			{Name: "notice", Type: ParamString, MaxLen: 1024, Pattern: hostedPlanTextPattern},

			// The allowances, as a JSON list the notice parses and drops
			// anything malformed out of. Bounded in length; its CONTENT is the
			// node's to distrust, and HostedPlanNotice::allowances() does.
			{Name: "allowances", Type: ParamString, MaxLen: 2048, Pattern: hostedPlanTextPattern},

			// Where the owner manages their hosting. https only — a link this
			// platform renders on a customer's admin page must not be able to
			// arrive as javascript: or plain http.
			{Name: "manage_url", Type: ParamString, MaxLen: 512, Pattern: hostedPlanURLPattern},
		},
		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",
			ScriptPath:  hostedPlanNoticeScript,
			Args:        nil,
			StdinFrom:   hostedPlanNoticePayload,
		},
		Timeout: 1 * time.Minute,
	})
}

// hostedPlanNoticeScript owns the five setting names.
const hostedPlanNoticeScript = "public_html/utils/hosted_plan_notice.php"

var (
	// A stored UTC timestamp: a date, optionally with a time.
	hostedPlanTimePattern = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}( \d{2}:\d{2}:\d{2})?)?$`)
	// Printable text on one line. No control characters, no newline.
	hostedPlanTextPattern = regexp.MustCompile(`^[^\x00-\x1f\x7f]*$`)
	// The one value that becomes a live link.
	hostedPlanURLPattern = regexp.MustCompile(`^(https://[A-Za-z0-9.\-/_]+)?$`)
)

// hostedPlanNoticePayload renders the five values as one object. Every key is
// emitted even when absent, so a value the plane stopped sending is CLEARED —
// which is what retires a trial countdown once the trial is over, and what
// returns a box to silence when its hosting ends.
func hostedPlanNoticePayload(params Params) (string, error) {
	body, err := json.Marshal(map[string]string{
		"state":      params.String("state"),
		"until_time": params.String("until_time"),
		"notice":     params.String("notice"),
		"allowances": params.String("allowances"),
		"manage_url": params.String("manage_url"),
	})
	if err != nil {
		return "", err
	}
	return string(body), nil
}
