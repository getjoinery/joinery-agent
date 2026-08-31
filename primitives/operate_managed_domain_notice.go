package primitives

import (
	"encoding/json"
	"regexp"
	"time"
)

// managed_domain_notice: tell this node the facts behind the take-ownership
// notice its owner sees.
//
// A deployment whose domain was bought for it at checkout carries four settings
// nothing local edits — the domain, when the registration runs out, where its
// custody currently sits, and where to go to take it over. While the name sits
// in the operator's registrar account its renewal bills the OPERATOR, and the
// platform never fronts a renewal, so the domain has to move into the owner's
// own account before it expires. ManagedDomainNotice renders that countdown from
// these four values, and an EMPTY custody state renders nothing at all — which
// is what keeps every other deployment on earth silent.
//
// THE SETTING NAMES ARE COMPILED INTO THE NODE-SIDE SCRIPT, NOT SENT. The plane
// supplies four values; it cannot express which settings they land in. That is
// the whole shape of this primitive, and the reason it exists rather than a
// generic write-a-setting one: a primitive that took a name and a value would
// hand a compromised plane the entire stg_settings table — every credential,
// every gate, every flag the platform reads — through a vocabulary that looks
// modest. The declared list is a security boundary, not documentation, and the
// boundary here is the FOUR NAMES, which live in
// public_html/utils/managed_domain_notice.php and never cross the wire.
//
// It replaces a shell command that was the worst thing left in the managed
// domain pipeline: it scraped the site's database password out of a PHP config
// file with `grep | cut | cut | tr | sed`, exported it, and piped hand-escaped
// INSERT ... ON CONFLICT SQL into psql — bypassing the declared-settings gate
// that is the only thing stopping a typo minting a row nothing reads, and
// naming the site directory from a column in the PLANE's database. All of that
// goes away by the script being inside the site: it already has a database
// connection, and it writes through Setting::put, which refuses an undeclared
// name.
//
// STATE IS AN ENUM OVER THE EXACT FOUR CUSTODY STATES PLUS EMPTY. An
// unrecognised state is refused here rather than rendered, and empty is a real
// value — it is what clears an earlier state and returns the box to silence.
//
// EVERY STRING IS BOUNDED, INCLUDING manage_url. It is the one plane-supplied
// value that renders as a live link on a customer's own admin notice, which
// makes it the only plane-to-node influence this design introduces — so it is
// pinned to https:// and a length rather than left at DefaultMaxLen.
//
// STDIN RATHER THAN ARGV, following run_backup.php's reason inverted: none of
// these is a secret, but they are a composed OBJECT rather than one value, and
// composing it here from a fixed set of declared parameters is what stops the
// plane adding a field by sending one. All four keys are always written, so an
// absent parameter clears its setting — which is what makes a push converge on
// the desired state instead of only ever adding to it.
func init() {
	Register(Primitive{
		Name:        "managed_domain_notice",
		Class:       ClassOperate,
		Description: "Set this node's managed-domain notice facts (four fixed settings; the names are not on the wire).",
		Params: []ParamSpec{
			// The same pattern and bound the prepare primitive uses. One name,
			// one spelling, both ends agreeing.
			{Name: "domain", Type: ParamString, Required: true, MaxLen: 253, Pattern: managedDomainPattern},

			// When the registration runs out. A date, optionally with a time —
			// the shape the platform stores and the notice counts down to.
			{Name: "expiry_time", Type: ParamString, MaxLen: 32, Pattern: managedDomainExpiryPattern},

			// Where custody sits. Empty is deliberate and is the common case:
			// nothing is said to a buyer for the first six months.
			{Name: "state", Type: ParamEnum, Values: []string{
				"operator_managed", "push_requested", "push_sent", "self_custody", "",
			}},

			// Where the notice sends the owner to take the domain over.
			{Name: "manage_url", Type: ParamString, MaxLen: 512, Pattern: managedDomainManageURLPattern},
		},
		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",

			// Core, outside public_html's plugin tree, so it verifies against
			// the site-root manifest.
			ScriptPath: managedDomainNoticeScript,

			// No argv at all — not an empty-looking template with a slot in it.
			// There is no element here for a future edit to make wire-supplied.
			Args: nil,

			StdinFrom: managedDomainNoticePayload,
		},
		// Four upserts. A minute is a ceiling on a wedged process; it sits well
		// under the plane's 900s claim floor, so this needs no
		// PRIMITIVE_CLAIM_BUDGETS entry.
		Timeout: 1 * time.Minute,
	})
}

// managedDomainNoticeScript is the core script that owns the four setting
// names. Named as a constant so the test asserts the same string the
// registration uses.
const managedDomainNoticeScript = "public_html/utils/managed_domain_notice.php"

// managedDomainExpiryPattern is a stored UTC timestamp: a date, optionally with
// a time. Bounded to the shape rather than left open because it is rendered to
// a customer as a deadline.
var managedDomainExpiryPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}( \d{2}:\d{2}:\d{2})?$`)

// managedDomainManageURLPattern pins the one value that becomes a live link on
// a customer's admin page. https only — a link the platform itself renders must
// not be able to arrive as javascript:, data:, or plain http.
var managedDomainManageURLPattern = regexp.MustCompile(`^https://[A-Za-z0-9.\-/_]+$`)

// managedDomainNoticePayload renders the notice object from validated
// parameters.
//
// This is the ONLY place that object is composed on this node, and it composes
// it from a fixed set of four keys. The plane cannot add a fifth by sending one:
// an undeclared parameter never reaches here, and a declared one lands in
// exactly the field named below.
//
// Every key is emitted even when the parameter is absent, so a value the plane
// stopped sending is CLEARED rather than left standing. A notice that could only
// be added to would leave a stale expiry date on a customer's site after a
// renewal, which is the one number on that notice they act on.
func managedDomainNoticePayload(params Params) (string, error) {
	body, err := json.Marshal(map[string]string{
		"domain":      params.String("domain"),
		"expiry_time": params.String("expiry_time"),
		"state":       params.String("state"),
		"manage_url":  params.String("manage_url"),
	})
	if err != nil {
		return "", err
	}
	return string(body), nil
}
