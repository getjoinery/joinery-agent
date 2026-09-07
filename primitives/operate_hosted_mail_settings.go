package primitives

import (
	"encoding/json"
	"regexp"
	"strconv"
	"time"
)

// hosted_mail_settings: give a site the outbound-mail credentials its operator
// minted for it.
//
// A site whose hosting somebody else runs does not open a mail-provider account.
// Its operator creates a subaccount and one SMTP user inside it, and hands that
// user's name and password to the box. These are the values that arrive.
//
// THE NINE SETTING NAMES ARE COMPILED INTO THE NODE-SIDE SCRIPT, NOT SENT. Same
// shape as managed_domain_notice and fleet_enroll, and pinned here for a reason
// worth stating plainly: a primitive that took a NAME and a value would let
// whatever is on the other end of this channel write any row in stg_settings —
// and the mail rows are the ones that matter most, because a site whose
// outbound mail can be redirected is a site whose password-reset emails can be
// redirected. The plane can say what this site's SMTP password is. It cannot
// say that the value it is sending is an SMTP password rather than something
// else, and it cannot reach a tenth setting by naming one.
//
// It is also why there is no general settings writer on this channel. One was
// built and removed: with the mail values carried here and the hosting banner
// carried by hosted_plan_notice, a general map-taking primitive would have been
// a general capability with no general use, bought at the cost of the property
// this comment describes.
//
// STDIN RATHER THAN ARGV: one of these values is a password, and argv is
// world-readable on the box for the life of the process.
func init() {
	Register(Primitive{
		Name:        "hosted_mail_settings",
		Class:       ClassOperate,
		Description: "Set this site's outbound SMTP credentials (nine fixed settings; the names are not on the wire).",
		Params: []ParamSpec{
			// Which provider the site sends through. An enum, not free text:
			// the platform's own vocabulary, and the only value the hosted tier
			// uses is smtp. Empty clears it back to unconfigured.
			{Name: "service", Type: ParamEnum, Values: []string{"smtp", ""}},

			// Where to connect. A hostname and a port, bounded to their shapes.
			{Name: "host", Type: ParamString, MaxLen: 253, Pattern: mailHostPattern},
			{Name: "port", Type: ParamInt, Min: 0, Max: 65535},

			// The credential. The username shape is the provider's; the password
			// is bounded printable text, because a provider may mint anything.
			{Name: "username", Type: ParamString, MaxLen: 128, Pattern: mailUserPattern},
			{Name: "password", Type: ParamString, MaxLen: 256, Pattern: mailSecretPattern},

			// The SENDING identity: the subdomain the provider verified, which
			// is not the domain the site answers on. Getting these wrong is the
			// difference between mail that authenticates and mail that is
			// filtered, so each is pinned to a hostname shape.
			{Name: "sender", Type: ParamString, MaxLen: 253, Pattern: mailSenderPattern},
			{Name: "helo", Type: ParamString, MaxLen: 253, Pattern: mailHostPattern},
			{Name: "hostname", Type: ParamString, MaxLen: 253, Pattern: mailHostPattern},
		},
		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",

			// Core, outside public_html's plugin tree, so it verifies against
			// the site-root manifest.
			ScriptPath: hostedMailSettingsScript,

			// No argv at all — not an empty-looking template with a slot in it.
			Args: nil,

			StdinFrom: hostedMailSettingsPayload,
		},
		// Nine upserts. A minute is a ceiling on a wedged process; well under
		// the plane's claim floor, so no PRIMITIVE_CLAIM_BUDGETS entry.
		Timeout: 1 * time.Minute,
	})
}

// hostedMailSettingsScript owns the nine setting names.
const hostedMailSettingsScript = "public_html/utils/hosted_mail_settings.php"

var (
	// A hostname, or nothing. No scheme, no path, no port — those are separate
	// fields, and letting one arrive inside another is how a second value
	// smuggles into one slot. Empty is accepted because clearing a setting is a
	// real push: it is how a site is handed back to its owner's own mail
	// account. Whether an EMPTY host is legitimate depends on the service, and
	// that pairing is checked where both values are in hand — in the builder
	// and again in the node-side script — not here, where only one is.
	mailHostPattern = regexp.MustCompile(`^(([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)?$`)
	// An SMTP username as providers mint them, plus the address form some use.
	mailUserPattern = regexp.MustCompile(`^[A-Za-z0-9._@+-]*$`)
	// A bounce address: a local part at a hostname.
	mailSenderPattern = regexp.MustCompile(`^([A-Za-z0-9._+-]+@[A-Za-z0-9.-]+)?$`)
	// A password: printable, one line. Deliberately permissive about content —
	// a provider mints what it likes — and strict about it being one value.
	mailSecretPattern = regexp.MustCompile(`^[\x20-\x7e]*$`)
)

// hostedMailSettingsPayload renders the eight values as one object. (The site
// writes nine settings: smtp_auth is derived there from whether a username was
// supplied, because that is not a judgement the wire needs to carry.)
//
// This is the ONLY place that object is composed on this node, and it composes
// it from a fixed set of keys: the plane cannot add a ninth by sending one. Each
// key is emitted every time, so a value the plane stopped sending is CLEARED
// rather than left standing — which is what makes a REPLACEMENT credential
// fully supersede the one before it. It is not a way to hand a site back: the
// owner's own credentials live in these same settings, and a push of empties
// after they typed them would stop their site sending.
func hostedMailSettingsPayload(params Params) (string, error) {
	body, err := json.Marshal(map[string]string{
		"service":  params.String("service"),
		"host":     params.String("host"),
		"port":     portString(params.Int("port")),
		"username": params.String("username"),
		"password": params.String("password"),
		"sender":   params.String("sender"),
		"helo":     params.String("helo"),
		"hostname": params.String("hostname"),
	})
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// portString renders a validated port. Zero renders empty rather than "0", so a
// push that omits the port CLEARS the setting instead of writing a port number
// no mail server listens on.
func portString(v int64) string {
	if v == 0 {
		return ""
	}
	return strconv.FormatInt(v, 10)
}
