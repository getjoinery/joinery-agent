package primitives

import (
	"encoding/json"
	"regexp"
	"time"
)

// fleet_enroll: seed this site's hosted-relay (fleet) credentials, so its
// owner lands on a one-click Enroll instead of pasting three values.
//
// When a buyer's hosting tier carries a fleet slot, the operator's management
// node mints an API key for the buyer's account on the fleet service and hands
// the new site three values: where the service is, and the key pair that
// authenticates to it as that buyer. The site's mailbox Setup tab reads them
// and offers Enroll.
//
// THE THREE SETTING NAMES ARE COMPILED INTO THE NODE-SIDE SCRIPT, NOT SENT.
// Same shape as managed_domain_notice: three values cross, and the plane
// cannot express which settings they land in. That is what keeps this a
// modest primitive rather than a write-anything one.
//
// It replaces a second SSH session at install completion that scraped the
// site's database password out of a PHP config file and piped a psql heredoc
// through sudo, over the same root password the bootstrap used. The site
// already has a database connection; it writes through Setting::put.
//
// STDIN, NOT ARGV: the secret half of the key pair is a credential and must
// not be visible in ps. Stdin is never logged.
func init() {
	Register(Primitive{
		Name:        "fleet_enroll",
		Class:       ClassOperate,
		Description: "Seed this site's fleet-service URL and API key pair (three fixed settings; the names are not on the wire).",
		Params: []ParamSpec{
			// Where the fleet service is. https only: the site will send the
			// key pair to it.
			{Name: "service_url", Type: ParamString, Required: true, MaxLen: 512, Pattern: fleetServiceURLPattern},

			// The key pair, in the exact shape the platform mints
			// (FleetProvisionSeeding::mintTenantKey): a fixed prefix and a
			// lowercase alphanumeric body.
			{Name: "public_key", Type: ParamString, Required: true, MaxLen: 80, Pattern: fleetPublicKeyPattern},
			{Name: "secret_key", Type: ParamString, Required: true, MaxLen: 80, Pattern: fleetSecretKeyPattern},
		},
		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",

			// Core, outside public_html's plugin tree, so it verifies against
			// the site-root manifest. The settings it writes belong to the
			// mailbox plugin; Setting::put refuses them where that plugin is
			// not active, and the job says so.
			ScriptPath: fleetEnrollScript,

			// No argv at all — the secret must not appear in ps.
			Args: nil,

			StdinFrom: fleetEnrollPayload,
		},
		// Three upserts. A minute is a ceiling on a wedged process.
		Timeout: 1 * time.Minute,
	})
}

// fleetEnrollScript is the core script that owns the three setting names.
const fleetEnrollScript = "public_html/utils/fleet_enroll.php"

// fleetServiceURLPattern pins the service address to https and a host with an
// optional path. No query string, no userinfo, nothing that reads as a shell
// word or a script.
var fleetServiceURLPattern = regexp.MustCompile(`^https://[A-Za-z0-9.\-]+(:[0-9]{1,5})?(/[A-Za-z0-9.\-/_]*)?$`)

// fleetPublicKeyPattern / fleetSecretKeyPattern: the platform's own key shape.
var (
	fleetPublicKeyPattern = regexp.MustCompile(`^public_[a-z0-9]{8,64}$`)
	fleetSecretKeyPattern = regexp.MustCompile(`^secret_[a-z0-9]{8,64}$`)
)

// fleetEnrollPayload renders the three values as one object. This is the only
// place that object is composed on this node, from a fixed set of three keys:
// the plane cannot add a fourth by sending one.
func fleetEnrollPayload(params Params) (string, error) {
	body, err := json.Marshal(map[string]string{
		"service_url": params.String("service_url"),
		"public_key":  params.String("public_key"),
		"secret_key":  params.String("secret_key"),
	})
	if err != nil {
		return "", err
	}
	return string(body), nil
}
