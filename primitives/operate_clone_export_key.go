package primitives

// File named _key rather than _arm: a Go filename ending in _arm is a GOARCH
// build constraint and the file silently drops out of every other build.

import (
	"encoding/json"
	"regexp"
	"time"
)

// clone_export_arm: turn this site's clone export on for one provision, and
// off again afterwards.
//
// A new machine installed from this site pulls the database, uploads, themes
// and plugins over HTTPS from utils/clone_export, inside its own install.sh
// run. That endpoint is off until clone_export_key holds a value, and the key
// is the bearer token the target presents. So the management node arms the
// SOURCE by handing it one key for the length of the provision, and disarms
// it by handing it an empty one once the clone has landed. Nothing opens an
// SSH session to the source; the source is reached by its web address.
//
// THE SETTING NAME IS COMPILED INTO THE NODE-SIDE SCRIPT, NOT SENT. Same shape
// as managed_domain_notice: the plane supplies one value and cannot express
// which setting it lands in. A generic write-a-setting primitive would hand a
// compromised plane every row in stg_settings; this one hands it exactly the
// power to enable a read-only export of this site, which is the power it needs.
//
// The key is BOUNDED TO A SHAPE, and empty is a real value: it is the disarm.
// The key is also the password the source encrypts its dump under
// (utils/clone_export.php), which is why it travels on stdin and not argv.
func init() {
	Register(Primitive{
		Name:        "clone_export_arm",
		Class:       ClassOperate,
		Description: "Arm (or, with an empty key, disarm) this site's clone export for one provision; the setting name is not on the wire.",
		Params: []ParamSpec{
			// Not required: absent and empty both disarm. The pattern is the
			// shape the plane mints (hex) with room for an operator-typed key.
			{Name: "export_key", Type: ParamString, MaxLen: 128, Pattern: cloneExportKeyPattern},
		},
		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",

			// Core, outside public_html's plugin tree, so it verifies against
			// the site-root manifest.
			ScriptPath: cloneExportArmScript,

			// No argv: the key is a credential and must not be visible in ps.
			Args: nil,

			StdinFrom: cloneExportArmPayload,
		},
		// One setting write. A minute is a ceiling on a wedged process.
		Timeout: 1 * time.Minute,
	})
}

// cloneExportArmScript is the core script that owns the setting name.
const cloneExportArmScript = "public_html/utils/clone_export_arm.php"

// cloneExportKeyPattern: a bearer token. Letters, digits, underscore and dash;
// empty disarms. Nothing here can be read as SQL, a path, or a shell word.
var cloneExportKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)

// cloneExportArmPayload renders the one-key object. The key is always emitted,
// so an absent parameter arrives as "" and DISARMS — a push converges on the
// desired state rather than only ever adding to it.
func cloneExportArmPayload(params Params) (string, error) {
	body, err := json.Marshal(map[string]string{
		"export_key": params.String("export_key"),
	})
	if err != nil {
		return "", err
	}
	return string(body), nil
}
