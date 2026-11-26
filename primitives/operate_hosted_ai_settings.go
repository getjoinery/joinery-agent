package primitives

import (
	"encoding/json"
	"regexp"
	"time"
)

// hosted_ai_settings: give a site the AI-credit API key its operator minted
// for it.
//
// A site whose hosting somebody else runs comes with a little AI credit. Its
// operator creates one capped inference key for that site and hands it to the
// box. This is the value that arrives (specs/hosted_ai_credit.md §3.4).
//
// THE SETTING NAME IS COMPILED INTO THE NODE-SIDE SCRIPT, NOT SENT. The same
// shape as hosted_mail_settings, whose comment carries the full argument: a
// primitive that took a NAME and a value would let whatever is on the other
// end of this channel write any row in stg_settings. The plane can say what
// this site's AI key is. It cannot say the value is something else, and it
// cannot reach another setting by naming one.
//
// A WORD OF ITS OWN, not a value added to hosted_mail_settings: each credential
// lives in its own script with its name compiled in, so a mail push cannot
// change AI settings and an AI push cannot change mail.
//
// EMPTY CLEARS. An absent or empty key is written as empty, which is how the
// plane turns hosted AI off on a site.
//
// STDIN RATHER THAN ARGV: the value is a credential, and argv is
// world-readable on the box for the life of the process. The script prints
// only a compiled fact (HOSTED_AI_SETTINGS=ok), never the key, so the output
// needs no redactor.
func init() {
	Register(Primitive{
		Name:        "hosted_ai_settings",
		Class:       ClassOperate,
		Description: "Set this site's hosted AI-credit API key (one fixed setting; the name is not on the wire). Empty clears it.",
		Params: []ParamSpec{
			// The credential: printable, one line, bounded. Deliberately
			// permissive about content — a provider mints what it likes — and
			// strict about it being one value.
			{Name: "api_key", Type: ParamString, MaxLen: 256, Pattern: aiKeyPattern},
		},
		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",

			// Core, outside public_html's plugin tree, so it verifies against
			// the site-root manifest.
			ScriptPath: hostedAiSettingsScript,

			// No argv at all: the one value is a credential.
			Args: nil,

			StdinFrom: hostedAiSettingsPayload,
		},
		// One upsert. A minute is a ceiling on a wedged process.
		Timeout: 1 * time.Minute,
	})
}

// hostedAiSettingsScript owns the setting name.
const hostedAiSettingsScript = "public_html/utils/hosted_ai_settings.php"

// An API key: printable ASCII on one line, or nothing.
var aiKeyPattern = regexp.MustCompile(`^[\x20-\x7e]*$`)

// hostedAiSettingsPayload renders the one value as an object with one fixed
// key. The key is emitted every time, so a push that omits it CLEARS the
// setting rather than leaving an old key standing.
func hostedAiSettingsPayload(params Params) (string, error) {
	body, err := json.Marshal(map[string]string{
		"api_key": params.String("api_key"),
	})
	if err != nil {
		return "", err
	}
	return string(body), nil
}
