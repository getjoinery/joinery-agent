package redact

// secretKeys is the list of credential key names whose VALUE is masked when it
// appears in a quoted key/value shape. It mirrors, entry for entry and in the
// same order, SmSecretRedactor::$secret_keys in the platform tree
// (plugins/server_manager/includes/SmSecretRedactor.php). A platform-side
// parity test reads this file and fails when the two lists differ, so:
//
//   - ONE quoted key per line, nothing else on the line;
//   - the order is the PHP order (longer name before a name it prefixes).
var secretKeys = []string{
	"secret_key",
	"access_key",
	"application_key",
	"app_key",
	"api_secret",
	"apk_secret_key",
	"password",
	"passwd",
	"token",
	"secret",
	"export_key",
	"clone_key",
	"credentials_b64",
	"credentials",
}
