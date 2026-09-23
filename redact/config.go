package redact

import (
	"regexp"
	"strings"
)

// Config returns one line of a configuration file with anything secret gone,
// for file_head (specs/agent_recipes_and_vocabulary.md, rule 2).
//
// Configuration files have shapes of their own that the log redactor's
// key=value pattern does not match: `key = value` with spaces (rspamd, php.ini,
// fail2ban), `Directive value` (Apache, OpenDKIM, sshd), `key: value`, and
// JSON's `"key": value` (docker's daemon.json). A line whose KEY names a
// credential comes back as the key alone, whatever the separator and whatever
// the value's quoting, so a value that spans a shape this file did not foresee
// still never leaves: the rule is about the key. A commented-out line is read
// the same way (`# password = old` is still a password).
//
// Every other line goes through the log redactor's value masks (credential
// assignments, a bearer token, the personal half of an address, opaque tokens,
// the password half of a URL's userinfo) EXCEPT the IP literal mask. Owner-set
// 2026-09-23: configuration is not private, and an address in configuration
// is infrastructure (mynetworks, RemoteIPTrustedProxy, a bind address), which
// is exactly what a diagnosis of that file needs. A log line's address is a
// visitor; a config line's is a machine.
func Config(line string) string {
	if m := configKeyLine.FindStringSubmatch(line); m != nil {
		if configSecretKey(m[3]) {
			return strings.TrimRight(m[1]+m[2]+m[3]+m[4], " \t")
		}
	}
	line = maskInlineSecrets(line)
	return textWith(line, false)
}

// configPair: any word LATER in the line followed by a separator and a value
// — Apache's `SetEnv DB_PASSWORD value`, `-o smtp_sasl_password=x` in
// master.cf, fail2ban's `action = cloudflare[cfuser=u, cfapikey="k"]`, an
// INI line carrying two settings. The separator's `=`/`:` form is tried
// before bare whitespace, so `password = "x"` reads the value, not the gap.
// A value stops at `[`, `]`, `=`, `;` and `,`, so a nested pair inside a
// value is still judged on its own name.
var configPair = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_.\-]*)(\s*[=:]\s*|\s+)("[^"]*"|'[^']*'|[^\s;,\[\]=]+)`)

// maskInlineSecrets masks the value of every pair whose name configSecretKey
// judges a credential — the one rule the whole-line check uses too. It may
// mask a word of an ordinary comment ("the password is set elsewhere" loses
// "is"); a comment that reads oddly is the price of a value that never leaves.
func maskInlineSecrets(line string) string {
	var b strings.Builder
	pos := 0
	for pos < len(line) {
		m := configPair.FindStringSubmatchIndex(line[pos:])
		if m == nil {
			break
		}
		name := line[pos+m[2] : pos+m[3]]
		if configSecretKey(name) {
			b.WriteString(line[pos : pos+m[6]])
			b.WriteString(Mask)
			pos += m[7]
			continue
		}
		// Not a credential: the value may itself be the next name
		// (`SetEnv DB_PASSWORD x`), so the scan resumes at the value.
		b.WriteString(line[pos : pos+m[6]])
		pos += m[6]
	}
	b.WriteString(line[pos:])
	return b.String()
}

// configKeyLine: leading space and comment markers (1), an optional quote (2),
// the key (3), the closing quote (4), then a separator — '=', ':', or plain
// whitespace for the Directive shape — and the rest.
var configKeyLine = regexp.MustCompile(`^(\s*(?:[#;]+\s*)?)(["']?)([A-Za-z_][A-Za-z0-9_.\-]*)(["']?)\s*(?:=|:|\s)`)

// configSecretWord: a key qualifies by containing one of these anywhere, in
// any case — the credentialAssignment rule for logs — or by being or ending
// in one of secretKeys.
var configSecretWord = regexp.MustCompile(`(?i)password|passwd|passphrase|token|secret|private_?key|_pw$|^pw$|apikey`)

func configSecretKey(key string) bool {
	if configSecretWord.MatchString(key) {
		return true
	}
	lower := strings.ToLower(key)
	for _, k := range secretKeys {
		if lower == k || strings.HasSuffix(lower, "_"+k) || strings.HasSuffix(lower, "."+k) {
			return true
		}
	}
	return false
}
