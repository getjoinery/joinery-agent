// Package redact is the node-side pass every word that returns text runs its
// result through before that result leaves the machine.
//
// It exists because the boundary is the node, not the plane
// (specs/sentinel_managed_recovery.md §11): a management node is the party
// whose word is not being taken, so nothing unredacted may reach it at all. The
// plane keeps its own display-time pass (SmSecretRedactor) and must not relax
// it on the strength of this one.
//
// What it masks, and what it deliberately leaves:
//
//   - credential VALUES named by a key from secretKeys, in the shapes the
//     platform's redactor handles (var_export, JSON, KEY=value environment
//     assignments, secret-key headers, --clone-key= flags) and a bearer token;
//     the mask is the platform's, ********, and the key name stays so the line
//     still reads;
//   - the personal half of an email address: local@example.com becomes
//     <email>@example.com — the domain is what a mail diagnosis needs, and a
//     masked domain would make every delivery failure read the same;
//   - IPv4 and IPv6 literals, which become <ip>: the agent's host_report
//     already promises never to say who failed to log in or from where;
//   - standalone opaque tokens (32 or more hex characters, or 32 or more
//     base64 characters carrying digits and both cases), which become <token>.
//
// Version strings, timestamps, file paths, setting names and class names pass
// through unchanged; the tests pin each of those as a non-mask, because a
// redactor that eats the diagnosis is as useless as one that leaks it.
//
// Free-text redaction masks SHAPES. A member's name inside an exception message
// is not a shape and passes. That limit is stated in the spec and on the
// owner's switch; it is not something a longer pattern list fixes.
package redact

import (
	"regexp"
	"strings"
	"unicode"
)

// Mask is the platform's mask, kept identical so a value masked here and a
// value masked on the plane are indistinguishable on the job page.
const Mask = "********"

var (
	keyAlternation = func() string {
		quoted := make([]string, 0, len(secretKeys))
		for _, k := range secretKeys {
			quoted = append(quoted, regexp.QuoteMeta(k))
		}
		return strings.Join(quoted, "|")
	}()

	// 'key' => 'value' and "key": "value" (var_export and JSON, both separators).
	quotedKeyValue = regexp.MustCompile(`(?i)(['"](?:` + keyAlternation + `)['"]\s*(?:=>|:)\s*['"])([^'"]*)(['"])`)

	// Header-style "secret-key: value".
	secretKeyHeader = regexp.MustCompile(`(?i)(secret-key\s*:\s*)([^\s'"]+)`)

	// The bootstrap's --clone-key=KEY flag.
	cloneKeyFlag = regexp.MustCompile(`(--clone-key=)('[^']*'|"[^"]*"|\S+)`)

	// Assignments: PGPASSWORD=..., AWS_SECRET_ACCESS_KEY=..., GITHUB_TOKEN=...
	// (the shape a console command uses) and, in any case, password=...,
	// dbpassword=..., csrf_token=..., api_key=... (the shape a DSN, a query
	// string or a config dump uses inside a log line). A name qualifies by
	// containing PASSWORD, PASSWD, TOKEN or SECRET anywhere, in any case, or by
	// being one of secretKeys, in any case. The platform pattern's (?!\s) is
	// implied here: every alternative of the value already begins with a
	// non-space.
	credentialAssignment = regexp.MustCompile(`(?i)\b([a-z][a-z0-9_]*(?:password|passwd|token|secret)[a-z0-9_]*|(?:` + keyAlternation + `))=('[^']*'|"[^"]*"|\S+)`)

	// A name ending in _KEY qualifies only in the conventional uppercase
	// spelling (API_KEY, DEPLOY_KEY). Lowercase names ending in _key are the
	// shape of flags and column names (--key=path, primary_key=usr_user_id),
	// which carry no secret. Bare KEY anywhere would swallow SSH_KEY_PATH and
	// its kind, which carry paths.
	upperKeyAssignment = regexp.MustCompile(`\b([A-Z][A-Z0-9_]*_KEY)=('[^']*'|"[^"]*"|\S+)`)

	// scheme://user:password@host — the password half of a URL's userinfo
	// (a DSN, a proxy URL). The user stays; group 1 keeps "scheme://user:".
	urlUserinfo = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://[^\s:/@]+:)[^\s@/]+@`)

	// Authorization: Bearer <token>.
	bearerToken = regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9._~+/\-]+=*`)

	// local@domain. Group 1 is the domain, which is kept.
	email = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@((?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,})\b`)

	// IPv6: the full eight-group form, or any form carrying "::". A timestamp
	// (23:10:00) has neither, and a MAC address has six groups and no "::".
	ipv6Full = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`)
	//
	// The compressed form is two patterns. With groups in front (2001:db8::1,
	// fe80::, fe80::1) the "::" is unambiguous. With nothing in front (::1)
	// at least one group must FOLLOW and no word character may precede, or
	// every PHP static call — PathHelper::getThemeFilePath — would lose its
	// method name. The bare any-address "[::]" is therefore left alone; it
	// names nobody.
	ipv6Compressed = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?`)
	ipv6Leading    = regexp.MustCompile(`(^|[^A-Za-z0-9_:])::[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6}`)

	// IPv4: four dotted octets. A version string has three parts.
	ipv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

	// Opaque tokens. Hex of 32 or more stands alone on word boundaries. The
	// base64 run is checked in code for digits and both cases, so a long
	// CamelCase class name or a long lowercase word is never a "token".
	// Both runs are checked in code for a mix of digits and letters, so a
	// 40-digit number or a run of one letter is never a "token".
	hexToken    = regexp.MustCompile(`\b[0-9a-fA-F]{32,}\b`)
	base64Token = regexp.MustCompile(`(^|[^A-Za-z0-9+/_\-])([A-Za-z0-9+]{32,}={0,2})($|[^A-Za-z0-9+/_\-])`)
)

// Text returns s with credential values, the personal half of email addresses,
// IP literals and opaque tokens masked. Safe on any string; a string carrying
// none of them comes back unchanged.
func Text(s string) string {
	return textWith(s, true)
}

// textWith is Text, with the IP literal masks optional: Config leaves them.
func textWith(s string, ips bool) string {
	if s == "" {
		return s
	}
	s = urlUserinfo.ReplaceAllString(s, "${1}"+Mask+"@")
	s = quotedKeyValue.ReplaceAllString(s, "${1}"+Mask+"${3}")
	s = secretKeyHeader.ReplaceAllString(s, "${1}"+Mask)
	s = cloneKeyFlag.ReplaceAllString(s, "${1}"+Mask)
	s = credentialAssignment.ReplaceAllString(s, "${1}="+Mask)
	s = upperKeyAssignment.ReplaceAllString(s, "${1}="+Mask)
	s = bearerToken.ReplaceAllString(s, "${1}"+Mask)
	s = email.ReplaceAllString(s, "<email>@${1}")
	if ips {
		s = ipv6Full.ReplaceAllString(s, "<ip>")
		s = ipv6Compressed.ReplaceAllString(s, "<ip>")
		s = ipv6Leading.ReplaceAllString(s, "${1}<ip>")
		s = ipv4.ReplaceAllString(s, "<ip>")
	}
	s = hexToken.ReplaceAllStringFunc(s, maskHexRun)
	s = base64Token.ReplaceAllStringFunc(s, maskBase64Run)
	return s
}

// maskHexRun masks a hex run only when it mixes digits and letters, the
// shape of a hash or a key; a long number or a run of one letter is left.
func maskHexRun(m string) string {
	var digit, letter bool
	for _, r := range m {
		if unicode.IsDigit(r) {
			digit = true
		} else {
			letter = true
		}
	}
	if digit && letter {
		return "<token>"
	}
	return m
}

// maskBase64Run masks the middle group of a base64Token match when it looks
// like a token rather than a word: at least one digit, one upper- and one
// lower-case letter.
func maskBase64Run(m string) string {
	sub := base64Token.FindStringSubmatch(m)
	if sub == nil {
		return m
	}
	run := sub[2]
	var digit, upper, lower bool
	for _, r := range run {
		switch {
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		}
	}
	if !(digit && upper && lower) {
		return m
	}
	return sub[1] + "<token>" + sub[3]
}

// Fields masks every string value in a result map in place, descending into
// nested map[string]interface{} and []interface{} values, so a word redacts
// its whole result in one call. Values of other types are left alone: a
// number, a bool or a time measured by the machine is not text a person wrote.
func Fields(m map[string]interface{}) {
	for k, v := range m {
		m[k] = fields(v)
	}
}

func fields(v interface{}) interface{} {
	switch t := v.(type) {
	case string:
		return Text(t)
	case map[string]interface{}:
		Fields(t)
		return t
	case []interface{}:
		for i := range t {
			t[i] = fields(t[i])
		}
		return t
	case []string:
		for i := range t {
			t[i] = Text(t[i])
		}
		return t
	case []map[string]interface{}:
		for i := range t {
			Fields(t[i])
		}
		return t
	}
	return v
}
