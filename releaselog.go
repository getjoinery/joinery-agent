package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Is this agent binary's release in the public log? (spec
// release_transparency, D5 and WP5.)
//
// Every release is written to Sigstore's public log as one signed statement
// recording the hash of every artifact it ships, this agent's binaries
// among them. A node that holds the keys to check that statement installs a
// new binary only when the statement verifies and records exactly the bytes
// on offer. The publisher signs the binaries AND the statement, so a
// compelled publisher could still sign a binary; what it cannot do is ship
// one nobody can see, because the statement the node demands is public.
//
// The checks are the PHP side's (includes/TransparencyProof.php and
// PackageSignature::checkLogged) line for line, with nothing but the standard
// library, on bytes already fetched and keys already held — never a key read
// from the release being checked:
//
//  1. the statement's DSSE envelope verifies against a statement key held;
//  2. the leaf is bound to THIS envelope (digest, signature, key), and is the
//     canonical form of what it decodes to;
//  3. the checkpoint is a signed note from a log whose key is held;
//  4. the RFC 6962 inclusion proof walks the leaf to the checkpoint's root;
//
// and the statement records this binary's sha256 under agent/<platform>.
//
// The keys held are the ones compiled into this binary (below) plus the ones
// this machine has proven since, kept in two root-owned files beside the
// identity. The statement's key_chain is walked forward from them in memory;
// what the walk proves is written to those files by the install step, after
// the swap, and never removed. A machine holding no statement key or no log
// key cannot check anything and updates on the release signature alone, as
// every agent did before the log existed.

// releaseStatementKeysB64 and releaseLogKeysB64 are the statement and
// checkpoint keys this binary trusts, injected at build time from the
// repository's release_keys/ by AgentDistPublisher:
//
//	-X main.releaseStatementKeysB64=<base64 DER>,<base64 DER>
//	-X main.releaseLogKeysB64=<origin>:<base64 DER>,<origin>:<base64 DER>
//
// A build without them holds no keys of its own.
var (
	releaseStatementKeysB64 = ""
	releaseLogKeysB64       = ""
)

const (
	// releaseStatementName is the file a release ships beside the agent's
	// manifest, and the artifact kind the channel serves it under.
	releaseStatementName = "RELEASE_STATEMENT"

	// maxReleaseStatementBytes bounds the statement this agent will read. A
	// real one is a few kilobytes plus a few per key ever rotated.
	maxReleaseStatementBytes = 1 << 20

	statementPayloadType = "application/vnd.joinery.release-statement+json"
	leafKind             = "hashedrekord"
	leafAPIVersion       = "0.0.2"
	leafDigestAlg        = "SHA2_256"
	statementKeyType     = "PKIX_ECDSA_P256_SHA_256"

	// The key files, in agentStateDir(). Same names and line formats as a
	// site's config/ copies: one base64 DER key per line, and
	// "<origin> <base64 DER>" per line.
	statementKeysFileName = "release_statement_keys"
	logKeysFileName       = "transparency_log_keys"
)

// ed25519SPKIPrefix is the SubjectPublicKeyInfo prefix of an Ed25519 key: the
// 32 raw bytes follow.
var ed25519SPKIPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

var (
	logOriginPattern      = regexp.MustCompile(`^[a-z0-9.-]+$`)
	checkpointSizePattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,18})$`)
	noteSignaturePattern  = regexp.MustCompile(`^\x{2014} (\S+) (\S+)$`)
	jsonIntPattern        = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
	textIntPattern        = regexp.MustCompile(`^[+-]?(0|[1-9][0-9]*)$`)
)

// releaseLogKeys is a set of keys held: P-256 statement keys and, per log
// origin, Ed25519 checkpoint keys (a log's key may rotate in place, so an
// origin can hold more than one). All as PKIX DER.
type releaseLogKeys struct {
	statement [][]byte
	log       map[string][][]byte
}

func newReleaseLogKeys() releaseLogKeys {
	return releaseLogKeys{log: map[string][][]byte{}}
}

// holds is whether these keys can check a statement at all, which is what
// makes the log required: a machine with nothing to check by would refuse
// every release, including the one that would give it the keys.
func (k releaseLogKeys) holds() bool {
	return len(k.statement) > 0 && len(k.log) > 0
}

func (k *releaseLogKeys) addStatement(der []byte) bool {
	for _, have := range k.statement {
		if bytes.Equal(have, der) {
			return false
		}
	}
	k.statement = append(k.statement, der)
	return true
}

func (k *releaseLogKeys) addLog(origin string, der []byte) bool {
	if k.log == nil {
		k.log = map[string][][]byte{}
	}
	for _, have := range k.log[origin] {
		if bytes.Equal(have, der) {
			return false
		}
	}
	k.log[origin] = append(k.log[origin], der)
	return true
}

func (k *releaseLogKeys) merge(other releaseLogKeys) {
	for _, der := range other.statement {
		k.addStatement(der)
	}
	for origin, ders := range other.log {
		for _, der := range ders {
			k.addLog(origin, der)
		}
	}
}

func (k releaseLogKeys) clone() releaseLogKeys {
	out := newReleaseLogKeys()
	out.merge(k)
	return out
}

// minus is what k holds that held does not.
func (k releaseLogKeys) minus(held releaseLogKeys) releaseLogKeys {
	out := newReleaseLogKeys()
	probe := held.clone()
	for _, der := range k.statement {
		if probe.addStatement(der) {
			out.addStatement(der)
		}
	}
	for origin, ders := range k.log {
		for _, der := range ders {
			if probe.addLog(origin, der) {
				out.addLog(origin, der)
			}
		}
	}
	return out
}

func (k releaseLogKeys) empty() bool {
	return len(k.statement) == 0 && len(k.log) == 0
}

// isP256 is whether DER is a P-256 public key, the only statement key form the
// log accepts and so the only one read from anywhere.
func isP256(der []byte) bool {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	return ok && ec.Curve == elliptic.P256()
}

// ed25519Raw is the 32 raw bytes of an Ed25519 SubjectPublicKeyInfo.
func ed25519Raw(der []byte) ([]byte, error) {
	if len(der) != len(ed25519SPKIPrefix)+ed25519.PublicKeySize || !bytes.HasPrefix(der, ed25519SPKIPrefix) {
		return nil, errors.New("the checkpoint key is not an Ed25519 public key")
	}
	return der[len(ed25519SPKIPrefix):], nil
}

// bakedReleaseLogKeys reads the keys compiled into this binary. A malformed
// entry is a build fault and is said once at start; the rest still count.
func bakedReleaseLogKeys() releaseLogKeys {
	keys := newReleaseLogKeys()
	for _, item := range strings.Split(releaseStatementKeysB64, ",") {
		if item = strings.TrimSpace(item); item == "" {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(item)
		if err != nil || !isP256(der) {
			log.Printf("release log: a statement key compiled into this build is not a P-256 key; ignored")
			continue
		}
		keys.addStatement(der)
	}
	for _, item := range strings.Split(releaseLogKeysB64, ",") {
		if item = strings.TrimSpace(item); item == "" {
			continue
		}
		origin, b64, found := strings.Cut(item, ":")
		der, err := base64.StdEncoding.DecodeString(b64)
		if !found || !logOriginPattern.MatchString(origin) || err != nil {
			log.Printf("release log: a log key compiled into this build is malformed; ignored")
			continue
		}
		if _, err := ed25519Raw(der); err != nil {
			log.Printf("release log: the log key compiled into this build for %s is not Ed25519; ignored", origin)
			continue
		}
		keys.addLog(origin, der)
	}
	return keys
}

// trustedKeyFile is whether a key file may be read: only root may have
// written it. A file anyone else could have written is read as empty, the
// rule the site's own key files follow (PackageSignature::nodeLog).
func trustedKeyFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	if info.Mode().Perm()&0o022 != 0 {
		warnKeyFileOnce(path, "release log: %s is writable beyond its owner; not trusted", path)
		return false
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 0 && os.Geteuid() == 0 {
		warnKeyFileOnce(path, "release log: %s is not root's; not trusted", path)
		return false
	}
	return true
}

// keyFileWarned keeps an untrusted key file from being reported on every
// update check.
var keyFileWarned sync.Map

func warnKeyFileOnce(path, format string, args ...interface{}) {
	if _, seen := keyFileWarned.LoadOrStore(path, true); !seen {
		log.Printf(format, args...)
	}
}

func keyFileLines(path string) []string {
	if !trustedKeyFile(path) {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r", "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" && line[0] != '#' {
			lines = append(lines, line)
		}
	}
	return lines
}

// readReleaseLogKeyFiles reads the keys this machine has proven, from dir.
// Lines that are not a key of the right kind are skipped.
func readReleaseLogKeyFiles(dir string) releaseLogKeys {
	keys := newReleaseLogKeys()
	for _, line := range keyFileLines(filepath.Join(dir, statementKeysFileName)) {
		if der, err := base64.StdEncoding.DecodeString(line); err == nil && isP256(der) {
			keys.addStatement(der)
		}
	}
	for _, line := range keyFileLines(filepath.Join(dir, logKeysFileName)) {
		fields := strings.Fields(line)
		if len(fields) != 2 || !logOriginPattern.MatchString(fields[0]) {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil {
			continue
		}
		if _, err := ed25519Raw(der); err == nil {
			keys.addLog(fields[0], der)
		}
	}
	return keys
}

// persistReleaseLogKeys appends to dir's key files every key in keys they do
// not already hold. Append-only: nothing is ever removed, so a machine that
// once required the log always will. Each file is replaced whole, by a
// rename, so a crash leaves it as it was or as it will be, never cut short.
// Returns the lines added.
func persistReleaseLogKeys(dir string, keys releaseLogKeys) ([]string, error) {
	plan := map[string][]string{}
	for _, der := range keys.statement {
		plan[statementKeysFileName] = append(plan[statementKeysFileName], base64.StdEncoding.EncodeToString(der))
	}
	origins := make([]string, 0, len(keys.log))
	for origin := range keys.log {
		origins = append(origins, origin)
	}
	sort.Strings(origins)
	for _, origin := range origins {
		for _, der := range keys.log[origin] {
			plan[logKeysFileName] = append(plan[logKeysFileName], origin+" "+base64.StdEncoding.EncodeToString(der))
		}
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var added []string
	for _, name := range []string{statementKeysFileName, logKeysFileName} {
		lines := plan[name]
		if len(lines) == 0 {
			continue
		}
		path := filepath.Join(dir, name)
		existing, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return added, err
		}
		have := map[string]bool{}
		for _, line := range strings.Split(string(existing), "\n") {
			have[strings.TrimSpace(line)] = true
		}
		var fresh []string
		for _, line := range lines {
			if !have[line] {
				have[line] = true
				fresh = append(fresh, line)
			}
		}
		if len(fresh) == 0 {
			continue
		}
		body := strings.TrimRight(string(existing), "\n")
		if body != "" {
			body += "\n"
		}
		body += strings.Join(fresh, "\n") + "\n"
		if err := replaceFile(path, []byte(body)); err != nil {
			return added, err
		}
		for _, line := range fresh {
			added = append(added, name+": "+line)
		}
	}
	return added, nil
}

// replaceFile writes body to path through a temporary file beside it, synced
// and renamed into place, mode 0644, and syncs the directory after.
func replaceFile(path string, body []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after the rename
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	// The rename is a change to the directory: synced too, so a power loss
	// just after it cannot take the new file back.
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// statementVersion is the release a statement names, unverified: for a log
// line that says which release a refused statement was for.
func statementVersion(doc []byte) string {
	link, ok := decodeLink(doc)
	if !ok {
		return ""
	}
	return decodePayload(link.env).version()
}

// ── The four checks ──

// ── Reading JSON the way PHP reads it ──
//
// encoding/json matches a struct's field names without regard to case, and
// takes the last of two keys that differ only in case; PHP's json_decode
// reads exact keys. Read through structs, {"ARTIFACTS": ...} beside
// {"artifacts": ...} would show this verifier one thing and the PHP one,
// verify_release.php and the releases page another (reviewer2 B1). So every
// document here is read as objects of raw values, by exact key.

// jsonObject is raw read as an object, keys exact; false when it is not one.
func jsonObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	if !isJSONObject(raw) {
		return nil, false
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, false
	}
	return m, true
}

// jsonArray is raw read as an array; false when it is not one.
func jsonArray(raw json.RawMessage) ([]json.RawMessage, bool) {
	if !strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
		return nil, false
	}
	var a []json.RawMessage
	if json.Unmarshal(raw, &a) != nil {
		return nil, false
	}
	return a, true
}

// jsonString is raw read as a string; false for anything else, null included.
func jsonString(raw json.RawMessage) (string, bool) {
	if !strings.HasPrefix(strings.TrimSpace(string(raw)), `"`) {
		return "", false
	}
	var str string
	if json.Unmarshal(raw, &str) != nil {
		return "", false
	}
	return str, true
}

// field is one exact key of an object, or nil.
func field(raw json.RawMessage, key string) json.RawMessage {
	m, ok := jsonObject(raw)
	if !ok {
		return nil
	}
	return m[key]
}

// dsseEnvelope is a statement envelope as read by exact key. A field that is
// absent or not a string is nil; signatures is nil unless it is an array, and
// a signature's sig nil unless it is a string.
type dsseEnvelope struct {
	PayloadType *string
	Payload     *string
	Signatures  []dsseSignature
}

type dsseSignature struct {
	Sig *string
}

func decodeEnvelope(raw json.RawMessage) dsseEnvelope {
	var env dsseEnvelope
	if v, ok := jsonString(field(raw, "payloadType")); ok {
		env.PayloadType = &v
	}
	if v, ok := jsonString(field(raw, "payload")); ok {
		env.Payload = &v
	}
	if sigs, ok := jsonArray(field(raw, "signatures")); ok {
		env.Signatures = []dsseSignature{}
		for _, sig := range sigs {
			var one dsseSignature
			if v, ok := jsonString(field(sig, "sig")); ok {
				one.Sig = &v
			}
			env.Signatures = append(env.Signatures, one)
		}
	}
	return env
}

// dssePAE is DSSE's pre-authentication encoding: what the statement key signs
// and what the log entry's digest is taken over.
func dssePAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

// verifyEnvelope is check 1: one signature, verifying over the PAE against a
// statement key held. Returns that key.
func verifyEnvelope(env dsseEnvelope, statementKeys [][]byte) ([]byte, error) {
	if env.PayloadType == nil || env.Payload == nil || env.Signatures == nil {
		return nil, errors.New("the statement envelope is not the DSSE form we write")
	}
	payload, err := base64.StdEncoding.DecodeString(*env.Payload)
	if err != nil {
		return nil, errors.New("the statement envelope is not the DSSE form we write")
	}
	if *env.PayloadType != statementPayloadType {
		return nil, fmt.Errorf("the statement envelope's payload type is %s, not a release statement", *env.PayloadType)
	}
	if len(env.Signatures) != 1 || env.Signatures[0].Sig == nil {
		return nil, errors.New("the statement envelope must carry exactly one signature")
	}
	sig, err := base64.StdEncoding.DecodeString(*env.Signatures[0].Sig)
	if err != nil || len(sig) == 0 {
		return nil, errors.New("the statement signature is not base64")
	}
	digest := sha256.Sum256(dssePAE(*env.PayloadType, payload))
	for _, der := range statementKeys {
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			continue
		}
		if ec, ok := pub.(*ecdsa.PublicKey); ok && ec.Curve == elliptic.P256() && ecdsa.VerifyASN1(ec, digest[:], sig) {
			return der, nil
		}
	}
	return nil, errors.New("the statement is not signed by a statement key this machine trusts")
}

// verifyLeafBinding is check 2: the leaf bytes are a hashedrekord entry for
// exactly this envelope, written under signer, and the canonical form of what
// they decode to — so the fields read here are the bytes hashed into the tree.
func verifyLeafBinding(leafBytes []byte, env dsseEnvelope, signer []byte) error {
	dec := json.NewDecoder(bytes.NewReader(leafBytes))
	dec.UseNumber()
	var decoded interface{}
	if err := dec.Decode(&decoded); err != nil || dec.More() {
		return errors.New("the log entry is not canonical JSON")
	}
	leaf, isObject := decoded.(map[string]interface{})
	canonical, ok := canonicalJSON(decoded)
	if !isObject || !ok || canonical != string(leafBytes) {
		return errors.New("the log entry is not canonical JSON")
	}
	hr, _ := jsonPath(leaf, "spec", "hashedRekordV002").(map[string]interface{})
	if leaf["kind"] != leafKind || leaf["apiVersion"] != leafAPIVersion || hr == nil {
		return fmt.Errorf("the log entry is not a %s %s entry", leafKind, leafAPIVersion)
	}
	payload, _ := base64.StdEncoding.DecodeString(*env.Payload)
	digest := sha256.Sum256(dssePAE(*env.PayloadType, payload))
	if jsonPath(hr, "data", "algorithm") != leafDigestAlg || !b64Equals(jsonPath(hr, "data", "digest"), digest[:]) {
		return errors.New("the log entry records a different statement than this one")
	}
	envSig, _ := base64.StdEncoding.DecodeString(*env.Signatures[0].Sig)
	if !b64Equals(jsonPath(hr, "signature", "content"), envSig) {
		return errors.New("the log entry carries a different signature than this statement")
	}
	if jsonPath(hr, "signature", "verifier", "keyDetails") != statementKeyType ||
		!b64Equals(jsonPath(hr, "signature", "verifier", "publicKey", "rawBytes"), signer) {
		return errors.New("the log entry was written under a different key than the one that signed this statement")
	}
	return nil
}

func jsonPath(v interface{}, keys ...string) interface{} {
	for _, key := range keys {
		m, ok := v.(map[string]interface{})
		if !ok {
			return nil
		}
		v = m[key]
	}
	return v
}

func b64Equals(v interface{}, want []byte) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	got, err := base64.StdEncoding.DecodeString(s)
	return err == nil && bytes.Equal(got, want)
}

// canonicalJSON is RFC 8785 for the shapes a log leaf takes — objects with
// sorted keys, arrays, printable-ASCII strings, integers, booleans — and false
// for anything else. It renders exactly what TransparencyProof::canonicalJson
// renders, quirks included, so the two verifiers accept the same leaves: an
// empty array is rendered {} and an object keyed "0".."n-1" in order is
// refused, both because PHP cannot tell those apart from each other once
// decoded. A hashedrekord leaf has neither.
func canonicalJSON(v interface{}) (string, bool) {
	switch t := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		list := len(keys) > 0
		for i, k := range keys {
			if k != strconv.Itoa(i) {
				list = false
				break
			}
		}
		if list {
			return "", false
		}
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			ck, ok := canonicalString(k)
			if !ok {
				return "", false
			}
			cv, ok := canonicalJSON(t[k])
			if !ok {
				return "", false
			}
			parts = append(parts, ck+":"+cv)
		}
		return "{" + strings.Join(parts, ",") + "}", true
	case []interface{}:
		if len(t) == 0 {
			return "{}", true
		}
		parts := make([]string, 0, len(t))
		for _, item := range t {
			c, ok := canonicalJSON(item)
			if !ok {
				return "", false
			}
			parts = append(parts, c)
		}
		return "[" + strings.Join(parts, ",") + "]", true
	case string:
		return canonicalString(t)
	case json.Number:
		if !jsonIntPattern.MatchString(t.String()) {
			return "", false
		}
		n, err := strconv.ParseInt(t.String(), 10, 64)
		if err != nil {
			return "", false
		}
		return strconv.FormatInt(n, 10), true
	case bool:
		if t {
			return "true", true
		}
		return "false", true
	}
	return "", false
}

func canonicalString(s string) (string, bool) {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			return "", false
		}
		if c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	b.WriteByte('"')
	return b.String(), true
}

type checkpoint struct {
	origin   string
	treeSize int64
	rootHash []byte
}

// verifyCheckpoint is check 3: a C2SP signed note from a log whose Ed25519
// key is held. Other signers on the note (witnesses) are ignored.
func verifyCheckpoint(note string, logKeys map[string][]byte) (*checkpoint, error) {
	split := strings.Index(note, "\n\n")
	if split < 0 || !strings.HasSuffix(note, "\n") {
		return nil, errors.New("the checkpoint is not a signed note")
	}
	body := note[:split+1]
	lines := strings.Split(body[:len(body)-1], "\n")
	if len(lines) < 3 || !checkpointSizePattern.MatchString(lines[1]) {
		return nil, errors.New("the checkpoint body is not origin, size, root")
	}
	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil {
		return nil, errors.New("the checkpoint body is not origin, size, root")
	}
	origin := lines[0]
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(root) != 32 {
		return nil, errors.New("the checkpoint root hash is malformed")
	}
	der, ok := logKeys[origin]
	if !ok {
		return nil, fmt.Errorf("the checkpoint is from %s, a log this machine holds no key for", origin)
	}
	pk, err := ed25519Raw(der)
	if err != nil {
		return nil, err
	}
	keyHash := sha256.Sum256(append([]byte(origin+"\n\x01"), pk...))
	for _, line := range strings.Split(strings.TrimRight(note[split+2:], "\n"), "\n") {
		m := noteSignaturePattern.FindStringSubmatch(line)
		if m == nil || m[1] != origin {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(m[2])
		if err != nil || len(raw) != 68 || !bytes.Equal(raw[:4], keyHash[:4]) {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pk), []byte(body), raw[4:]) {
			return &checkpoint{origin: origin, treeSize: size, rootHash: root}, nil
		}
	}
	return nil, fmt.Errorf("the checkpoint is not signed by %s's key", origin)
}

func rfc6962Leaf(leaf []byte) []byte {
	sum := sha256.Sum256(append([]byte{0x00}, leaf...))
	return sum[:]
}

func rfc6962Node(left, right []byte) []byte {
	buf := make([]byte, 0, 1+len(left)+len(right))
	buf = append(buf, 0x01)
	buf = append(buf, left...)
	buf = append(buf, right...)
	sum := sha256.Sum256(buf)
	return sum[:]
}

// inclusionHolds is check 4: RFC 9162 section 2.1.3.2, the audit path from
// leaf index in a tree of size leaves arrives at root.
func inclusionHolds(leafHash []byte, index, size int64, path [][]byte, root []byte) bool {
	if index < 0 || index >= size {
		return false
	}
	fn, sn := index, size-1
	r := leafHash
	for _, p := range path {
		if sn == 0 || len(p) != 32 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = rfc6962Node(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = rfc6962Node(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(root, r)
}

// jsonInt reads a JSON integer, or a string holding one.
func jsonInt(raw json.RawMessage) (int64, bool) {
	text := strings.TrimSpace(string(raw))
	if strings.HasPrefix(text, `"`) {
		var s string
		if json.Unmarshal(raw, &s) != nil || !textIntPattern.MatchString(s) {
			return 0, false
		}
		text = strings.TrimPrefix(s, "+")
	} else if !jsonIntPattern.MatchString(text) {
		return 0, false
	}
	n, err := strconv.ParseInt(text, 10, 64)
	return n, err == nil
}

// verifyEntry runs all four checks over one stored entry against one log key
// per origin.
func verifyEntry(env dsseEnvelope, entry map[string]json.RawMessage, statementKeys [][]byte, logKeys map[string][]byte) error {
	for _, field := range []string{"log_origin", "log_index", "leaf", "inclusion_proof", "checkpoint"} {
		if raw, ok := entry[field]; !ok || string(raw) == "null" {
			return fmt.Errorf("the log entry has no %s", field)
		}
	}
	signer, err := verifyEnvelope(env, statementKeys)
	if err != nil {
		return err
	}

	var leafB64, origin, note string
	json.Unmarshal(entry["leaf"], &leafB64)
	json.Unmarshal(entry["log_origin"], &origin)
	leaf, err := base64.StdEncoding.DecodeString(leafB64)
	if err != nil || len(leaf) == 0 {
		return errors.New("the log entry has no leaf bytes")
	}
	if err := verifyLeafBinding(leaf, env, signer); err != nil {
		return err
	}

	if json.Unmarshal(entry["checkpoint"], &note) != nil {
		return errors.New("the checkpoint is not a signed note")
	}
	cp, err := verifyCheckpoint(note, logKeys)
	if err != nil {
		return err
	}
	if cp.origin != origin {
		return fmt.Errorf("the checkpoint is from %s, the entry says %s", cp.origin, origin)
	}

	proof := entry["inclusion_proof"]
	var path [][]byte
	hashes, _ := jsonArray(field(proof, "hashes"))
	for _, h := range hashes {
		text, _ := jsonString(h)
		raw, _ := base64.StdEncoding.DecodeString(text)
		path = append(path, raw)
	}
	index, okIndex := jsonInt(entry["log_index"])
	size, okSize := jsonInt(field(proof, "tree_size"))
	rootText, _ := jsonString(field(proof, "root_hash"))
	proofRoot, rootErr := base64.StdEncoding.DecodeString(rootText)
	if !okIndex || !okSize || size != cp.treeSize || rootErr != nil || !bytes.Equal(proofRoot, cp.rootHash) {
		return errors.New("the inclusion proof is for a different tree than the checkpoint")
	}
	if !inclusionHolds(rfc6962Leaf(leaf), index, size, path, cp.rootHash) {
		return fmt.Errorf("the inclusion proof does not place this entry at index %d of %s", index, cp.origin)
	}
	return nil
}

// entryVerifies is "" when the entry verifies against one of the keys held
// for its log, and otherwise why not.
func entryVerifies(env dsseEnvelope, entry map[string]json.RawMessage, keys releaseLogKeys) string {
	var origin string
	json.Unmarshal(entry["log_origin"], &origin)
	why := fmt.Sprintf("the statement is logged on %s, a log this machine holds no key for", origin)
	for _, der := range keys.log[origin] {
		err := verifyEntry(env, entry, keys.statement, map[string][]byte{origin: der})
		if err == nil {
			return ""
		}
		why = err.Error()
	}
	return why
}

// statementPayload is the part of a statement's payload this agent reads.
// The payload is the statement's own JSON, read by exact key.
type statementPayload struct {
	raw json.RawMessage
}

func decodePayload(env dsseEnvelope) statementPayload {
	if env.Payload == nil {
		return statementPayload{}
	}
	raw, err := base64.StdEncoding.DecodeString(*env.Payload)
	if err != nil {
		return statementPayload{}
	}
	return statementPayload{raw: raw}
}

func (p statementPayload) version() string {
	v, _ := jsonString(field(p.raw, "version"))
	return v
}

// artifact is the hash the statement records under name, or "".
func (p statementPayload) artifact(name string) string {
	v, _ := jsonString(field(field(p.raw, "artifacts"), name))
	return v
}

func (p statementPayload) keysInstalled() json.RawMessage {
	return field(p.raw, "keys_installed")
}

// payloadKeys is the statement and log keys a statement installs, P-256 and
// Ed25519 only.
func payloadKeys(env dsseEnvelope) releaseLogKeys {
	keys := newReleaseLogKeys()
	installed := decodePayload(env).keysInstalled()
	statementKeys, _ := jsonArray(field(installed, "statement_keys"))
	for _, item := range statementKeys {
		b64, _ := jsonString(item)
		if der, err := base64.StdEncoding.DecodeString(b64); err == nil && isP256(der) {
			keys.addStatement(der)
		}
	}
	logKeys, _ := jsonArray(field(installed, "log_keys"))
	for _, pair := range logKeys {
		origin, _ := jsonString(field(pair, "origin"))
		b64, _ := jsonString(field(pair, "key"))
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || !logOriginPattern.MatchString(origin) {
			continue
		}
		if _, err := ed25519Raw(der); err == nil {
			keys.addLog(origin, der)
		}
	}
	return keys
}

// statementLink is one statement and its entry, as RELEASE_STATEMENT and each
// key_chain link carry them.
type statementLink struct {
	env   dsseEnvelope
	entry map[string]json.RawMessage
}

func decodeLink(raw json.RawMessage) (*statementLink, bool) {
	envelope := field(raw, "envelope")
	entry, ok := jsonObject(field(raw, "entry"))
	if _, isObject := jsonObject(envelope); !isObject || !ok {
		return nil, false
	}
	return &statementLink{env: decodeEnvelope(envelope), entry: entry}, true
}

func isJSONObject(raw json.RawMessage) bool {
	t := strings.TrimSpace(string(raw))
	return strings.HasPrefix(t, "{")
}

// releaseLogVerdict is what a statement that verified says.
type releaseLogVerdict struct {
	origin  string
	index   int64
	version string
	// proven is every key the key chain proved that was not already held:
	// the install step writes these, the check never does.
	proven releaseLogKeys
}

// verifyReleaseStatement checks a RELEASE_STATEMENT against the keys held and
// that it records sha256Hex under artifact (agent/<platform>). It reads
// nothing and writes nothing.
func verifyReleaseStatement(doc []byte, artifact, sha256Hex string, held releaseLogKeys) (*releaseLogVerdict, error) {
	if len(bytes.TrimSpace(doc)) == 0 {
		return nil, fmt.Errorf("the release carries no %s", releaseStatementName)
	}
	link, ok := decodeLink(doc)
	if !ok {
		return nil, errors.New("the statement is not the format the publisher writes")
	}
	chain, _ := jsonArray(field(doc, "key_chain"))

	if !held.holds() {
		return nil, errors.New("this machine holds no statement key or no log key to check a statement with")
	}

	// The chain, forward from what this machine holds: a link that verifies
	// under the keys held so far adds the keys it installs; one that does not
	// adds nothing.
	keys := held.clone()
	for _, raw := range chain {
		chainLink, ok := decodeLink(raw)
		if !ok || entryVerifies(chainLink.env, chainLink.entry, keys) != "" {
			continue
		}
		keys.merge(payloadKeys(chainLink.env))
	}

	if why := entryVerifies(link.env, link.entry, keys); why != "" {
		return nil, errors.New(why)
	}
	payload := decodePayload(link.env)
	recorded, rerr := hex.DecodeString(payload.artifact(artifact))
	offered, oerr := hex.DecodeString(sha256Hex)
	if rerr != nil || oerr != nil || len(recorded) != sha256.Size || !bytes.Equal(recorded, offered) {
		return nil, fmt.Errorf("the logged statement does not record this binary as %s", artifact)
	}

	var origin string
	json.Unmarshal(link.entry["log_origin"], &origin)
	index, _ := jsonInt(link.entry["log_index"])
	return &releaseLogVerdict{origin: origin, index: index, version: payload.version(), proven: keys.minus(held)}, nil
}
