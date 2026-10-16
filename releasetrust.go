package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The trusted set (specs/release_key_rotation.md R1-R3).
//
// The release keys and statement keys this machine trusts are one set: the
// keys the last release that changed it installed. Each statement names,
// beside the keys it installs, its authority: the release and statement keys
// allowed to sign the next change. A statement from before the field has the
// whole set as its authority. The keys compiled into this binary
// (updatePubKeyB64, releaseStatementKeysB64) are only the starting set: once a
// release has been verified here, the set it left is recorded in the agent's
// state directory (release_trust) and wins over them.
//
// Walking a statement's key chain, a link that does not verify under the
// statement keys held adds nothing; one that installs the set already held
// adds the log keys it installs; one that installs another set replaces the
// set only when its statement is signed by a statement key of the authority
// held, and otherwise adds nothing. A release whose own set differs from the
// set the walk ends with must be signed, statement and binary or manifest, by
// keys of that authority, or it is refused. So a key is retired by a release,
// signed by the authority, that leaves it out; once the authority has moved
// to new keys, the old ones cannot change the set back. The rule and the
// record's format are the site's own (PackageSignature, config/release_trust).

// releaseTrustFileName is the record, in agentStateDir(): JSON
// {format, release_keys, statement_keys, authority {release_keys,
// statement_keys}, set_by, retired {release_keys, statement_keys},
// recorded_at}, base64. retired is kept only to say so; nothing trusts it.
const releaseTrustFileName = "release_trust"

// errUnauthorizedKeys is a release that changes the trusted set without the
// authority to.
var errUnauthorizedKeys = errors.New("the release changes which keys this machine trusts, but is not signed by the keys allowed to change them")

// trustKeys is a set of release keys (raw Ed25519) and statement keys (P-256 DER).
type trustKeys struct {
	release   [][]byte
	statement [][]byte
}

// releaseTrust is a trusted set and its authority; a nil authority is the
// whole set.
type releaseTrust struct {
	trustKeys
	authority *trustKeys
	setBy     string
}

func containsKey(set [][]byte, key []byte) bool {
	for _, have := range set {
		if bytes.Equal(have, key) {
			return true
		}
	}
	return false
}

func addKey(set [][]byte, key []byte) [][]byte {
	if containsKey(set, key) {
		return set
	}
	return append(set, key)
}

// sameKeySet is whether two lists hold the same keys, in any order.
func sameKeySet(a, b [][]byte) bool {
	var ua, ub [][]byte
	for _, k := range a {
		ua = addKey(ua, k)
	}
	for _, k := range b {
		ub = addKey(ub, k)
	}
	if len(ua) != len(ub) {
		return false
	}
	for _, k := range ua {
		if !containsKey(ub, k) {
			return false
		}
	}
	return true
}

// effectiveAuthority is the set's authority, the whole set when it names none.
func (t releaseTrust) effectiveAuthority() trustKeys {
	if t.authority != nil {
		return *t.authority
	}
	return t.trustKeys
}

// sameTrust is whether two sets hold the same keys and the same authority.
func sameTrust(a, b releaseTrust) bool {
	aa, ba := a.effectiveAuthority(), b.effectiveAuthority()
	return sameKeySet(a.release, b.release) && sameKeySet(a.statement, b.statement) &&
		sameKeySet(aa.release, ba.release) && sameKeySet(aa.statement, ba.statement)
}

// releasePublicKeys is the set's release keys as ed25519 keys.
func (t releaseTrust) releasePublicKeys() []ed25519.PublicKey {
	out := make([]ed25519.PublicKey, 0, len(t.release))
	for _, k := range t.release {
		out = append(out, ed25519.PublicKey(k))
	}
	return out
}

var bakedReleaseKeysOnce sync.Once

// bakedReleaseKeys reads the release keys compiled into this binary:
// updatePubKeyB64, comma-separated. A malformed entry is a build fault, said
// once; the rest still count.
func bakedReleaseKeys() [][]byte {
	var keys [][]byte
	bad := false
	for _, item := range strings.Split(updatePubKeyB64, ",") {
		if item = strings.TrimSpace(item); item == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(item)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			bad = true
			continue
		}
		keys = addKey(keys, raw)
	}
	if bad {
		bakedReleaseKeysOnce.Do(func() {
			log.Printf("release keys: a release key compiled into this build is malformed; ignored")
		})
	}
	return keys
}

// decodeReleaseKeys reads a JSON array of base64 Ed25519 keys; anything else is skipped.
func decodeReleaseKeys(raw json.RawMessage) [][]byte {
	items, _ := jsonArray(raw)
	var out [][]byte
	for _, item := range items {
		b64, _ := jsonString(item)
		if key, err := base64.StdEncoding.DecodeString(b64); err == nil && len(key) == ed25519.PublicKeySize {
			out = addKey(out, key)
		}
	}
	return out
}

// payloadTrust is the trusted set a statement's payload installs, or nil when
// it names no release key or no statement key. An authority naming a key
// outside the set, or leaving a kind empty, is read as none at all.
func payloadTrust(env dsseEnvelope) *releaseTrust {
	payload := decodePayload(env)
	release := decodeReleaseKeys(field(payload.keysInstalled(), "release_keys"))
	statement := payloadKeys(env).statement
	if len(release) == 0 || len(statement) == 0 {
		return nil
	}
	t := &releaseTrust{trustKeys: trustKeys{release: release, statement: statement}, setBy: payload.version()}
	authority := field(payload.raw, "authority")
	if isJSONObject(authority) {
		var ar, as [][]byte
		for _, k := range decodeReleaseKeys(field(authority, "release_keys")) {
			if containsKey(release, k) {
				ar = addKey(ar, k)
			}
		}
		items, _ := jsonArray(field(authority, "statement_keys"))
		for _, item := range items {
			b64, _ := jsonString(item)
			if der, err := base64.StdEncoding.DecodeString(b64); err == nil && containsKey(statement, der) {
				as = addKey(as, der)
			}
		}
		if len(ar) > 0 && len(as) > 0 {
			t.authority = &trustKeys{release: ar, statement: as}
		}
	}
	return t
}

// trustRecord is release_trust on disk.
type trustRecord struct {
	Format        int           `json:"format"`
	ReleaseKeys   []string      `json:"release_keys"`
	StatementKeys []string      `json:"statement_keys"`
	Authority     trustKeyLists `json:"authority"`
	SetBy         *string       `json:"set_by"`
	Retired       trustKeyLists `json:"retired"`
	RecordedAt    string        `json:"recorded_at"`
}

type trustKeyLists struct {
	ReleaseKeys   []string `json:"release_keys"`
	StatementKeys []string `json:"statement_keys"`
}

func encodeKeys(keys [][]byte) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, base64.StdEncoding.EncodeToString(k))
	}
	sort.Strings(out)
	return out
}

func decodeRecordKeys(b64s []string, statement bool) [][]byte {
	var out [][]byte
	for _, b64 := range b64s {
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil {
			continue
		}
		if statement && !isP256(key) {
			continue
		}
		if !statement && len(key) != ed25519.PublicKeySize {
			continue
		}
		out = addKey(out, key)
	}
	return out
}

// readReleaseTrust is the set recorded in dir, and the keys it has retired,
// or nil when there is no record, it is not root's alone, or it is not one.
func readReleaseTrust(dir string) (*releaseTrust, trustKeys) {
	if dir == "" {
		return nil, trustKeys{}
	}
	path := filepath.Join(dir, releaseTrustFileName)
	if _, err := os.Stat(path); err != nil || !trustedKeyFile(path) {
		return nil, trustKeys{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, trustKeys{}
	}
	var rec trustRecord
	if json.Unmarshal(data, &rec) != nil || rec.Format != 1 {
		return nil, trustKeys{}
	}
	t := releaseTrust{trustKeys: trustKeys{
		release:   decodeRecordKeys(rec.ReleaseKeys, false),
		statement: decodeRecordKeys(rec.StatementKeys, true),
	}}
	if rec.SetBy != nil {
		t.setBy = *rec.SetBy
	}
	if len(t.release) == 0 || len(t.statement) == 0 {
		return nil, trustKeys{}
	}
	ar := decodeRecordKeys(rec.Authority.ReleaseKeys, false)
	as := decodeRecordKeys(rec.Authority.StatementKeys, true)
	if len(ar) > 0 && len(as) > 0 {
		t.authority = &trustKeys{release: ar, statement: as}
	}
	retired := trustKeys{
		release:   decodeRecordKeys(rec.Retired.ReleaseKeys, false),
		statement: decodeRecordKeys(rec.Retired.StatementKeys, true),
	}
	return &t, retired
}

// heldReleaseTrust is the set this machine trusts now: its record, or the
// compiled-in release keys (baked) with the statement keys it holds and no
// authority of its own (the whole set).
func heldReleaseTrust(dir string, baked, statement [][]byte) releaseTrust {
	if rec, _ := readReleaseTrust(dir); rec != nil {
		return *rec
	}
	return releaseTrust{trustKeys: trustKeys{release: baked, statement: statement}}
}

// heldReleaseKeys is the release keys a signature is checked against now, for
// the checks that have no statement to walk: the record's, or the compiled-in
// ones. Read at each call, so a set a release changed takes effect at once.
func heldReleaseKeys(dir string, baked [][]byte) []ed25519.PublicKey {
	return heldReleaseTrust(dir, baked, nil).releasePublicKeys()
}

// releaseKeysOf is a fixed list of ed25519 keys as raw bytes.
func releaseKeysOf(keys ...ed25519.PublicKey) [][]byte {
	var out [][]byte
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize {
			out = addKey(out, []byte(k))
		}
	}
	return out
}

// signerOf is the key in keys that signed message, or nil. Exactly one
// Ed25519 signature: anything longer or shorter is no signature at all.
func signerOf(keys []ed25519.PublicKey, message, signature []byte) ed25519.PublicKey {
	if len(signature) != ed25519.SignatureSize {
		return nil
	}
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, message, signature) {
			return k
		}
	}
	return nil
}

// persistReleaseTrust records t in dir when it differs from the set held: the
// record, with the keys it drops kept as retired, and the statement key file
// rewritten to the set, so nothing that reads it holds a retired key. Each
// file is replaced whole. Returns a line for each change.
func persistReleaseTrust(dir string, t releaseTrust, baked releaseLogKeys, bakedRelease [][]byte) ([]string, error) {
	if dir == "" || len(t.release) == 0 || len(t.statement) == 0 {
		return nil, nil
	}
	prev, retired := readReleaseTrust(dir)
	if prev != nil && sameTrust(*prev, t) {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var priorRelease, priorStatement [][]byte
	if prev != nil {
		priorRelease, priorStatement = prev.release, prev.statement
	} else {
		priorRelease = bakedRelease
		held := baked.clone()
		held.merge(readReleaseLogKeyFiles(dir))
		priorStatement = held.statement
	}
	for _, k := range priorRelease {
		if !containsKey(t.release, k) {
			retired.release = addKey(retired.release, k)
		}
	}
	for _, k := range priorStatement {
		if !containsKey(t.statement, k) {
			retired.statement = addKey(retired.statement, k)
		}
	}
	var keptRelease, keptStatement [][]byte
	for _, k := range retired.release {
		if !containsKey(t.release, k) {
			keptRelease = append(keptRelease, k)
		}
	}
	for _, k := range retired.statement {
		if !containsKey(t.statement, k) {
			keptStatement = append(keptStatement, k)
		}
	}
	authority := t.effectiveAuthority()
	var setBy *string
	if t.setBy != "" {
		v := t.setBy
		setBy = &v
	}
	body, err := json.MarshalIndent(trustRecord{
		Format:        1,
		ReleaseKeys:   encodeKeys(t.release),
		StatementKeys: encodeKeys(t.statement),
		Authority:     trustKeyLists{ReleaseKeys: encodeKeys(authority.release), StatementKeys: encodeKeys(authority.statement)},
		SetBy:         setBy,
		Retired:       trustKeyLists{ReleaseKeys: encodeKeys(keptRelease), StatementKeys: encodeKeys(keptStatement)},
		RecordedAt:    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}, "", "    ")
	if err != nil {
		return nil, err
	}
	statementLines := strings.Join(encodeKeys(t.statement), "\n") + "\n"
	if err := replaceFile(filepath.Join(dir, statementKeysFileName), []byte(statementLines)); err != nil {
		return nil, err
	}
	if err := replaceFile(filepath.Join(dir, releaseTrustFileName), append(body, '\n')); err != nil {
		return nil, err
	}
	line := releaseTrustFileName + ": " + strconv.Itoa(len(t.release)) + " release and " + strconv.Itoa(len(t.statement)) + " statement key(s)"
	if t.setBy != "" {
		line += ", set by " + t.setBy
	}
	if n := len(keptRelease) + len(keptStatement); n > 0 {
		line += ", " + strconv.Itoa(n) + " retired"
	}
	return []string{line}, nil
}

// trustFingerprints names a set of keys for a report: the first 12 hex
// characters of each key's sha256, sorted.
func trustFingerprints(keys [][]byte) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		sum := sha256.Sum256(k)
		out = append(out, hex.EncodeToString(sum[:])[:12])
	}
	sort.Strings(out)
	return out
}

// reportReleaseTrust is what check_status reports of the trusted sets on this
// machine (specs/release_key_rotation.md R6): the agent's, and the site's in
// siteRoot where there is one, so each step of a key rotation is a check on
// every node. Each side is {recorded, release, statement, authority, set_by},
// keys named by trustFingerprints; recorded false is a set from the compiled-in
// keys or the site's key files, before any release recorded one, and has the
// whole set as its authority (null). A record or key file that is not root's
// alone is passed over, as the checks that trust it pass it over.
func reportReleaseTrust(siteRoot string) map[string]interface{} {
	dir := agentStateDir()
	out := map[string]interface{}{}
	if rec, _ := readReleaseTrust(dir); rec != nil {
		out["agent"] = trustReport(*rec, true)
	} else {
		held := heldReleaseLogKeys(bakedReleaseLogKeys(), dir)
		out["agent"] = trustReport(releaseTrust{trustKeys: trustKeys{release: bakedReleaseKeys(), statement: held.statement}}, false)
	}
	if siteRoot != "" {
		config := filepath.Join(siteRoot, "config")
		if rec, _ := readReleaseTrust(config); rec != nil {
			out["site"] = trustReport(*rec, true)
		} else {
			out["site"] = trustReport(releaseTrust{trustKeys: trustKeys{
				release:   siteKeyFile(filepath.Join(config, "release_verify_keys"), false),
				statement: siteKeyFile(filepath.Join(config, "release_statement_keys"), true),
			}}, false)
		}
	}
	return out
}

// trustReport is one trusted set as check_status names it.
func trustReport(t releaseTrust, recorded bool) map[string]interface{} {
	r := map[string]interface{}{
		"recorded":  recorded,
		"release":   trustFingerprints(t.release),
		"statement": trustFingerprints(t.statement),
		"authority": nil,
		"set_by":    nil,
	}
	if t.authority != nil {
		r["authority"] = map[string]interface{}{
			"release":   trustFingerprints(t.authority.release),
			"statement": trustFingerprints(t.authority.statement),
		}
	}
	if t.setBy != "" {
		r["set_by"] = t.setBy
	}
	return r
}

// siteKeyFile is a site key file's keys, one base64 key a line (a release
// key's raw bytes, a statement key's DER), or none where the file is missing
// or not root's alone.
func siteKeyFile(path string, statement bool) [][]byte {
	if !trustedKeyFile(path) {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return decodeRecordKeys(strings.Fields(string(data)), statement)
}

// retiredNote names the release key, among those the record in dir has
// retired, that made signature over message: the reason a release signed
// before a rotation is refused after it (specs/release_key_rotation.md F6),
// as the site says it. "" when none did.
func retiredNote(dir string, message, signature []byte) string {
	_, retired := readReleaseTrust(dir)
	for _, raw := range retired.release {
		if len(raw) == ed25519.PublicKeySize && len(signature) == ed25519.SignatureSize && ed25519.Verify(raw, message, signature) {
			return "; it is signed by release key " + trustFingerprints([][]byte{raw})[0] + ", which this machine's trusted set has retired"
		}
	}
	return ""
}

// treeRetiredNote is retiredNote for the signed manifest at root.
func treeRetiredNote(dir, root string) string {
	body, err := os.ReadFile(filepath.Join(root, primitivesManifestName))
	if err != nil {
		return ""
	}
	sigRaw, err := os.ReadFile(filepath.Join(root, primitivesSignatureName))
	if err != nil {
		return ""
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil {
		return ""
	}
	return retiredNote(dir, body, sig)
}
