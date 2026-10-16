package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The trusted set and its authority (specs/release_key_rotation.md R1-R3),
// through verifyReleaseStatementTrust and settle, the record, and the
// self-update: a rotation M -> N -> N+1, a machine that missed a step, and a
// thief holding the old keys.

type rotationKeys struct {
	oldRelease, newRelease     ed25519.PublicKey
	oldReleasePriv, newRelPriv ed25519.PrivateKey
	oldStatement, newStatement testStatementKey
	log                        testLog
}

func newRotationKeys(t *testing.T) rotationKeys {
	t.Helper()
	op, opriv, _ := ed25519.GenerateKey(rand.Reader)
	np, npriv, _ := ed25519.GenerateKey(rand.Reader)
	return rotationKeys{
		oldRelease: op, oldReleasePriv: opriv, newRelease: np, newRelPriv: npriv,
		oldStatement: newTestStatementKey(t), newStatement: newTestStatementKey(t),
		log: newTestLog(t, "log2025-1.rekor.test"),
	}
}

// trustPayload is a statement payload installing release and statement keys,
// the log's key, and, when authority is set, that authority.
func trustPayload(t *testing.T, version string, artifacts map[string]string, release []ed25519.PublicKey, statement []testStatementKey,
	l testLog, authRelease []ed25519.PublicKey, authStatement []testStatementKey) []byte {
	t.Helper()
	enc := func(keys []ed25519.PublicKey) []string {
		out := []string{}
		for _, k := range keys {
			out = append(out, b64(k))
		}
		return out
	}
	encS := func(keys []testStatementKey) []string {
		out := []string{}
		for _, k := range keys {
			out = append(out, b64(k.der))
		}
		return out
	}
	doc := map[string]interface{}{
		"version":   version,
		"artifacts": artifacts,
		"keys_installed": map[string]interface{}{
			"release_keys": enc(release), "statement_keys": encS(statement),
			"log_keys": []map[string]string{{"origin": l.origin, "key": b64(l.der)}},
		},
	}
	if authRelease != nil {
		doc["authority"] = map[string]interface{}{"release_keys": enc(authRelease), "statement_keys": encS(authStatement)}
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// link is one logged statement as a key_chain link and as a document.
type link struct {
	env, entry map[string]interface{}
}

func (k rotationKeys) logged(t *testing.T, signer testStatementKey, payload []byte) link {
	t.Helper()
	env, entry := loggedEnv(t, signer, k.log, payload)
	return link{env: env, entry: entry}
}

func (l link) chainLink() map[string]interface{} {
	return map[string]interface{}{"envelope": l.env, "entry": l.entry}
}

func (l link) doc(t *testing.T, chain ...link) []byte {
	t.Helper()
	var c []map[string]interface{}
	for _, x := range chain {
		c = append(c, x.chainLink())
	}
	return statementDoc(t, l.env, l.entry, c...)
}

// ceremony builds genesis, M, N and N+1, each recording binary as agent/linux-amd64.
func (k rotationKeys) ceremony(t *testing.T, binary []byte) (g, m, n, n1 link) {
	t.Helper()
	sum := sha256.Sum256(binary)
	art := map[string]string{"agent/linux-amd64": hex.EncodeToString(sum[:])}
	old := []ed25519.PublicKey{k.oldRelease}
	oldS := []testStatementKey{k.oldStatement}
	both := []ed25519.PublicKey{k.oldRelease, k.newRelease}
	bothS := []testStatementKey{k.oldStatement, k.newStatement}
	nu := []ed25519.PublicKey{k.newRelease}
	nuS := []testStatementKey{k.newStatement}
	g = k.logged(t, k.oldStatement, trustPayload(t, "0.9.1", art, old, oldS, k.log, nil, nil))
	m = k.logged(t, k.oldStatement, trustPayload(t, "0.9.2", art, old, oldS, k.log, old, oldS))
	n = k.logged(t, k.oldStatement, trustPayload(t, "0.9.3", art, both, bothS, k.log, nu, nuS))
	n1 = k.logged(t, k.newStatement, trustPayload(t, "0.9.4", art, nu, nuS, k.log, nu, nuS))
	return
}

func trustOf(release []ed25519.PublicKey, statement []testStatementKey, authRelease []ed25519.PublicKey, authStatement []testStatementKey) releaseTrust {
	t := releaseTrust{trustKeys: trustKeys{release: releaseKeysOf(release...)}}
	for _, s := range statement {
		t.statement = addKey(t.statement, s.der)
	}
	if authRelease != nil {
		a := trustKeys{release: releaseKeysOf(authRelease...)}
		for _, s := range authStatement {
			a.statement = addKey(a.statement, s.der)
		}
		t.authority = &a
	}
	return t
}

func logKeysOf(l testLog) releaseLogKeys {
	k := newReleaseLogKeys()
	k.addLog(l.origin, l.der)
	return k
}

func binarySum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func wantSet(t *testing.T, why string, got releaseTrust, release []ed25519.PublicKey, statement []testStatementKey, authRelease []ed25519.PublicKey) {
	t.Helper()
	want := trustOf(release, statement, authRelease, nil)
	if !sameKeySet(got.release, want.release) || !sameKeySet(got.statement, want.statement) ||
		!sameKeySet(got.effectiveAuthority().release, want.authority.release) {
		t.Fatalf("%s: the set is not the one expected", why)
	}
}

func TestTheCeremonyMovesTheSetAndAMachineThatMissedAStepFollows(t *testing.T) {
	k := newRotationKeys(t)
	bin := []byte("AGENT")
	g, m, n, n1 := k.ceremony(t, bin)
	logs := logKeysOf(k.log)
	old := []ed25519.PublicKey{k.oldRelease}
	nu := []ed25519.PublicKey{k.newRelease}
	both := []ed25519.PublicKey{k.oldRelease, k.newRelease}
	bothS := []testStatementKey{k.oldStatement, k.newStatement}

	atM := trustOf(old, []testStatementKey{k.oldStatement}, old, []testStatementKey{k.oldStatement})
	v, err := verifyReleaseStatementTrust(n.doc(t, g, m), "agent/linux-amd64", binarySum(bin), withStatement(logs, atM.statement), atM)
	if err != nil {
		t.Fatalf("at M, N's statement: %v", err)
	}
	set, err := v.settle(k.oldRelease)
	if err != nil {
		t.Fatalf("at M, N signed by the old keys (the authority) is refused: %v", err)
	}
	wantSet(t, "N adds the new keys and makes them the authority", set, both, bothS, nu)

	atN := trustOf(both, bothS, nu, []testStatementKey{k.newStatement})
	v, err = verifyReleaseStatementTrust(n1.doc(t, g, m, n), "agent/linux-amd64", binarySum(bin), withStatement(logs, atN.statement), atN)
	if err != nil {
		t.Fatalf("at N, N+1's statement: %v", err)
	}
	if set, err = v.settle(k.newRelease); err != nil {
		t.Fatalf("at N, N+1 signed by the new keys is refused: %v", err)
	}
	wantSet(t, "N+1 drops the old keys", set, nu, []testStatementKey{k.newStatement}, nu)

	v, err = verifyReleaseStatementTrust(n1.doc(t, g, m, n), "agent/linux-amd64", binarySum(bin), withStatement(logs, atM.statement), atM)
	if err != nil {
		t.Fatalf("a machine that missed N cannot read N+1's statement: %v", err)
	}
	if !containsKey(releaseKeysOf(v.releaseKeys()...), k.newRelease) {
		t.Fatal("walking N's link must give a machine that missed N the new release key")
	}
	if set, err = v.settle(k.newRelease); err != nil {
		t.Fatalf("a machine that missed N refuses N+1: %v", err)
	}
	wantSet(t, "and adopts N+1's set", set, nu, []testStatementKey{k.newStatement}, nu)

	beforeM := releaseTrust{trustKeys: trustKeys{release: releaseKeysOf(k.oldRelease), statement: [][]byte{k.oldStatement.der}}}
	v, err = verifyReleaseStatementTrust(n1.doc(t, g, m, n), "agent/linux-amd64", binarySum(bin), withStatement(logs, beforeM.statement), beforeM)
	if err != nil {
		t.Fatalf("a machine from before M cannot read N+1's statement: %v", err)
	}
	if set, err = v.settle(k.newRelease); err != nil {
		t.Fatalf("a machine from before M refuses N+1: %v", err)
	}
	wantSet(t, "a machine from before M ends on N+1's set", set, nu, []testStatementKey{k.newStatement}, nu)
}

func TestAThiefWithTheOldKeysCannotMoveTheSet(t *testing.T) {
	k := newRotationKeys(t)
	bin := []byte("THIEF")
	g, m, n, n1 := k.ceremony(t, bin)
	logs := logKeysOf(k.log)
	old := []ed25519.PublicKey{k.oldRelease}
	oldS := []testStatementKey{k.oldStatement}
	nu := []ed25519.PublicKey{k.newRelease}
	both := []ed25519.PublicKey{k.oldRelease, k.newRelease}
	bothS := []testStatementKey{k.oldStatement, k.newStatement}
	art := map[string]string{"agent/linux-amd64": binarySum(bin)}

	// After N: the old keys back as the set and the authority, N's real chain copied in.
	theft := k.logged(t, k.oldStatement, trustPayload(t, "0.9.5", art, old, oldS, k.log, old, oldS))
	atN := trustOf(both, bothS, nu, []testStatementKey{k.newStatement})
	v, err := verifyReleaseStatementTrust(theft.doc(t, g, m, n), "agent/linux-amd64", binarySum(bin), withStatement(logs, atN.statement), atN)
	if err != nil {
		t.Fatalf("the thief's statement is logged under a key still in the set and verifies: %v", err)
	}
	if _, err := v.settle(k.oldRelease); !errors.Is(err, errUnauthorizedKeys) {
		t.Fatalf("at N, a set change signed by the old keys must be refused; got %v", err)
	}

	// A forged link in the chain changing the set under the old key adds nothing.
	forged := k.logged(t, k.oldStatement, trustPayload(t, "0.9.6", map[string]string{"x": strings.Repeat("d", 64)}, old, oldS, k.log, old, oldS))
	v, err = verifyReleaseStatementTrust(theft.doc(t, g, m, n, forged), "agent/linux-amd64", binarySum(bin), withStatement(logs, atN.statement), atN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.settle(k.oldRelease); !errors.Is(err, errUnauthorizedKeys) {
		t.Fatalf("a forged link must add nothing; got %v", err)
	}
	if !sameKeySet(v.walked.release, atN.release) {
		t.Fatal("the forged link changed the walked set")
	}

	// After N+1, nothing under the old statement key verifies at all.
	atN1 := trustOf(nu, []testStatementKey{k.newStatement}, nu, []testStatementKey{k.newStatement})
	if _, err := verifyReleaseStatementTrust(theft.doc(t, g, m, n, n1), "agent/linux-amd64", binarySum(bin), withStatement(logs, atN1.statement), atN1); err == nil {
		t.Fatal("at N+1, a statement under the retired key must not verify")
	}
}

func TestTheSetIsRecordedAndReplacesTheStatementKeys(t *testing.T) {
	k := newRotationKeys(t)
	dir := t.TempDir()
	baked := keysOf(k.oldStatement, k.log)
	both := trustOf([]ed25519.PublicKey{k.oldRelease, k.newRelease}, []testStatementKey{k.oldStatement, k.newStatement},
		[]ed25519.PublicKey{k.newRelease}, []testStatementKey{k.newStatement})
	both.setBy = "0.9.3"
	lines, err := persistReleaseTrust(dir, both, baked, releaseKeysOf(k.oldRelease))
	if err != nil || len(lines) != 1 {
		t.Fatalf("N's set was not recorded: %v %v", lines, err)
	}
	rec, _ := readReleaseTrust(dir)
	if rec == nil || !sameTrust(*rec, both) || rec.setBy != "0.9.3" {
		t.Fatal("the record does not read back as N's set")
	}
	if again, _ := persistReleaseTrust(dir, both, baked, releaseKeysOf(k.oldRelease)); len(again) != 0 {
		t.Fatal("the same set again must write nothing")
	}
	held := heldReleaseLogKeys(baked, dir)
	if !sameKeySet(held.statement, both.statement) || len(held.log[k.log.origin]) != 1 {
		t.Fatal("with a record, the statement keys held are the record's, and the log keys stay")
	}

	nu := trustOf([]ed25519.PublicKey{k.newRelease}, []testStatementKey{k.newStatement},
		[]ed25519.PublicKey{k.newRelease}, []testStatementKey{k.newStatement})
	if _, err := persistReleaseTrust(dir, nu, baked, releaseKeysOf(k.oldRelease)); err != nil {
		t.Fatal(err)
	}
	rec, retired := readReleaseTrust(dir)
	if rec == nil || !sameTrust(*rec, nu) {
		t.Fatal("N+1's set was not recorded")
	}
	if !containsKey(retired.release, k.oldRelease) || !containsKey(retired.statement, k.oldStatement.der) {
		t.Fatal("the dropped keys are kept as retired, for saying so")
	}
	if held := heldReleaseLogKeys(baked, dir); !sameKeySet(held.statement, [][]byte{k.newStatement.der}) {
		t.Fatal("the compiled-in old statement key must not come back once the record drops it")
	}
	data, _ := os.ReadFile(filepath.Join(dir, statementKeysFileName))
	if strings.Contains(string(data), b64(k.oldStatement.der)) {
		t.Fatal("the statement key file still names the retired key")
	}
	if keys := heldReleaseKeys(dir, releaseKeysOf(k.oldRelease)); len(keys) != 1 || !keys[0].Equal(k.newRelease) {
		t.Fatal("the release keys held are the record's, not the compiled-in ones")
	}

	if err := os.Chmod(filepath.Join(dir, releaseTrustFileName), 0o666); err != nil {
		t.Fatal(err)
	}
	if rec, _ := readReleaseTrust(dir); rec != nil {
		t.Fatal("a record anybody could have written is not read")
	}
}

func TestOneSignatureOnly(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte("manifest")
	sig := ed25519.Sign(priv, msg)
	if signerOf([]ed25519.PublicKey{pub}, msg, sig) == nil {
		t.Fatal("a good signature must name its signer")
	}
	if signerOf([]ed25519.PublicKey{pub}, msg, append(append([]byte{}, sig...), ed25519.Sign(other, msg)...)) != nil {
		t.Fatal("a second signature beside the first must be refused")
	}
}

func TestBakedReleaseKeysAreAList(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _, _ := ed25519.GenerateKey(rand.Reader)
	saved := updatePubKeyB64
	defer func() { updatePubKeyB64 = saved }()
	updatePubKeyB64 = base64.StdEncoding.EncodeToString(a) + "," + base64.StdEncoding.EncodeToString(b) + ",not-a-key"
	keys := bakedReleaseKeys()
	if len(keys) != 2 || !containsKey(keys, a) || !containsKey(keys, b) {
		t.Fatalf("a comma-separated list of release keys must read as both, the malformed one skipped: %d", len(keys))
	}
}

// The self-update, end to end: a machine at N refuses a release under the old
// keys that would take the new ones away, and installs N+1.
func TestTheSelfUpdateFollowsTheAuthority(t *testing.T) {
	k := newRotationKeys(t)
	e := requiredUpdaterEnv(t, k.oldStatement, k.log)
	e.u.releaseKeys = releaseKeysOf(k.oldRelease)
	atN := trustOf([]ed25519.PublicKey{k.oldRelease, k.newRelease}, []testStatementKey{k.oldStatement, k.newStatement},
		[]ed25519.PublicKey{k.newRelease}, []testStatementKey{k.newStatement})
	if _, err := persistReleaseTrust(e.u.keyDir, atN, e.u.bakedLogKeys, e.u.releaseKeys); err != nil {
		t.Fatal(err)
	}

	theftBin := []byte("THIEF-BINARY")
	g, m, n, _ := k.ceremony(t, theftBin)
	old := []ed25519.PublicKey{k.oldRelease}
	oldS := []testStatementKey{k.oldStatement}
	theft := k.logged(t, k.oldStatement, trustPayload(t, "0.9.5", map[string]string{"agent/linux-amd64": binarySum(theftBin)}, old, oldS, k.log, old, oldS))
	e.priv = k.oldReleasePriv
	e.writeDist(t, "1.64.0", theftBin, nil)
	e.writeStatement(t, theft.doc(t, g, m, n))
	if e.u.CheckAndApply() || e.installedContent(t) != "OLD-BINARY" {
		t.Fatal("a release under the old keys taking the new ones away was installed")
	}
	if _, state := e.u.HeartbeatInfo(); state != updateStateVerifyFailed {
		t.Fatalf("state = %q, want %q", state, updateStateVerifyFailed)
	}

	goodBin := []byte("NEW-BINARY")
	g, m, n, n1 := k.ceremony(t, goodBin)
	e.priv = k.newRelPriv
	e.writeDist(t, "1.65.0", goodBin, nil)
	e.writeStatement(t, n1.doc(t, g, m, n))
	if !e.u.CheckAndApply() || e.installedContent(t) != "NEW-BINARY" {
		_, state := e.u.HeartbeatInfo()
		t.Fatalf("N+1, signed by the authority, must install; state %q", state)
	}
	rec, _ := readReleaseTrust(e.u.keyDir)
	if rec == nil || !sameKeySet(rec.release, releaseKeysOf(k.newRelease)) {
		t.Fatal("after N+1 the machine must hold the new release key alone")
	}
}

func TestCheckStatusReportsTheTrustedSets(t *testing.T) {
	k := newRotationKeys(t)
	state := t.TempDir()
	t.Setenv("AGENT_STATE_DIR", state)
	site := t.TempDir()
	config := filepath.Join(site, "config")
	if err := os.MkdirAll(config, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(config, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("release_verify_keys", b64(k.oldRelease)+"\n")
	write("release_statement_keys", b64(k.oldStatement.der)+"\nnot a key\n")

	name := func(key []byte) string { return trustFingerprints([][]byte{key})[0] }
	side := func(r map[string]interface{}, which string) map[string]interface{} {
		s, _ := r[which].(map[string]interface{})
		if s == nil {
			t.Fatalf("no %s set reported: %v", which, r)
		}
		return s
	}

	r := reportReleaseTrust(site)
	s := side(r, "site")
	if s["recorded"] != false || s["authority"] != nil || s["set_by"] != nil {
		t.Fatalf("a site with no record reports its key files, with the whole set as authority: %v", s)
	}
	if rel := s["release"].([]string); len(rel) != 1 || rel[0] != name(k.oldRelease) {
		t.Fatalf("the site's release key is named by its fingerprint: %v", rel)
	}
	if st := s["statement"].([]string); len(st) != 1 || st[0] != name(k.oldStatement.der) {
		t.Fatalf("the site's statement key is named, and a line that is no key is passed over: %v", st)
	}
	if side(r, "agent")["recorded"] != false {
		t.Fatal("an agent with no record reports its compiled-in set")
	}

	both := trustOf([]ed25519.PublicKey{k.oldRelease, k.newRelease}, []testStatementKey{k.oldStatement, k.newStatement},
		[]ed25519.PublicKey{k.newRelease}, []testStatementKey{k.newStatement})
	both.setBy = "0.9.3"
	baked := keysOf(k.oldStatement, k.log)
	for _, dir := range []string{state, config} {
		if _, err := persistReleaseTrust(dir, both, baked, releaseKeysOf(k.oldRelease)); err != nil {
			t.Fatal(err)
		}
	}
	r = reportReleaseTrust(site)
	for _, which := range []string{"site", "agent"} {
		s := side(r, which)
		auth, _ := s["authority"].(map[string]interface{})
		if s["recorded"] != true || s["set_by"] != "0.9.3" || auth == nil {
			t.Fatalf("the %s's record is reported with its authority and the release that set it: %v", which, s)
		}
		if rel := s["release"].([]string); len(rel) != 2 {
			t.Fatalf("the %s's record names both release keys: %v", which, rel)
		}
		if ar := auth["release"].([]string); len(ar) != 1 || ar[0] != name(k.newRelease) {
			t.Fatalf("the %s's authority is the new release key alone: %v", which, ar)
		}
	}

	if err := os.Chmod(filepath.Join(config, releaseTrustFileName), 0o666); err != nil {
		t.Fatal(err)
	}
	if side(reportReleaseTrust(site), "site")["recorded"] != false {
		t.Fatal("a record anybody could have written is not reported as the site's set")
	}
	if _, ok := reportReleaseTrust("")["site"]; ok {
		t.Fatal("a machine with no site reports no site set")
	}
}

func TestASelfUpdateThatSkippedNFollowsTheChain(t *testing.T) {
	k := newRotationKeys(t)
	e := requiredUpdaterEnv(t, k.oldStatement, k.log)
	e.u.releaseKeys = releaseKeysOf(k.oldRelease)
	if rec, _ := readReleaseTrust(e.u.keyDir); rec != nil {
		t.Fatal("the machine starts at M with no record: its compiled-in keys")
	}

	// M itself first: the set unchanged, so the record it writes is the set
	// held, named as set by M, as the site's record is.
	mBin := []byte("M-BINARY")
	g, m, n, n1 := k.ceremony(t, mBin)
	e.priv = k.oldReleasePriv
	e.writeDist(t, "1.64.0", mBin, nil)
	e.writeStatement(t, m.doc(t, g))
	if !e.u.CheckAndApply() || e.installedContent(t) != "M-BINARY" {
		_, state := e.u.HeartbeatInfo()
		t.Fatalf("M, under the keys held, must install; state %q", state)
	}
	if rec, _ := readReleaseTrust(e.u.keyDir); rec == nil || rec.setBy != "0.9.2" || !sameKeySet(rec.release, releaseKeysOf(k.oldRelease)) {
		t.Fatalf("M records the set held, set by M: %+v", rec)
	}

	bin := []byte("N1-BINARY")
	g, m, n, n1 = k.ceremony(t, bin)
	e.priv = k.newRelPriv
	e.writeDist(t, "1.65.0", bin, nil)
	e.writeStatement(t, n1.doc(t, g, m, n))
	if !e.u.CheckAndApply() || e.installedContent(t) != "N1-BINARY" {
		_, state := e.u.HeartbeatInfo()
		t.Fatalf("a machine that never saw N must walk N's link and install N+1; state %q", state)
	}
	rec, _ := readReleaseTrust(e.u.keyDir)
	if rec == nil || !sameKeySet(rec.release, releaseKeysOf(k.newRelease)) || !sameKeySet(rec.statement, [][]byte{k.newStatement.der}) {
		t.Fatal("after N+1 the machine that skipped N holds the new keys alone")
	}
}

func TestARefusalNamesTheRetiredKey(t *testing.T) {
	k := newRotationKeys(t)
	dir := t.TempDir()
	baked := keysOf(k.oldStatement, k.log)
	both := trustOf([]ed25519.PublicKey{k.oldRelease, k.newRelease}, []testStatementKey{k.oldStatement, k.newStatement},
		[]ed25519.PublicKey{k.newRelease}, []testStatementKey{k.newStatement})
	nu := trustOf([]ed25519.PublicKey{k.newRelease}, []testStatementKey{k.newStatement},
		[]ed25519.PublicKey{k.newRelease}, []testStatementKey{k.newStatement})
	msg := []byte("a manifest")
	byOld := ed25519.Sign(k.oldReleasePriv, msg)
	for _, set := range []releaseTrust{both, nu} {
		if _, err := persistReleaseTrust(dir, set, baked, releaseKeysOf(k.oldRelease)); err != nil {
			t.Fatal(err)
		}
	}
	note := retiredNote(dir, msg, byOld)
	if !strings.Contains(note, trustFingerprints([][]byte{k.oldRelease})[0]) || !strings.Contains(note, "retired") {
		t.Fatalf("a signature by the retired key is named as such: %q", note)
	}
	if retiredNote(dir, msg, ed25519.Sign(k.newRelPriv, msg)) != "" || retiredNote(dir, []byte("other"), byOld) != "" {
		t.Fatal("a signature by a key not retired, or over other bytes, is named as nothing")
	}
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, primitivesManifestName), msg, 0o644)
	os.WriteFile(filepath.Join(root, primitivesSignatureName), []byte(b64(byOld)+"\n"), 0o644)
	if treeRetiredNote(dir, root) != note {
		t.Fatal("a tree whose manifest the retired key signed is named the same way")
	}
}
