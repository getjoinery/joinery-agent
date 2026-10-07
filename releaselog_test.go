package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The agent's half of the public-log check (spec release_transparency, WP5),
// against a log built here with keys made here: a real Merkle tree, a real
// signed checkpoint, a real hashedrekord leaf. The cases are WP4's, as they
// apply to a binary: a logged release installs; a stripped statement, a
// borrowed proof, a stranger's checkpoint and a statement that records other
// bytes are each refused as unlogged; a key chain carries a machine to a log
// key it did not hold; a machine with no keys updates as it always did; and
// the requirement outlives the binary that first carried the keys.

// testLog is one log origin and its checkpoint key.
type testLog struct {
	origin string
	priv   ed25519.PrivateKey
	der    []byte
}

func newTestLog(t *testing.T, origin string) testLog {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return testLog{origin: origin, priv: priv, der: der}
}

// testStatementKey is a P-256 release statement key.
type testStatementKey struct {
	priv *ecdsa.PrivateKey
	der  []byte
}

func newTestStatementKey(t *testing.T) testStatementKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return testStatementKey{priv: priv, der: der}
}

func keysOf(sk testStatementKey, logs ...testLog) releaseLogKeys {
	k := newReleaseLogKeys()
	k.addStatement(sk.der)
	for _, l := range logs {
		k.addLog(l.origin, l.der)
	}
	return k
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// payloadFor is a statement payload recording artifacts and installing keys.
func payloadFor(t *testing.T, artifacts map[string]string, installs releaseLogKeys) []byte {
	t.Helper()
	statementKeys := []string{}
	for _, der := range installs.statement {
		statementKeys = append(statementKeys, b64(der))
	}
	logKeys := []map[string]string{}
	for origin, ders := range installs.log {
		for _, der := range ders {
			logKeys = append(logKeys, map[string]string{"origin": origin, "key": b64(der)})
		}
	}
	raw, err := json.Marshal(map[string]interface{}{
		"version":   "0.8.470",
		"artifacts": artifacts,
		"keys_installed": map[string]interface{}{
			"release_keys": []string{}, "statement_keys": statementKeys, "log_keys": logKeys,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// signEnvelope is the DSSE envelope the publisher writes.
func signEnvelope(t *testing.T, sk testStatementKey, payload []byte) map[string]interface{} {
	t.Helper()
	digest := sha256.Sum256(dssePAE(statementPayloadType, payload))
	sig, err := ecdsa.SignASN1(rand.Reader, sk.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return map[string]interface{}{
		"payloadType": statementPayloadType,
		"payload":     b64(payload),
		"signatures":  []map[string]string{{"keyid": "", "sig": b64(sig)}},
	}
}

// leafFor is Rekor v2's canonical hashedrekord leaf for an envelope.
func leafFor(t *testing.T, env map[string]interface{}, signer []byte) []byte {
	t.Helper()
	payload, _ := base64.StdEncoding.DecodeString(env["payload"].(string))
	digest := sha256.Sum256(dssePAE(statementPayloadType, payload))
	sig := env["signatures"].([]map[string]string)[0]["sig"]
	leaf := map[string]interface{}{
		"apiVersion": leafAPIVersion,
		"kind":       leafKind,
		"spec": map[string]interface{}{
			"hashedRekordV002": map[string]interface{}{
				"data": map[string]interface{}{"algorithm": leafDigestAlg, "digest": b64(digest[:])},
				"signature": map[string]interface{}{
					"content": sig,
					"verifier": map[string]interface{}{
						"keyDetails": statementKeyType,
						"publicKey":  map[string]interface{}{"rawBytes": b64(signer)},
					},
				},
			},
		},
	}
	canonical, ok := canonicalJSON(roundTrip(t, leaf))
	if !ok {
		t.Fatal("the test leaf has no canonical form")
	}
	return []byte(canonical)
}

func roundTrip(t *testing.T, v interface{}) interface{} {
	t.Helper()
	raw, _ := json.Marshal(v)
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var out interface{}
	if err := dec.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// mth is RFC 6962's Merkle tree hash over leaf hashes.
func mth(hashes [][]byte) []byte {
	if len(hashes) == 1 {
		return hashes[0]
	}
	k := 1
	for k*2 < len(hashes) {
		k *= 2
	}
	return rfc6962Node(mth(hashes[:k]), mth(hashes[k:]))
}

// auditPath is RFC 6962's PATH(m, D[n]).
func auditPath(m int, hashes [][]byte) [][]byte {
	if len(hashes) <= 1 {
		return nil
	}
	k := 1
	for k*2 < len(hashes) {
		k *= 2
	}
	if m < k {
		return append(auditPath(m, hashes[:k]), mth(hashes[k:]))
	}
	return append(auditPath(m-k, hashes[k:]), mth(hashes[:k]))
}

// signCheckpoint is a C2SP signed note from l.
func signCheckpoint(l testLog, size int, root []byte) string {
	body := l.origin + "\n" + strconv.Itoa(size) + "\n" + b64(root) + "\n"
	pk := l.priv.Public().(ed25519.PublicKey)
	keyHash := sha256.Sum256(append([]byte(l.origin+"\n\x01"), pk...))
	sig := append(append([]byte{}, keyHash[:4]...), ed25519.Sign(l.priv, []byte(body))...)
	return body + "\n— " + l.origin + " " + b64(sig) + "\n"
}

// logEntry writes leaf at index 3 of a seven-leaf tree on l, and returns the
// entry the publisher stores.
func logEntry(t *testing.T, l testLog, leaf []byte) map[string]interface{} {
	t.Helper()
	const index, size = 3, 7
	hashes := make([][]byte, size)
	for i := range hashes {
		if i == index {
			hashes[i] = rfc6962Leaf(leaf)
			continue
		}
		filler := make([]byte, 40)
		rand.Read(filler)
		hashes[i] = rfc6962Leaf(filler)
	}
	root := mth(hashes)
	path := []string{}
	for _, h := range auditPath(index, hashes) {
		path = append(path, b64(h))
	}
	return map[string]interface{}{
		"log_origin": l.origin,
		"log_index":  index,
		"leaf":       b64(leaf),
		"inclusion_proof": map[string]interface{}{
			"tree_size": size, "root_hash": b64(root), "hashes": path,
		},
		"checkpoint": signCheckpoint(l, size, root),
	}
}

// statementDoc is RELEASE_STATEMENT as the publisher writes it.
func statementDoc(t *testing.T, env, entry map[string]interface{}, chain ...map[string]interface{}) []byte {
	t.Helper()
	if chain == nil {
		chain = []map[string]interface{}{}
	}
	raw, err := json.MarshalIndent(map[string]interface{}{
		"format": 1, "envelope": env, "entry": entry, "key_chain": chain,
	}, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// loggedStatement is a whole logged statement recording binary for
// linux-amd64: what a release ships.
func loggedStatement(t *testing.T, sk testStatementKey, l testLog, binary []byte, installs releaseLogKeys) []byte {
	t.Helper()
	sum := sha256.Sum256(binary)
	env := signEnvelope(t, sk, payloadFor(t, map[string]string{"agent/linux-amd64": hex.EncodeToString(sum[:])}, installs))
	return statementDoc(t, env, logEntry(t, l, leafFor(t, env, sk.der)))
}

// loggedEnv returns a logged envelope and its entry, for building chains and
// borrowed proofs.
func loggedEnv(t *testing.T, sk testStatementKey, l testLog, payload []byte) (map[string]interface{}, map[string]interface{}) {
	t.Helper()
	env := signEnvelope(t, sk, payload)
	return env, logEntry(t, l, leafFor(t, env, sk.der))
}

// requiredUpdaterEnv is an updater holding sk and l as compiled-in keys,
// with its own key directory.
func requiredUpdaterEnv(t *testing.T, sk testStatementKey, l testLog) *testUpdaterEnv {
	t.Helper()
	e := newTestUpdaterEnv(t, "1.63.0")
	e.u.bakedLogKeys = keysOf(sk, l)
	e.u.keyDir = t.TempDir()
	return e
}

func (e *testUpdaterEnv) writeStatement(t *testing.T, doc []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.distDir, releaseStatementName), doc, 0644); err != nil {
		t.Fatal(err)
	}
}

func (e *testUpdaterEnv) wantRefusedUnlogged(t *testing.T, why string) {
	t.Helper()
	if e.u.CheckAndApply() {
		t.Fatalf("%s: installed", why)
	}
	if e.installedContent(t) != "OLD-BINARY" {
		t.Fatalf("%s: the binary changed", why)
	}
	if _, state := e.u.HeartbeatInfo(); state != updateStateUnlogged {
		t.Fatalf("%s: state = %q, want %q", why, state, updateStateUnlogged)
	}
}

// ── The updater ──

func TestALoggedReleaseInstallsAndItsKeysAreKept(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log2025-1.rekor.test")
	e := requiredUpdaterEnv(t, sk, l)
	e.writeDist(t, "1.64.0", []byte("NEW-BINARY"), nil)
	e.writeStatement(t, loggedStatement(t, sk, l, []byte("NEW-BINARY"), keysOf(sk, l)))

	if !e.u.CheckAndApply() {
		_, state := e.u.HeartbeatInfo()
		t.Fatalf("a logged release must install; state %q", state)
	}
	if e.installedContent(t) != "NEW-BINARY" {
		t.Fatal("the logged binary was not installed")
	}
	// The keys the binary carried are now the machine's own, so the next
	// binary is held to the log even if it carries none.
	kept := readReleaseLogKeyFiles(e.u.keyDir)
	if !kept.holds() || len(kept.statement) != 1 || len(kept.log[l.origin]) != 1 {
		t.Fatalf("the keys held were not written to the key files: %+v", kept)
	}
}

func TestAStrippedStatementIsRefusedUntilOneArrives(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log2025-1.rekor.test")
	e := requiredUpdaterEnv(t, sk, l)
	e.writeDist(t, "1.64.0", []byte("NEW-BINARY"), nil)

	e.wantRefusedUnlogged(t, "a signed binary with no release statement")
	e.wantRefusedUnlogged(t, "the same release on the next check (the verdict holds)")

	// The statement lands after the manifest, as a publish writes them: the
	// release changed, so it is checked again, and installs.
	e.writeStatement(t, loggedStatement(t, sk, l, []byte("NEW-BINARY"), keysOf(sk, l)))
	if !e.u.CheckAndApply() {
		t.Fatal("a release refused for its missing statement must be retried once the statement arrives")
	}
}

// B5: a statement that was never logged, carrying the proof and leaf of one
// that was. Same statement key, a payload that records the hostile binary.
func TestABorrowedProofIsRefused(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log2025-1.rekor.test")
	e := requiredUpdaterEnv(t, sk, l)
	e.writeDist(t, "1.64.0", []byte("HOSTILE"), nil)

	_, realEntry := loggedEnv(t, sk, l, payloadFor(t, map[string]string{"agent/linux-amd64": strings.Repeat("ab", 32)}, keysOf(sk, l)))
	sum := sha256.Sum256([]byte("HOSTILE"))
	unlogged := signEnvelope(t, sk, payloadFor(t, map[string]string{"agent/linux-amd64": hex.EncodeToString(sum[:])}, keysOf(sk, l)))
	e.writeStatement(t, statementDoc(t, unlogged, realEntry))

	e.wantRefusedUnlogged(t, "an unlogged statement carrying a logged statement's proof")
}

func TestACheckpointSignedByAStrangerIsRefused(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log2025-1.rekor.test")
	stranger := newTestLog(t, "log2025-1.rekor.test") // same origin, other key
	e := requiredUpdaterEnv(t, sk, l)
	e.writeDist(t, "1.64.0", []byte("NEW-BINARY"), nil)
	e.writeStatement(t, loggedStatement(t, sk, stranger, []byte("NEW-BINARY"), keysOf(sk, l)))

	e.wantRefusedUnlogged(t, "a checkpoint signed by a key this machine does not hold")
}

func TestAStatementThatRecordsOtherBytesIsRefused(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log2025-1.rekor.test")
	e := requiredUpdaterEnv(t, sk, l)
	e.writeDist(t, "1.64.0", []byte("NEW-BINARY"), nil)
	e.writeStatement(t, loggedStatement(t, sk, l, []byte("SOME-OTHER-BINARY"), keysOf(sk, l)))

	e.wantRefusedUnlogged(t, "a logged statement recording other bytes for this platform")
}

func TestAStatementByAnUnheldKeyIsRefused(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log2025-1.rekor.test")
	other := newTestStatementKey(t)
	e := requiredUpdaterEnv(t, sk, l)
	e.writeDist(t, "1.64.0", []byte("NEW-BINARY"), nil)
	e.writeStatement(t, loggedStatement(t, other, l, []byte("NEW-BINARY"), keysOf(other, l)))

	e.wantRefusedUnlogged(t, "a statement signed by a statement key this machine does not hold")
}

// A machine that missed the release carrying a new log's key is not stuck:
// the release it does install carries the chain that gets it there, and only
// a link logged under a key it already holds can introduce one.
func TestTheKeyChainCarriesAMachineToANewLog(t *testing.T) {
	sk := newTestStatementKey(t)
	oldLog, newLog := newTestLog(t, "log2025-1.rekor.test"), newTestLog(t, "log2026-1.rekor.test")

	// The link: logged on the old log, installing the new log's key.
	linkEnv, linkEntry := loggedEnv(t, sk, oldLog, payloadFor(t, map[string]string{}, keysOf(sk, oldLog, newLog)))
	link := map[string]interface{}{"envelope": linkEnv, "entry": linkEntry}

	// The release: logged on the new log only.
	sum := sha256.Sum256([]byte("NEW-BINARY"))
	env, entry := loggedEnv(t, sk, newLog, payloadFor(t, map[string]string{"agent/linux-amd64": hex.EncodeToString(sum[:])}, keysOf(sk, oldLog, newLog)))

	e := requiredUpdaterEnv(t, sk, oldLog)
	e.writeDist(t, "1.64.0", []byte("NEW-BINARY"), nil)
	e.writeStatement(t, statementDoc(t, env, entry))
	e.wantRefusedUnlogged(t, "a release on a log this machine holds no key for, with no chain")

	// A chain link logged under a log this machine does not hold proves nothing.
	strangerLog := newTestLog(t, "log2025-1.rekor.test")
	forgedEnv, forgedEntry := loggedEnv(t, sk, strangerLog, payloadFor(t, map[string]string{}, keysOf(sk, oldLog, newLog)))
	verdict, err := verifyReleaseStatement(statementDoc(t, env, entry, map[string]interface{}{"envelope": forgedEnv, "entry": forgedEntry}),
		"agent/linux-amd64", hex.EncodeToString(sum[:]), keysOf(sk, oldLog))
	if err == nil || verdict != nil {
		t.Fatal("a chain link whose checkpoint is not signed by a held log key must not introduce a key")
	}

	// Checked without writing: the verdict carries the key, the files do not.
	verdict, err = verifyReleaseStatement(statementDoc(t, env, entry, link), "agent/linux-amd64", hex.EncodeToString(sum[:]), keysOf(sk, oldLog))
	if err != nil {
		t.Fatalf("the chain must carry the machine to the new log: %v", err)
	}
	if len(verdict.proven.log[newLog.origin]) != 1 || len(verdict.proven.statement) != 0 || len(verdict.proven.log[oldLog.origin]) != 0 {
		t.Fatalf("proven should be exactly the new log key: %+v", verdict.proven)
	}
	if _, err := os.Stat(filepath.Join(e.u.keyDir, logKeysFileName)); !os.IsNotExist(err) {
		t.Fatal("checking a statement wrote a key file; only the install step writes")
	}

	// And the install step writes it.
	e.writeStatement(t, statementDoc(t, env, entry, link))
	if !e.u.CheckAndApply() {
		_, state := e.u.HeartbeatInfo()
		t.Fatalf("a release reached through the chain must install; state %q", state)
	}
	if len(readReleaseLogKeyFiles(e.u.keyDir).log[newLog.origin]) != 1 {
		t.Fatal("the key the chain proved was not kept")
	}
}

// A machine holding no keys cannot check a statement, never asks for one, and
// updates on the release signature, as every agent did before the log.
func TestAMachineWithNoKeysUpdatesOnTheSignature(t *testing.T) {
	e := newTestUpdaterEnv(t, "1.63.0")
	e.u.keyDir = t.TempDir()
	e.u.source = &statementlessSource{localDirSource{dir: e.distDir}}
	e.writeDist(t, "1.64.0", []byte("NEW-BINARY"), nil)
	if !e.u.CheckAndApply() {
		t.Fatal("a machine with no release-log keys must still update on a signed binary")
	}
}

// statementlessSource fails the test if a statement is asked for.
type statementlessSource struct{ localDirSource }

func (s *statementlessSource) Statement() ([]byte, error) {
	panic("a machine holding no release-log keys asked for a release statement")
}

// A binary that carries no keys does not lower the bar: the keys an earlier
// one carried are on disk, and they hold it to the log.
func TestTheRequirementOutlivesTheBinaryThatCarriedTheKeys(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log2025-1.rekor.test")
	e := newTestUpdaterEnv(t, "1.64.0")
	e.u.keyDir = t.TempDir()
	if _, err := persistReleaseLogKeys(e.u.keyDir, keysOf(sk, l)); err != nil {
		t.Fatal(err)
	}
	e.writeDist(t, "1.65.0", []byte("NEW-BINARY"), nil)
	e.wantRefusedUnlogged(t, "a keyless binary on a machine whose key files hold keys")
}

// A key file someone other than its owner could have written is not trusted:
// read as empty, the rule a site's own key files follow.
func TestAKeyFileOthersCouldWriteIsNotTrusted(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log2025-1.rekor.test")
	dir := t.TempDir()
	if _, err := persistReleaseLogKeys(dir, keysOf(sk, l)); err != nil {
		t.Fatal(err)
	}
	if !readReleaseLogKeyFiles(dir).holds() {
		t.Fatal("key files written by persist must read back")
	}
	os.Chmod(filepath.Join(dir, statementKeysFileName), 0o666)
	if got := readReleaseLogKeyFiles(dir); len(got.statement) != 0 || got.holds() {
		t.Fatal("a world-writable statement key file was trusted")
	}
}

func TestPersistIsAppendOnlyAndWritesAKeyOnce(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log2025-1.rekor.test")
	dir := t.TempDir()
	added, err := persistReleaseLogKeys(dir, keysOf(sk, l))
	if err != nil || len(added) != 2 {
		t.Fatalf("first write: %v %v", added, err)
	}
	added, err = persistReleaseLogKeys(dir, keysOf(sk, l))
	if err != nil || len(added) != 0 {
		t.Fatalf("a key already held was written again: %v %v", added, err)
	}
	other := newTestLog(t, "log2026-1.rekor.test")
	if _, err := persistReleaseLogKeys(dir, keysOf(sk, other)); err != nil {
		t.Fatal(err)
	}
	got := readReleaseLogKeyFiles(dir)
	if len(got.log[l.origin]) != 1 || len(got.log[other.origin]) != 1 {
		t.Fatalf("a later write removed or skipped a key: %+v", got.log)
	}
}

// Over the channel: a siteless machine asks its plane for the statement.
func TestASitelessMachineChecksTheStatementItsPlaneServes(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log2025-1.rekor.test")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	manifest, gzipped := signedAgentArtifact(t, priv, "2.0.0", []byte("NEW-BINARY-CONTENTS"))

	plane := &planeArtifact{manifest: manifest, binaryGz: gzipped}
	u, _ := channelUpdater(t, plane, pub, "1.63.0")
	u.bakedLogKeys = keysOf(sk, l)
	u.keyDir = t.TempDir()
	if u.CheckAndApply() {
		t.Fatal("a plane serving no statement got a binary installed on a machine that requires the log")
	}
	if _, state := u.HeartbeatInfo(); state != updateStateUnlogged {
		t.Fatalf("state = %q, want %q", state, updateStateUnlogged)
	}

	plane.statement = loggedStatement(t, sk, l, []byte("NEW-BINARY-CONTENTS"), keysOf(sk, l))
	if !u.CheckAndApply() {
		_, state := u.HeartbeatInfo()
		t.Fatalf("the statement the plane served must let the binary install; state %q", state)
	}
}

// A plane that predates the statement kind is a failed fetch, retried, not a
// verdict on the release.
func TestAPlaneWithoutTheStatementKindIsAFetchFailure(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log2025-1.rekor.test")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	manifest, gzipped := signedAgentArtifact(t, priv, "2.0.0", []byte("NEW"))
	plane := &planeArtifact{manifest: manifest, binaryGz: gzipped, noStatementKind: true}
	u, _ := channelUpdater(t, plane, pub, "1.63.0")
	u.bakedLogKeys = keysOf(sk, l)
	u.keyDir = t.TempDir()
	if u.CheckAndApply() {
		t.Fatal("installed with no statement fetched")
	}
	if _, state := u.HeartbeatInfo(); state != updateStateFetchFailed {
		t.Fatalf("state = %q, want %q", state, updateStateFetchFailed)
	}
}

// ── The checks underneath ──

func TestInclusionProofsForEveryLeafOfSmallTrees(t *testing.T) {
	for size := 1; size <= 9; size++ {
		hashes := make([][]byte, size)
		for i := range hashes {
			hashes[i] = rfc6962Leaf([]byte{byte(i), byte(size)})
		}
		root := mth(hashes)
		for i := 0; i < size; i++ {
			path := auditPath(i, hashes)
			if !inclusionHolds(hashes[i], int64(i), int64(size), path, root) {
				t.Fatalf("leaf %d of %d does not verify", i, size)
			}
			if size > 1 && inclusionHolds(hashes[i], int64((i+1)%size), int64(size), path, root) {
				t.Fatalf("leaf %d of %d verifies at the wrong index", i, size)
			}
		}
	}
	if inclusionHolds(rfc6962Leaf([]byte("x")), 0, 0, nil, make([]byte, 32)) {
		t.Fatal("an empty tree holds nothing")
	}
}

// The leaf check is strict, and agrees with the PHP verifier's on what
// "canonical" means (TransparencyProof::canonicalJson).
func TestCanonicalJSONMatchesThePHPVerifier(t *testing.T) {
	cases := map[string]bool{
		`{"a":1,"b":[1,2],"c":"x\"y"}`: true,
		`{"b":1,"a":2}`:                false, // unsorted
		`{"a": 1}`:                     false, // whitespace
		`{"a":1.5}`:                    false, // not an integer
		`{"a":null}`:                   false,
		`{"a":"é"}`:                    false, // not printable ASCII
		`{"a":"a/b"}`:                  true,  // slashes unescaped
		`{"a":{}}`:                     true,
		`{"a":[]}`:                     false, // PHP renders an empty array {}
		`{"0":"x","1":"y"}`:            false, // PHP decodes this as a list
		`{"a":-0}`:                     false,
		`{"a":true}`:                   true,
	}
	for in, want := range cases {
		dec := json.NewDecoder(strings.NewReader(in))
		dec.UseNumber()
		var v interface{}
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		out, ok := canonicalJSON(v)
		if got := ok && out == in; got != want {
			t.Errorf("%s: canonical = %v (%q), want %v", in, got, out, want)
		}
	}
}

func TestANonCanonicalLeafIsRefused(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log2025-1.rekor.test")
	payload := payloadFor(t, map[string]string{"agent/linux-amd64": strings.Repeat("ab", 32)}, keysOf(sk, l))
	env := signEnvelope(t, sk, payload)
	leaf := leafFor(t, env, sk.der)
	spaced := []byte(strings.Replace(string(leaf), `"kind":`, `"kind": `, 1))
	doc := statementDoc(t, env, logEntry(t, l, spaced))
	if _, err := verifyReleaseStatement(doc, "agent/linux-amd64", strings.Repeat("ab", 32), keysOf(sk, l)); err == nil ||
		!strings.Contains(err.Error(), "canonical") {
		t.Fatalf("a leaf that is not its own canonical form must be refused: %v", err)
	}
	if _, err := verifyReleaseStatement(statementDoc(t, env, logEntry(t, l, leaf)), "agent/linux-amd64", strings.Repeat("ab", 32), keysOf(sk, l)); err != nil {
		t.Fatalf("the same statement with its canonical leaf must verify: %v", err)
	}
}

func TestBakedKeysAreRead(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log2025-1.rekor.test")
	oldS, oldL := releaseStatementKeysB64, releaseLogKeysB64
	t.Cleanup(func() { releaseStatementKeysB64, releaseLogKeysB64 = oldS, oldL })

	releaseStatementKeysB64 = b64(sk.der) + ",not-a-key"
	releaseLogKeysB64 = l.origin + ":" + b64(l.der) + ",bad origin:" + b64(l.der) + ",x.test:" + b64(sk.der)
	got := bakedReleaseLogKeys()
	if len(got.statement) != 1 || len(got.log) != 1 || len(got.log[l.origin]) != 1 {
		t.Fatalf("baked keys read as %+v", got)
	}

	releaseStatementKeysB64, releaseLogKeysB64 = "", ""
	if bakedReleaseLogKeys().holds() {
		t.Fatal("a build with no keys holds keys")
	}
}

// A real entry on Sigstore's log2025-1, recorded when the log client was
// built (the same fixture the PHP side's release_log_client_test reads): the
// envelope we wrote, Rekor's answer, our statement key, and the log's
// checkpoint key from release_keys/log/. Proves this verifier reads Rekor's
// own leaf bytes, proof and witnessed checkpoint the way the PHP one does.
func TestARealRekorEntryVerifies(t *testing.T) {
	read := func(name string) []byte {
		raw, err := os.ReadFile(filepath.Join("testdata", "release_log", name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	keyOf := func(name string) []byte {
		der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(read(name))))
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	const origin = "log2025-1.rekor.sigstore.dev"
	statementKey, logKey := keyOf("statement_key.pub"), keyOf(origin+".pub")

	env := decodeEnvelope(read("envelope.json"))
	// Rekor's answer, as ReleaseLogClient::entryFromResponse stores it.
	var tle struct {
		CanonicalizedBody string `json:"canonicalizedBody"`
		InclusionProof    struct {
			LogIndex   string   `json:"logIndex"`
			RootHash   string   `json:"rootHash"`
			TreeSize   string   `json:"treeSize"`
			Hashes     []string `json:"hashes"`
			Checkpoint struct {
				Envelope string `json:"envelope"`
			} `json:"checkpoint"`
		} `json:"inclusionProof"`
	}
	if err := json.Unmarshal(read("response.json"), &tle); err != nil {
		t.Fatal(err)
	}
	p := tle.InclusionProof
	stored, _ := json.Marshal(map[string]interface{}{
		"log_origin": origin,
		"log_index":  json.Number(p.LogIndex),
		"leaf":       tle.CanonicalizedBody,
		"inclusion_proof": map[string]interface{}{
			"tree_size": json.Number(p.TreeSize), "root_hash": p.RootHash, "hashes": p.Hashes,
		},
		"checkpoint": p.Checkpoint.Envelope,
	})
	var entry map[string]json.RawMessage
	json.Unmarshal(stored, &entry)

	if err := verifyEntry(env, entry, [][]byte{statementKey}, map[string][]byte{origin: logKey}); err != nil {
		t.Fatalf("the recorded Rekor entry must verify: %v", err)
	}

	// And each check bites on the real thing.
	other := newTestLog(t, origin)
	if err := verifyEntry(env, entry, [][]byte{statementKey}, map[string][]byte{origin: other.der}); err == nil {
		t.Error("the real checkpoint verified under a stranger's key")
	}
	if err := verifyEntry(env, entry, [][]byte{newTestStatementKey(t).der}, map[string][]byte{origin: logKey}); err == nil {
		t.Error("the real envelope verified under a stranger's statement key")
	}
	tampered := map[string]json.RawMessage{}
	for k, v := range entry {
		tampered[k] = v
	}
	tampered["log_index"] = json.RawMessage(`142362518`)
	if err := verifyEntry(env, tampered, [][]byte{statementKey}, map[string][]byte{origin: logKey}); err == nil {
		t.Error("the real proof verified at the wrong index")
	}
}

// B1 (reviewer2): keys are read exactly, as PHP reads them. encoding/json
// would match a struct field by any case and take the last of two twins, so a
// statement could show this verifier one artifact and every PHP reader
// another.
func TestCaseTwinKeysAreReadAsPHPReadsThem(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log2025-1.rekor.test")
	honest := sha256.Sum256([]byte("HONEST-BINARY"))
	hostile := sha256.Sum256([]byte("HOSTILE"))

	logged := func(payload []byte) []byte {
		env, entry := loggedEnv(t, sk, l, payload)
		return statementDoc(t, env, entry)
	}

	// The real key records the honest bytes; a twin records the hostile ones.
	twin := []byte(`{"version":"0.8.470","artifacts":{"agent/linux-amd64":"` + hex.EncodeToString(honest[:]) +
		`"},"ARTIFACTS":{"agent/linux-amd64":"` + hex.EncodeToString(hostile[:]) + `"},"keys_installed":{}}`)
	if _, err := verifyReleaseStatement(logged(twin), "agent/linux-amd64", hex.EncodeToString(hostile[:]), keysOf(sk, l)); err == nil {
		t.Error("the hostile hash under a case twin of artifacts was accepted")
	}
	if _, err := verifyReleaseStatement(logged(twin), "agent/linux-amd64", hex.EncodeToString(honest[:]), keysOf(sk, l)); err != nil {
		t.Errorf("the hash under the exact key must still verify: %v", err)
	}
	upper := []byte(`{"version":"0.8.470","ARTIFACTS":{"agent/linux-amd64":"` + hex.EncodeToString(hostile[:]) + `"}}`)
	if _, err := verifyReleaseStatement(logged(upper), "agent/linux-amd64", hex.EncodeToString(hostile[:]), keysOf(sk, l)); err == nil {
		t.Error("artifacts under ARTIFACTS alone were read")
	}

	// An envelope whose fields are spelled in another case is not the DSSE
	// form, as PHP says.
	env := signEnvelope(t, sk, payloadFor(t, map[string]string{}, keysOf(sk, l)))
	raw, _ := json.Marshal(map[string]interface{}{"PayloadType": env["payloadType"], "Payload": env["payload"], "Signatures": env["signatures"]})
	if _, err := verifyEnvelope(decodeEnvelope(raw), [][]byte{sk.der}); err == nil {
		t.Error("an envelope with mis-cased field names verified")
	}

	// A chain link installing a key under KEYS_INSTALLED installs nothing.
	newLog := newTestLog(t, "log2026-1.rekor.test")
	linkPayload, _ := json.Marshal(map[string]interface{}{
		"version": "0.8.469", "artifacts": map[string]string{},
		"KEYS_INSTALLED": map[string]interface{}{"statement_keys": []string{}, "log_keys": []map[string]string{{"origin": newLog.origin, "key": b64(newLog.der)}}},
	})
	linkEnv, linkEntry := loggedEnv(t, sk, l, linkPayload)
	if got := payloadKeys(decodeEnvelope(mustJSON(t, linkEnv))); len(got.log) != 0 {
		t.Errorf("a key under KEYS_INSTALLED was adopted: %+v", got.log)
	}
	sum := sha256.Sum256([]byte("NEW"))
	relEnv, relEntry := loggedEnv(t, sk, newLog, payloadFor(t, map[string]string{"agent/linux-amd64": hex.EncodeToString(sum[:])}, keysOf(sk, l, newLog)))
	doc := statementDoc(t, relEnv, relEntry, map[string]interface{}{"envelope": linkEnv, "entry": linkEntry})
	if _, err := verifyReleaseStatement(doc, "agent/linux-amd64", hex.EncodeToString(sum[:]), keysOf(sk, l)); err == nil {
		t.Error("a chain link's mis-cased key list carried the machine to a new log")
	}
}

func mustJSON(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// B2 (reviewer2): the keys are kept before the swap, and a swap whose keys
// could not be kept does not happen.
func TestKeysAreKeptBeforeTheSwapOrThereIsNoSwap(t *testing.T) {
	sk, l := newTestStatementKey(t), newTestLog(t, "log2025-1.rekor.test")
	e := requiredUpdaterEnv(t, sk, l)
	e.writeDist(t, "1.64.0", []byte("NEW-BINARY"), nil)
	e.writeStatement(t, loggedStatement(t, sk, l, []byte("NEW-BINARY"), keysOf(sk, l)))

	// A key directory that cannot be written: a file stands where it should be.
	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	os.WriteFile(blocked, []byte("x"), 0o644)
	e.u.keyDir = blocked
	if e.u.CheckAndApply() {
		t.Fatal("installed although the release-log keys could not be kept")
	}
	if e.installedContent(t) != "OLD-BINARY" {
		t.Fatal("the binary was swapped before its keys were kept")
	}
	if _, state := e.u.HeartbeatInfo(); state != updateStateFetchFailed {
		t.Fatalf("state = %q, want %q (retried, not a verdict)", state, updateStateFetchFailed)
	}

	// Retried on the next check, not held: once the keys can be kept, it installs.
	e.u.keyDir = filepath.Join(t.TempDir(), "fresh", "dir")
	if !e.u.CheckAndApply() {
		t.Fatal("the same release was not retried once the keys could be kept")
	}
	if !readReleaseLogKeyFiles(e.u.keyDir).holds() {
		t.Fatal("the keys were not kept")
	}
	leftovers, _ := filepath.Glob(filepath.Join(e.u.keyDir, ".*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left beside the key files: %v", leftovers)
	}
}
