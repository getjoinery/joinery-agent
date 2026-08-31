package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"joinery-agent/primitives"
)

// The node-side approval, and specifically its refusals — which are the whole
// of what it is for. A gate that lets the right answer through is easy; a gate
// that cannot be talked round by anything else is the thing being built.

// fakeSettings is the handoff row, in memory. It stands in for the settings
// table so the refusals can be exercised without a database — and, more to the
// point, so a test can play the part of a COMPROMISED WEB TIER writing whatever
// it likes into the answer row, which is the attacker this gate must survive.
type fakeSettings struct {
	mu     sync.Mutex
	values map[string]string
	// onWrite fires after each write, so a test can answer a challenge the
	// instant it appears rather than racing the poll interval.
	onWrite func(name, value string)
	// writeErr makes one named write fail; swallow makes one report success
	// and store nothing. Two different lies a settings table can tell.
	writeErr     error
	writeErrName string
	swallow      map[string]bool
}

func newFakeSettings(seed map[string]string) *fakeSettings {
	values := map[string]string{}
	for k, v := range seed {
		values[k] = v
	}
	return &fakeSettings{values: values}
}

func (f *fakeSettings) Read(name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.values[name], nil
}

func (f *fakeSettings) Write(name, value string) error {
	f.mu.Lock()
	if f.writeErr != nil && name == f.writeErrName {
		err := f.writeErr
		f.mu.Unlock()
		return err
	}
	if f.swallow != nil && f.swallow[name] {
		// Reports success and stores nothing — the shape of a settings write
		// that cannot be observed to have failed. This is what a node looks
		// like when its own site never shows the approval screen.
		f.mu.Unlock()
		return nil
	}
	f.values[name] = value
	hook := f.onWrite
	f.mu.Unlock()
	if hook != nil {
		hook(name, value)
	}
	return nil
}

// provenKeyStore is a machine with a recovery key whose possession has been
// proven here — the only state that lets a challenge be issued at all.
func provenKeyStore(t *testing.T) (*fakeSettings, []byte) {
	t.Helper()
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	public, err := curve25519.X25519(secret[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(public)
	return newFakeSettings(map[string]string{
		settingRecoveryPublicKey: base64.StdEncoding.EncodeToString(public),
		settingRecoveryProof:     hex.EncodeToString(sum[:]),
	}), secret[:]
}

func testStatement() primitives.ApprovalStatement {
	return primitives.ApprovalStatement{
		Primitive: "restore_database",
		Summary:   "This will erase the database jeremytunnell on this machine.",
		Facts: []primitives.ApprovalFact{
			{Label: "Database", Value: "jeremytunnell"},
			{Label: "Taken", Value: "2026-08-30 03:00:00 UTC (6 hours ago)"},
		},
	}
}

// openChallenge is the operator's browser, in Go: the same X25519 → HKDF-SHA256
// → AES-256-GCM the shipped JavaScript does. It is here so the round trip can be
// exercised in a unit test; the check that the REAL browser code agrees with the
// real sealing code is tests/backups/approval_challenge_parity_gate.sh, which
// runs the shipped .js file rather than a copy of the algorithm.
func openChallenge(t *testing.T, blob string, secret, public []byte) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil || len(raw) < 32+12+16 {
		t.Fatalf("challenge is not a well-formed blob: %v (%d bytes)", err, len(raw))
	}
	ephPub, iv, ct := raw[:32], raw[32:44], raw[44:]

	shared, err := curve25519.X25519(secret, ephPub)
	if err != nil {
		t.Fatal(err)
	}
	info := append(append([]byte(approvalInfoPrefix), ephPub...), public...)
	key := make([]byte, 32)
	if _, err := hkdfRead(shared, info, key); err != nil {
		t.Fatal(err)
	}
	plain, err := gcmOpen(key, iv, ct)
	if err != nil {
		t.Fatalf("could not open the challenge: %v", err)
	}
	return string(plain)
}

// runApproval issues a challenge and lets `answer` decide what to write back, as
// soon as the request appears. Returns the gate's verdict.
func runApproval(t *testing.T, store *fakeSettings, answer func(req approvalRequest) string) error {
	t.Helper()
	gate := &SettingsApproval{store: store}

	store.onWrite = func(name, value string) {
		if name != settingApprovalRequest || value == "" {
			return
		}
		var req approvalRequest
		if err := json.Unmarshal([]byte(value), &req); err != nil {
			t.Errorf("the staged request is not readable JSON: %v", err)
			return
		}
		if reply := answer(req); reply != "" {
			store.Write(settingApprovalAnswer, reply)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return gate.Require(ctx, 4242, testStatement())
}

// TestTheAnswerTheBrowserPostsIsTheAnswerTheAgentWANTS is the check that would
// have caught this mechanism's worst bug, and did not exist when it shipped.
//
// The browser posts the ENTIRE recovered plaintext — recovery-readiness.js
// assigns `proof` to the hidden field and submits. An earlier agent compared
// only the first line of a multi-line plaintext, so every genuine approval was
// refused, and both sides' unit tests were green throughout because each was
// written against its author's belief about the other. The plaintext is now one
// line and the whole of it is compared; this pins both halves of that.
func TestTheAnswerTheBrowserPostsIsWhatTheAgentCompares(t *testing.T) {
	store, secret := provenKeyStore(t)
	public, _ := base64.StdEncoding.DecodeString(store.values[settingRecoveryPublicKey])

	var recovered string
	err := runApproval(t, store, func(req approvalRequest) string {
		// Exactly what the shipped JavaScript does: open, then post the value
		// it got back, untouched. No slicing, no trimming, no reformatting.
		recovered = openChallenge(t, req.Challenge, secret, public)
		body, _ := json.Marshal(approvalAnswer{JobID: req.JobID, Answer: recovered})
		return string(body)
	})
	if err != nil {
		t.Fatalf("the value the browser posts must be accepted as-is: %v", err)
	}

	// And it has to survive a form POST unchanged. A plaintext with newlines in
	// it does not: urlencoded submission normalises line breaks to CRLF, so the
	// bytes the agent compares would not be the bytes it sealed.
	if strings.ContainsAny(recovered, "\r\n") {
		t.Errorf("the sealed plaintext contains a line break, so it cannot survive a form POST "+
			"byte-for-byte: %q", recovered)
	}
	// The binding is inside what gets compared, not merely alongside it.
	if !strings.Contains(recovered, "job:4242") {
		t.Errorf("the compared value does not name the job: %q", recovered)
	}
}

func TestARestoreRunsOnlyWhenTheRecoveryKeyOpenedTheChallenge(t *testing.T) {
	store, secret := provenKeyStore(t)
	public, _ := base64.StdEncoding.DecodeString(store.values[settingRecoveryPublicKey])

	var seen approvalRequest
	err := runApproval(t, store, func(req approvalRequest) string {
		seen = req
		plain := openChallenge(t, req.Challenge, secret, public)
		// The operator's browser posts back the WHOLE recovered plaintext.
		body, _ := json.Marshal(approvalAnswer{JobID: req.JobID, Answer: plain})
		return string(body)
	})
	if err != nil {
		t.Fatalf("an answer opened with the real recovery key must be accepted: %v", err)
	}

	// What was staged is what the operator reads. It has to be the NODE's
	// account, and it has to carry the binding.
	if seen.JobID != 4242 {
		t.Errorf("the staged request names job %d", seen.JobID)
	}
	if !strings.Contains(seen.Summary, "erase the database") {
		t.Errorf("the summary should say what is destroyed, got %q", seen.Summary)
	}
	if len(seen.Facts) == 0 {
		t.Error("the request carries no facts — there would be nothing to check before approving")
	}
	if seen.Info != approvalInfoPrefix {
		t.Errorf("the request must name the approval HKDF context, got %q", seen.Info)
	}

	// And the request is cleared afterwards: an approval screen for a restore
	// that is no longer running is how somebody approves something twice.
	if left, _ := store.Read(settingApprovalRequest); left != "" {
		t.Error("the challenge outlived the job")
	}
	if left, _ := store.Read(settingApprovalAnswer); left != "" {
		t.Error("the answer outlived the job")
	}
}

func TestTheChallengeCarriesTheJobAndTheStatementInsideTheBox(t *testing.T) {
	// The binding is under the AEAD, not beside it. A field the web tier could
	// edit would let an answer recovered for one restore be pointed at another.
	store, secret := provenKeyStore(t)
	public, _ := base64.StdEncoding.DecodeString(store.values[settingRecoveryPublicKey])

	statementSHA := ""
	runApproval(t, store, func(req approvalRequest) string {
		plain := openChallenge(t, req.Challenge, secret, public)
		statementSHA = req.StatementSHA
		if !strings.Contains(plain, "job:4242") {
			t.Errorf("the sealed plaintext does not name the job: %q", plain)
		}
		if !strings.Contains(plain, "statement:"+req.StatementSHA) {
			t.Errorf("the sealed plaintext does not bind the statement: %q", plain)
		}
		body, _ := json.Marshal(approvalAnswer{JobID: req.JobID, Answer: plain})
		return string(body)
	})

	// The staged hash is the hash of what was actually staged, so an operator
	// approving it is approving the words they were shown.
	body, _ := json.Marshal(testStatement())
	want := sha256.Sum256(body)
	if statementSHA != hex.EncodeToString(want[:]) {
		t.Errorf("the statement hash does not match the statement that was shown")
	}
}

func TestAnAnswerNobodyOpenedIsRefused(t *testing.T) {
	// The compromised-web-tier case, stated plainly: something that can write
	// the answer row but cannot open the box gets nowhere. That is the whole
	// reason the secret is inside the box rather than beside it.
	store, _ := provenKeyStore(t)
	err := runApproval(t, store, func(req approvalRequest) string {
		body, _ := json.Marshal(approvalAnswer{
			JobID:  req.JobID,
			Answer: "joinery-restore-approval " + base64.StdEncoding.EncodeToString([]byte("guessed")),
		})
		return string(body)
	})
	if !primitives.Refused(err) {
		t.Fatalf("a guessed answer must be refused, got %v", err)
	}
	if !strings.Contains(err.Error(), "not what this node's approval challenge opens to") {
		t.Errorf("the refusal should say the answer is wrong, got %q", err)
	}
}

func TestAnAnswerForADifferentJobIsIgnored(t *testing.T) {
	// A stale answer must not satisfy a fresh challenge. It is cleared rather
	// than treated as an error, so a leftover row cannot wedge every future
	// approval — but it must not count.
	store, secret := provenKeyStore(t)
	public, _ := base64.StdEncoding.DecodeString(store.values[settingRecoveryPublicKey])

	gate := &SettingsApproval{store: store}
	answered := false
	store.onWrite = func(name, value string) {
		if name != settingApprovalRequest || value == "" || answered {
			return
		}
		answered = true
		var req approvalRequest
		json.Unmarshal([]byte(value), &req)
		plain := openChallenge(t, req.Challenge, secret, public)
		// The right answer, aimed at the wrong job.
		body, _ := json.Marshal(approvalAnswer{JobID: req.JobID + 1, Answer: plain})
		store.Write(settingApprovalAnswer, string(body))
	}

	// A short window, because the expected outcome is that nothing satisfies it.
	gate.now = fixedClockRunningOut()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := gate.Require(ctx, 4242, testStatement())
	if !primitives.Refused(err) {
		t.Fatalf("an answer for another job must not approve this one, got %v", err)
	}
}

func TestDecliningIsAnAnswer(t *testing.T) {
	store, _ := provenKeyStore(t)
	err := runApproval(t, store, func(req approvalRequest) string {
		body, _ := json.Marshal(approvalAnswer{JobID: req.JobID, Declined: true})
		return string(body)
	})
	if !primitives.Refused(err) {
		t.Fatalf("a decline must refuse, got %v", err)
	}
	if !strings.Contains(err.Error(), "declined") {
		t.Errorf("the refusal should say a person declined, not that something failed: %q", err)
	}
}

func TestAnUnansweredChallengeExpires(t *testing.T) {
	// Nobody is at the keyboard. The job refuses rather than pinning the node
	// until the plane's claim budget runs out — and the refusal says what to do.
	store, _ := provenKeyStore(t)
	gate := &SettingsApproval{store: store, now: fixedClockRunningOut()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := gate.Require(ctx, 4242, testStatement())
	if !primitives.Refused(err) {
		t.Fatalf("an unanswered challenge must expire into a refusal, got %v", err)
	}
	if !strings.Contains(err.Error(), "Dispatch it again") {
		t.Errorf("the refusal should tell the operator what to do, got %q", err)
	}
}

func TestNoRecoveryKeyMeansNoRestore(t *testing.T) {
	// Nothing to seal to, so nobody to ask. Refuse — never treat "there is
	// nobody to ask" as "nobody objected".
	gate := &SettingsApproval{store: newFakeSettings(nil)}
	err := gate.Require(context.Background(), 1, testStatement())
	if !primitives.Refused(err) {
		t.Fatalf("a machine with no recovery key must refuse, got %v", err)
	}
	if !strings.Contains(err.Error(), "no usable backup recovery key") {
		t.Errorf("the refusal should name what is missing, got %q", err)
	}
}

func TestAnUnprovenRecoveryKeyMeansNoRestore(t *testing.T) {
	// A key nobody has demonstrated holding. Sealing to it would always appear
	// to work and might be openable by nobody at all — or by whoever put it
	// there. Either way it is not an approver.
	store, _ := provenKeyStore(t)
	store.values[settingRecoveryProof] = ""
	gate := &SettingsApproval{store: store}
	err := gate.Require(context.Background(), 1, testStatement())
	if !primitives.Refused(err) {
		t.Fatalf("an unproven key must refuse, got %v", err)
	}
	if !strings.Contains(err.Error(), "never been proven here") {
		t.Errorf("the refusal should name the missing proof, got %q", err)
	}
}

func TestNoDatabaseMeansNoRestore(t *testing.T) {
	gate := NewSettingsApproval(nil)
	err := gate.Require(context.Background(), 1, testStatement())
	if !primitives.Refused(err) {
		t.Fatalf("a machine that cannot reach its own database must refuse, got %v", err)
	}
}

// fixedClockRunningOut reports "now" as already past the approval window on the
// second call, so an expiry can be exercised without waiting a quarter of an
// hour. The first call is the issue time.
func fixedClockRunningOut() func() time.Time {
	base := time.Now().UTC()
	calls := 0
	return func() time.Time {
		calls++
		if calls == 1 {
			return base
		}
		return base.Add(primitives.ApprovalWindow + time.Minute)
	}
}

// hkdfRead / gcmOpen are the reader's half of sealToRecoveryKey, kept beside the
// test that uses them rather than exported from the production file — nothing
// the agent ships ever opens one of these, and a helper that existed for a test
// would read as one that did.
func hkdfRead(secret, info, out []byte) (int, error) {
	return hkdf.New(sha256.New, secret, nil, info).Read(out)
}

func gcmOpen(key, iv, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, ct, nil)
}

func TestStrayWhitespaceDoesNotRefuseAGenuineApproval(t *testing.T) {
	// The value crosses a browser form and, on the command-line fallback, a
	// paste. Refusing an otherwise-correct answer over a trailing newline would
	// present to somebody mid-incident as "my recovery key does not work",
	// which is the most alarming thing this platform could tell them.
	store, secret := provenKeyStore(t)
	public, _ := base64.StdEncoding.DecodeString(store.values[settingRecoveryPublicKey])

	err := runApproval(t, store, func(req approvalRequest) string {
		plain := openChallenge(t, req.Challenge, secret, public)
		body, _ := json.Marshal(approvalAnswer{JobID: req.JobID, Answer: "  " + plain + "\r\n"})
		return string(body)
	})
	if err != nil {
		t.Fatalf("a correct answer with stray whitespace must still be accepted: %v", err)
	}
}

// --- The staging handoff must not fail silently -------------------------------

func TestAnApprovalThatCannotBeStagedRefusesInsteadOfWaiting(t *testing.T) {
	// The first live restore attempt failed this way and nothing said so: the
	// node sealed a challenge, wrote it to a settings row, waited the full
	// fifteen minutes and reported "no one approved" — while the operator sat on
	// an admin page that had never been given anything to show. A write that
	// cannot report failure makes "nobody was asked" and "nobody said yes" the
	// same outcome, and they are opposite problems.
	store, _ := provenKeyStore(t)
	store.writeErr = errors.New("relation stg_settings is read only")
	store.writeErrName = settingApprovalRequest

	gate := &SettingsApproval{store: store}
	err := gate.Require(context.Background(), 77, primitives.ApprovalStatement{
		Primitive: "restore_database", Summary: "erase and reload"})

	if err == nil {
		t.Fatal("a restore whose approval could not be staged was allowed to proceed")
	}
	if !strings.Contains(err.Error(), "nobody would ever have been shown") {
		t.Errorf("the refusal does not say the screen was never shown: %v", err)
	}
	if strings.Contains(err.Error(), "no one approved") {
		t.Error("a staging failure is reported as an operator declining to approve")
	}
}

func TestAStagingWriteThatStoresNothingIsCaughtByReadingItBack(t *testing.T) {
	// The harder case, and the one a returned error does not cover: the write
	// reports success and the row is not there. Only asking the row settles it,
	// so the check is a read-back rather than trust in the return value.
	store, _ := provenKeyStore(t)
	store.swallow = map[string]bool{settingApprovalRequest: true}

	gate := &SettingsApproval{store: store}
	err := gate.Require(context.Background(), 78, primitives.ApprovalStatement{
		Primitive: "restore_database", Summary: "erase and reload"})

	if err == nil {
		t.Fatal("a restore whose approval was never actually stored was allowed to proceed")
	}
	if !strings.Contains(err.Error(), "could not read it back") {
		t.Errorf("the refusal does not name the read-back: %v", err)
	}
}
