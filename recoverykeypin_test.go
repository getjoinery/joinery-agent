package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"joinery-agent/xwing"
)

// newRecoveryKey is a recovery key pair: its seed (the operator's private
// key) and public half.
func newRecoveryKey(t *testing.T) (secret, public []byte) {
	t.Helper()
	secret, err := xwing.NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	public, err = xwing.PublicKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	return secret, public
}

// proveOnSite writes a key and its proof into the site's settings, as the web
// tier can: the attacker's move as much as the operator's.
func proveOnSite(store *fakeSettings, public []byte) {
	sum := sha256.Sum256(public)
	store.Write(settingRecoveryPublicKey, base64.StdEncoding.EncodeToString(public))
	store.Write(settingRecoveryProof, hex.EncodeToString(sum[:]))
}

// answerWith answers whatever request appears in scope's row by opening it
// with secret; an opening that fails answers with nonsense, as a web tier
// without the key would.
func answerWith(t *testing.T, store *fakeSettings, scope approvalScope, secret []byte, decline bool) {
	store.onWrite = func(name, value string) {
		if name != scope.requestSetting || value == "" {
			return
		}
		var req approvalRequest
		if err := json.Unmarshal([]byte(value), &req); err != nil {
			t.Errorf("staged request unreadable: %v", err)
			return
		}
		reply := approvalAnswer{JobID: req.JobID, Declined: decline}
		if !decline {
			raw, _ := base64.StdEncoding.DecodeString(req.Challenge)
			if plain, err := xwing.Open(raw, secret, scope.infoPrefix); err == nil {
				reply.Answer = string(plain)
			} else {
				reply.Answer = "a web tier without the key guesses"
			}
		}
		body, _ := json.Marshal(reply)
		go store.Write(scope.answerSetting, string(body))
	}
}

func pinPath(t *testing.T) string {
	return filepath.Join(t.TempDir(), "recovery_key.json")
}

func requireOnce(gate *SettingsApproval) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return gate.Require(ctx, 4242, testStatement())
}

// The first proven key is root's from then on: recorded 0600, and the
// restore is approved with it.
func TestTheFirstProvenKeyIsRecordedAndApprovesWithIt(t *testing.T) {
	path := pinPath(t)
	secret, public := newRecoveryKey(t)
	store := newFakeSettings(nil)
	proveOnSite(store, public)
	answerWith(t, store, restoreScope, secret, false)

	if err := requireOnce(&SettingsApproval{store: store, pin: &recoveryKeyPinner{path: path}}); err != nil {
		t.Fatalf("the operator's own key must approve: %v", err)
	}
	pin, err := LoadRecoveryKeyPin(path)
	if err != nil || pin == nil || pin.Fingerprint != recoveryKeyFingerprint(public) || pin.How != pinFirstSeen {
		t.Fatalf("the key was not recorded: %+v, %v", pin, err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("root's record is mode %04o, want 0600", info.Mode().Perm())
	}
}

// The attack this exists for: the web tier writes a key of its own, proves
// it, and answers with it. Nothing is staged and nothing runs.
func TestAKeyTheWebTierSwappedInApprovesNothing(t *testing.T) {
	path := pinPath(t)
	_, operator := newRecoveryKey(t)
	if _, err := pinRecoveryKey(path, operator, pinFirstSeen); err != nil {
		t.Fatal(err)
	}
	attackerSecret, attacker := newRecoveryKey(t)
	store := newFakeSettings(nil)
	proveOnSite(store, attacker)
	answerWith(t, store, restoreScope, attackerSecret, false)

	err := requireOnce(&SettingsApproval{store: store, pin: &recoveryKeyPinner{path: path}})
	if err == nil || !strings.Contains(err.Error(), "not the one root recorded") {
		t.Fatalf("a swapped key must be refused, got %v", err)
	}
	if v, _ := store.Read(settingApprovalRequest); v != "" {
		t.Error("no challenge may be staged against a key root did not record")
	}
}

// A changed key is recorded only when the previous key opens the
// confirmation; until then the record, and so every approval, stays.
func TestAChangedKeyIsRecordedOnlyWhenThePreviousKeyConfirmsIt(t *testing.T) {
	path := pinPath(t)
	oldSecret, old := newRecoveryKey(t)
	newSecret, fresh := newRecoveryKey(t)
	if _, err := pinRecoveryKey(path, old, pinFirstSeen); err != nil {
		t.Fatal(err)
	}
	store := newFakeSettings(nil)
	proveOnSite(store, fresh)
	w := &RecoveryKeyWatcher{store: store, pin: recoveryKeyPinner{path: path}}

	// The new key cannot confirm itself: that is what a web tier holding
	// only the key it wrote would try.
	answerWith(t, store, rekeyScope, newSecret, false)
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pin, _ := LoadRecoveryKeyPin(path); pin.Fingerprint != recoveryKeyFingerprint(old) {
		t.Fatal("the new key confirmed itself")
	}

	answerWith(t, store, rekeyScope, oldSecret, false)
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	pin, _ := LoadRecoveryKeyPin(path)
	if pin.Fingerprint != recoveryKeyFingerprint(fresh) || pin.How != pinConfirmed {
		t.Fatalf("the confirmed key was not recorded: %+v", pin)
	}
	if v, _ := store.Read(rekeyScope.requestSetting); v != "" {
		t.Error("the confirmation request outlived its answer")
	}
}

// A declined change is remembered, and not asked about again until the key
// changes once more.
func TestADeclinedChangeIsNotAskedAgain(t *testing.T) {
	path := pinPath(t)
	oldSecret, old := newRecoveryKey(t)
	_, fresh := newRecoveryKey(t)
	if _, err := pinRecoveryKey(path, old, pinFirstSeen); err != nil {
		t.Fatal(err)
	}
	store := newFakeSettings(nil)
	proveOnSite(store, fresh)
	w := &RecoveryKeyWatcher{store: store, pin: recoveryKeyPinner{path: path}}
	answerWith(t, store, rekeyScope, oldSecret, true)
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	pin, _ := LoadRecoveryKeyPin(path)
	if pin.Fingerprint != recoveryKeyFingerprint(old) || pin.DeclinedFingerprint != recoveryKeyFingerprint(fresh) {
		t.Fatalf("a decline must keep the old key and remember the new one: %+v", pin)
	}
	staged := false
	store.onWrite = func(name, value string) {
		if name == rekeyScope.requestSetting && value != "" {
			staged = true
		}
	}
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if staged {
		t.Error("a declined change was asked about again")
	}
}

// With no record yet the watcher takes one; with no proven key it takes none.
func TestTheWatcherRecordsTheFirstProvenKeyOnly(t *testing.T) {
	path := pinPath(t)
	store := newFakeSettings(nil)
	w := &RecoveryKeyWatcher{store: store, pin: recoveryKeyPinner{path: path}}
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a record was made with no proven key")
	}
	_, public := newRecoveryKey(t)
	store.Write(settingRecoveryPublicKey, base64.StdEncoding.EncodeToString(public))
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a record was made of an unproven key")
	}
	proveOnSite(store, public)
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pin, _ := LoadRecoveryKeyPin(path); pin == nil || pin.Fingerprint != recoveryKeyFingerprint(public) {
		t.Fatal("the first proven key was not recorded")
	}
}

// A record anyone else could have written is no record: approvals refuse.
func TestARecordOpenBeyondItsOwnerRefuses(t *testing.T) {
	path := pinPath(t)
	secret, public := newRecoveryKey(t)
	if _, err := pinRecoveryKey(path, public, pinFirstSeen); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	store := newFakeSettings(nil)
	proveOnSite(store, public)
	answerWith(t, store, restoreScope, secret, false)
	err := requireOnce(&SettingsApproval{store: store, pin: &recoveryKeyPinner{path: path}})
	if err == nil || !strings.Contains(err.Error(), "unusable") {
		t.Fatalf("a record open beyond its owner must refuse, got %v", err)
	}
	// And a record whose key and fingerprint disagree.
	pin := &RecoveryKeyPin{PublicKey: base64.StdEncoding.EncodeToString(public), Fingerprint: strings.Repeat("0", 64)}
	if err := writeRecoveryKeyPin(path, pin); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecoveryKeyPin(path); err == nil {
		t.Error("a record whose fingerprint does not match its key must not load")
	}
}

// The gates that answer for this machine's own site hold to the record; the
// victim's does not.
func TestTheOwnSiteGatesHoldToTheRecord(t *testing.T) {
	db := &DB{}
	if NewSettingsApproval(db).pin == nil || NewExportApproval(db).pin == nil {
		t.Error("a restore or an export of this site must be held to root's record")
	}
	if newScopedApproval(newFakeSettings(nil), decommissionScope).pin != nil {
		t.Error("a removal is approved with the removed site's own key, which this host has no record of")
	}
}

// Root's accept during the wait is not undone by a decline that arrives
// after it (reviewer2 round 2 B1).
func TestADeclineAfterRootAcceptedLeavesRootsRecord(t *testing.T) {
	path := pinPath(t)
	_, old := newRecoveryKey(t)
	_, fresh := newRecoveryKey(t)
	if _, err := pinRecoveryKey(path, old, pinFirstSeen); err != nil {
		t.Fatal(err)
	}
	store := newFakeSettings(nil)
	proveOnSite(store, fresh)
	store.onWrite = func(name, value string) {
		if name != rekeyScope.requestSetting || value == "" {
			return
		}
		var req approvalRequest
		json.Unmarshal([]byte(value), &req)
		// Root runs recovery-key accept while the box is open; then someone
		// declines the box.
		time.Sleep(1100 * time.Millisecond) // a different PinnedTime second
		if _, err := pinRecoveryKey(path, fresh, pinAcceptedAsRoot); err != nil {
			t.Error(err)
		}
		body, _ := json.Marshal(approvalAnswer{JobID: req.JobID, Declined: true})
		go store.Write(rekeyScope.answerSetting, string(body))
	}
	w := &RecoveryKeyWatcher{store: store, pin: recoveryKeyPinner{path: path}}
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	pin, _ := LoadRecoveryKeyPin(path)
	if pin.Fingerprint != recoveryKeyFingerprint(fresh) || pin.How != pinAcceptedAsRoot || pin.DeclinedFingerprint != "" {
		t.Fatalf("a stale decline overwrote root's accept: %+v", pin)
	}
}

// A decline quiets the question for a day, then it is asked again.
func TestADeclineIsAskedAgainAfterADay(t *testing.T) {
	path := pinPath(t)
	_, old := newRecoveryKey(t)
	_, fresh := newRecoveryKey(t)
	pin, err := pinRecoveryKey(path, old, pinFirstSeen)
	if err != nil {
		t.Fatal(err)
	}
	pin.DeclinedFingerprint = recoveryKeyFingerprint(fresh)
	pin.DeclinedTime = time.Now().UTC().Format("2006-01-02 15:04:05")
	if err := writeRecoveryKeyPin(path, pin); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if !pin.declineHolds(pin.DeclinedFingerprint, now) {
		t.Error("a decline just made must hold")
	}
	if pin.declineHolds(pin.DeclinedFingerprint, now.Add(25*time.Hour)) {
		t.Error("a decline must not hold past a day")
	}
	store := newFakeSettings(nil)
	proveOnSite(store, fresh)
	_, err = (recoveryKeyPinner{path: path}).recipient(fresh)
	if err == nil || !strings.Contains(err.Error(), "declined") {
		t.Errorf("a declined key's refusal must say it was declined, got %v", err)
	}
}

// check_status reports the record and the site's key by fingerprint, and
// whether they agree; never the key itself.
func TestTheRecordIsReportedByFingerprint(t *testing.T) {
	path := pinPath(t)
	_, old := newRecoveryKey(t)
	_, fresh := newRecoveryKey(t)
	store := newFakeSettings(nil)
	proveOnSite(store, old)
	if rec := reportRecoveryKeyRecord(store, path); rec["recorded"] != false || rec["site_fingerprint"] != recoveryKeyFingerprint(old) {
		t.Fatalf("with no record: %v", rec)
	}
	if _, err := pinRecoveryKey(path, old, pinFirstSeen); err != nil {
		t.Fatal(err)
	}
	if rec := reportRecoveryKeyRecord(store, path); rec["matches"] != true || rec["how"] != pinFirstSeen {
		t.Fatalf("a matching record: %v", rec)
	}
	proveOnSite(store, fresh)
	rec := reportRecoveryKeyRecord(store, path)
	if rec["matches"] != false {
		t.Fatalf("a changed key must report a mismatch: %v", rec)
	}
	body, _ := json.Marshal(rec)
	if strings.Contains(string(body), base64.StdEncoding.EncodeToString(old)) {
		t.Error("the report carries the key, not only its fingerprint")
	}
}
