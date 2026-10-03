package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"joinery-agent/primitives"
)

// The copy's page handoff for a copy from backups (specs/site_copy.md WP10):
// the request is staged on the site's own settings, a wrong answer is said on
// the page and the wait goes on, a right one ends it, a decline or a withdrawn
// job refuses, and both rows are cleared at the end.

func keyRequest() primitives.CopyKeyRequest {
	return primitives.CopyKeyRequest{ChainID: "chain-20261001_030000", ManifestSHA256: strings.Repeat("ab", 32),
		RecoveryFingerprint: strings.Repeat("cd", 32), EphemeralPublic: base64.StdEncoding.EncodeToString(make([]byte, 32))}
}

func answerRow(jobID int64, shared string, declined bool) string {
	b, _ := json.Marshal(copyKeyAnswerRow{JobID: jobID, Shared: base64.StdEncoding.EncodeToString([]byte(shared)),
		PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), Declined: declined})
	return string(b)
}

func TestAWrongAnswerIsSaidOnThePageAndTheWaitGoesOn(t *testing.T) {
	store := newFakeSettings(nil)
	var errorsShown []string
	store.onWrite = func(name, value string) {
		if name != settingCopyKeyRequest || value == "" {
			return
		}
		var row copyKeyRequestRow
		_ = json.Unmarshal([]byte(value), &row)
		if row.LastError == "" {
			_ = store.Write(settingCopyKeyAnswer, answerRow(row.JobID, "wrong", false))
		} else {
			errorsShown = append(errorsShown, row.LastError)
			_ = store.Write(settingCopyKeyAnswer, answerRow(row.JobID, "right", false))
		}
	}
	h := &SettingsKeyHandoff{store: store}
	tries := 0
	err := h.Await(context.Background(), 77, keyRequest(), func(shared, pub []byte) error {
		tries++
		if string(shared) != "right" {
			return errors.New("that recovery key does not open this backup")
		}
		return nil
	})
	if err != nil || tries != 2 {
		t.Fatalf("await: %v after %d tries", err, tries)
	}
	if len(errorsShown) != 1 || !strings.Contains(errorsShown[0], "does not open") {
		t.Errorf("the page was shown %v", errorsShown)
	}
	if v, _ := store.Read(settingCopyKeyRequest); v != "" {
		t.Error("the request outlived the job")
	}
	if v, _ := store.Read(settingCopyKeyAnswer); v != "" {
		t.Error("the answer outlived the job")
	}
}

func TestADeclineAndAWithdrawnJobRefuse(t *testing.T) {
	store := newFakeSettings(nil)
	store.onWrite = func(name, value string) {
		if name == settingCopyKeyRequest && value != "" {
			_ = store.Write(settingCopyKeyAnswer, answerRow(5, "", true))
		}
	}
	h := &SettingsKeyHandoff{store: store}
	err := h.Await(context.Background(), 5, keyRequest(), func([]byte, []byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "declined") {
		t.Errorf("decline: %v", err)
	}

	quiet := newFakeSettings(nil)
	h = &SettingsKeyHandoff{store: quiet, now: steppingClock(withdrawCheckInterval),
		withdrawn: func(ctx context.Context, jobID int64) (bool, error) { return true, nil }}
	err = h.Await(context.Background(), 6, keyRequest(), func([]byte, []byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "withdrew") {
		t.Errorf("withdrawn: %v", err)
	}
	if v, _ := quiet.Read(settingCopyKeyRequest); v != "" {
		t.Error("a withdrawn request stayed on the page")
	}
}

func TestTheWaitEndsWithTheWindow(t *testing.T) {
	h := &SettingsKeyHandoff{store: newFakeSettings(nil), now: steppingClock(primitives.ApprovalWindow + time.Minute),
		withdrawn: func(ctx context.Context, jobID int64) (bool, error) { return false, nil }}
	err := h.Await(context.Background(), 8, keyRequest(), func([]byte, []byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "no one opened") {
		t.Errorf("window: %v", err)
	}
}
