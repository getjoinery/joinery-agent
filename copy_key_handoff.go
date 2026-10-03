package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"joinery-agent/primitives"
)

// The copy's half of a copy made from backups (specs/site_copy.md WP10): the
// request copy_take_key stages on THIS machine's own site, and the owner's
// answer, through the settings table as every approval is (approval.go says
// why that surface).
//
// What travels: the backup's statement (chain, newest run, manifest hash, the
// recovery key's fingerprint, the sealed box's ephemeral public key), and back
// the X25519 value the owner's browser worked out with the recovery key, with
// the recovery public key. That value opens one sealed box, the chain key this
// machine is about to write anyway; the recovery key itself never leaves the
// browser. The management node is in neither direction.
//
// Unlike an approval, a wrong answer is not the end: a mistyped or wrong
// recovery key is caught here (its fingerprint, or the box refusing to open),
// written back to the page as the reason, and the wait goes on.

const (
	// settingCopyKeyRequest / settingCopyKeyAnswer mirror CopyKeyHandoff's
	// REQUEST_SETTING and ANSWER_SETTING on the PHP side.
	settingCopyKeyRequest = "copy_key_request"
	settingCopyKeyAnswer  = "copy_key_answer"
)

// copyKeyRequestRow is what the copy's page renders.
type copyKeyRequestRow struct {
	JobID       int64  `json:"job_id"`
	IssuedTime  string `json:"issued_time"`
	ExpiresTime string `json:"expires_time"`
	LastError   string `json:"last_error,omitempty"`
	primitives.CopyKeyRequest
}

// copyKeyAnswerRow is what the page writes back.
type copyKeyAnswerRow struct {
	JobID     int64  `json:"job_id"`
	Shared    string `json:"shared"`
	PublicKey string `json:"public_key"`
	Declined  bool   `json:"declined"`
}

// SettingsKeyHandoff is the KeyHandoff over this site's settings table.
type SettingsKeyHandoff struct {
	store     approvalStore
	now       func() time.Time
	withdrawn func(ctx context.Context, jobID int64) (bool, error)
}

// NewCopyKeyHandoff builds the handoff over this machine's own database; nil
// when there is none, and copy_take_key then refuses.
func NewCopyKeyHandoff(db *DB) primitives.KeyHandoff {
	if db == nil {
		return nil
	}
	return &SettingsKeyHandoff{store: dbSettings{db: db}}
}

func (h *SettingsKeyHandoff) clock() time.Time {
	if h.now != nil {
		return h.now()
	}
	return time.Now().UTC()
}

// Await stages the request, then polls for answers until try accepts one.
func (h *SettingsKeyHandoff) Await(ctx context.Context, jobID int64, req primitives.CopyKeyRequest,
	try func(shared, recoveryPublic []byte) error) error {
	if jobID <= 0 {
		return &primitives.RefusalError{Reason: "copy_take_key has no job to bind its request to"}
	}
	issued := h.clock()
	row := copyKeyRequestRow{
		JobID:          jobID,
		IssuedTime:     issued.Format("2006-01-02 15:04:05"),
		ExpiresTime:    issued.Add(primitives.ApprovalWindow).Format("2006-01-02 15:04:05"),
		CopyKeyRequest: req,
	}
	stage := func() error {
		body, err := json.Marshal(row)
		if err != nil {
			return err
		}
		return h.store.Write(settingCopyKeyRequest, string(body))
	}
	if err := h.store.Write(settingCopyKeyAnswer, ""); err != nil {
		return &primitives.RefusalError{Reason: "the previous answer could not be cleared from this site's settings: " + err.Error()}
	}
	if err := stage(); err != nil {
		return &primitives.RefusalError{Reason: "the request could not be staged on this site's page: " + err.Error()}
	}
	if back, err := h.store.Read(settingCopyKeyRequest); err != nil || trimSpace(back) == "" {
		return &primitives.RefusalError{Reason: "the request was written and could not be read back, so this site's page would not show it"}
	}
	defer func() {
		_ = h.store.Write(settingCopyKeyRequest, "")
		_ = h.store.Write(settingCopyKeyAnswer, "")
	}()
	log.Printf("  job #%d is waiting for its owner to open chain %s's key on this copy's own page (%s)",
		jobID, req.ChainID, primitives.ApprovalWindow)

	deadline := issued.Add(primitives.ApprovalWindow)
	ticker := time.NewTicker(restoreApprovalPollInterval)
	defer ticker.Stop()
	withdrawn := h.withdrawn
	if withdrawn == nil {
		withdrawn = planeJobWithdrawn()
	}
	lastAsked := issued
	for {
		raw, err := h.store.Read(settingCopyKeyAnswer)
		if err == nil && trimSpace(raw) != "" {
			// Taken off the row first, so an answer given after a refusal is
			// never the one cleared. One for another job is a leftover.
			_ = h.store.Write(settingCopyKeyAnswer, "")
			var ans copyKeyAnswerRow
			if json.Unmarshal([]byte(raw), &ans) == nil && ans.JobID == jobID {
				if ans.Declined {
					return &primitives.RefusalError{Reason: "the owner declined on this copy's own page, so no key was taken"}
				}
				shared, e1 := base64.StdEncoding.DecodeString(trimSpace(ans.Shared))
				public, e2 := base64.StdEncoding.DecodeString(trimSpace(ans.PublicKey))
				var why error
				if e1 != nil || e2 != nil {
					why = fmt.Errorf("the answer is not the shape the backup's key opens with")
				} else {
					why = try(shared, public)
				}
				zero(shared)
				if why == nil {
					log.Printf("  job #%d: the owner opened chain %s's key on this copy's own page", jobID, req.ChainID)
					return nil
				}
				// Said on the page, and the wait goes on: a wrong key is the
				// owner's to correct, not a reason to start over.
				row.LastError = why.Error()
				_ = stage()
			}
		}

		if withdrawn != nil && !h.clock().Before(lastAsked.Add(withdrawCheckInterval)) {
			lastAsked = h.clock()
			if gone, err := withdrawn(ctx, jobID); err == nil && gone {
				return &primitives.RefusalError{Reason: "the management node withdrew this job while it waited, so the " +
					"request was taken off this copy's page"}
			}
		}
		if !h.clock().Before(deadline) {
			return &primitives.RefusalError{Reason: fmt.Sprintf("no one opened the backup's key on this copy's own page "+
				"within %s. Start the copy run again when the owner is at the keyboard with the recovery key",
				primitives.ApprovalWindow)}
		}
		select {
		case <-ctx.Done():
			return &primitives.RefusalError{Reason: "the wait for the owner ended before they answered, so no key was taken"}
		case <-ticker.C:
		}
	}
}
