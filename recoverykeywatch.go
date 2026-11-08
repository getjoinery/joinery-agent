package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"joinery-agent/primitives"
)

// recoveryKeyCheckInterval is how often the watcher compares the site's key
// with root's record.
const recoveryKeyCheckInterval = time.Minute

// RecoveryKeyWatcher keeps root's record of this site's recovery key
// (recoverykeypin.go). It records the first proven key it sees, and when the
// site's key changes it asks, on the site's Backups page, for the change to
// be confirmed with the previous key; it records the new key only then.
type RecoveryKeyWatcher struct {
	store approvalStore
	pin   recoveryKeyPinner
	// now and the withdrawn check are the gate's; tests set them.
	now func() time.Time
}

// Run checks at start and then every minute until ctx ends.
func (w *RecoveryKeyWatcher) Run(ctx context.Context) {
	for {
		if err := w.tick(ctx); err != nil {
			log.Printf("recovery key: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(recoveryKeyCheckInterval):
		}
	}
}

// tick is one comparison, and the confirmation it asks for when the key has
// changed. It blocks while a confirmation waits.
func (w *RecoveryKeyWatcher) tick(ctx context.Context) error {
	site := &SettingsApproval{store: w.store, scope: restoreScope}
	raw, err := site.provenRecoveryKey()
	if err != nil {
		// No proven key yet: there is nothing to record, and every approval
		// refuses on its own until there is one.
		return nil
	}
	path := w.pin.where()
	pin, err := LoadRecoveryKeyPin(path)
	if err != nil {
		return fmt.Errorf("root's record is unusable, so approvals refuse: %v", err)
	}
	if pin == nil {
		if _, err := pinRecoveryKey(path, raw, pinFirstSeen); err != nil {
			return err
		}
		log.Printf("recovery key: recorded this site's key (%s) as root's own", shortFingerprint(recoveryKeyFingerprint(raw)))
		return nil
	}
	fpr := recoveryKeyFingerprint(raw)
	clock := time.Now().UTC()
	if w.now != nil {
		clock = w.now()
	}
	if fpr == pin.Fingerprint || pin.declineHolds(fpr, clock) {
		return nil
	}
	previous, err := pin.Raw()
	if err != nil {
		return err
	}

	gate := &SettingsApproval{
		store: w.store, scope: rekeyScope, fixedRecipient: previous, now: w.now,
		// Nothing withdraws a confirmation; it waits for the operator.
		withdrawn: func(context.Context, int64) (bool, error) { return false, nil },
	}
	issued := time.Now().UTC()
	if w.now != nil {
		issued = w.now()
	}
	statement := primitives.ApprovalStatement{
		Primitive: "recovery_key_change",
		Summary: "This site's backup recovery key has changed. Restores and copies of this site wait until the new " +
			"key is confirmed with the previous one.",
		Facts: []primitives.ApprovalFact{
			{Label: "Previous key", Value: shortFingerprint(pin.Fingerprint) + ", recorded " + pin.PinnedTime + " (" + pin.How + ")"},
			{Label: "New key", Value: shortFingerprint(fpr)},
		},
	}
	log.Printf("recovery key: this site's key changed (%s to %s); asking for the change to be confirmed with the previous key",
		shortFingerprint(pin.Fingerprint), shortFingerprint(fpr))
	err = gate.Require(ctx, issued.Unix(), statement)

	// The wait can be a quarter of an hour, and root may have accepted a key
	// in it (recovery-key accept). An answer to this request speaks only for
	// the record it was asked against.
	now, lerr := LoadRecoveryKeyPin(path)
	if lerr != nil {
		return fmt.Errorf("root's record is unusable, so approvals refuse: %v", lerr)
	}
	if now == nil || now.Fingerprint != pin.Fingerprint || now.PinnedTime != pin.PinnedTime {
		log.Printf("recovery key: root's record changed while the confirmation waited; its answer is set aside")
		return nil
	}
	pin = now
	if err == nil {
		if _, err := pinRecoveryKey(path, raw, pinConfirmed); err != nil {
			return err
		}
		log.Printf("recovery key: the change to %s was confirmed with the previous key; recorded", shortFingerprint(fpr))
		return nil
	}
	if gate.declined {
		pin.DeclinedFingerprint = fpr
		pin.DeclinedTime = time.Now().UTC().Format("2006-01-02 15:04:05")
		if werr := writeRecoveryKeyPin(path, pin); werr != nil {
			return werr
		}
		log.Printf("recovery key: the change to %s was declined; approvals stay sealed to %s", shortFingerprint(fpr), shortFingerprint(pin.Fingerprint))
		return nil
	}
	// Expired or ended: asked again at the next tick.
	return nil
}

// cliRecoveryKey is `joinery-agent recovery-key [accept]`: show root's record
// beside the site's key, or, as root, record the site's current proven key.
// accept is for a previous key that is lost; with the previous key, confirm
// on the Backups page instead.
func cliRecoveryKey(args []string) int {
	accept := len(args) == 1 && args[0] == "accept"
	if len(args) > 1 || (len(args) == 1 && !accept) {
		return cliError("usage: joinery-agent recovery-key [accept]")
	}
	// Root's record and the site's config are root's to read; without root
	// both would read as something wrong rather than as not allowed.
	if os.Geteuid() != 0 {
		return cliError("recovery-key reads root's record and the site's config: run it as root")
	}
	cfg := cliConfig()
	if cfg.Siteless {
		return cliError("this machine has no site, so it has no recovery key of its own")
	}
	db, err := NewDB(cfg)
	if err != nil {
		return cliError("the site's database could not be opened: %v", err)
	}
	defer db.Close()
	site := &SettingsApproval{store: dbSettings{db: db}, scope: restoreScope}
	raw, siteErr := site.provenRecoveryKey()

	path := RecoveryKeyPinPath()
	pin, pinErr := LoadRecoveryKeyPin(path)
	switch {
	case pinErr != nil:
		fmt.Printf("Root's record (%s): unusable: %v\n", path, pinErr)
	case pin == nil:
		fmt.Printf("Root's record (%s): none yet\n", path)
	default:
		fmt.Printf("Root's record: %s, recorded %s (%s)\n", shortFingerprint(pin.Fingerprint), pin.PinnedTime, pin.How)
	}
	if siteErr != nil {
		fmt.Printf("The site's key: %v\n", siteErr)
	} else {
		fmt.Printf("The site's key: %s\n", shortFingerprint(recoveryKeyFingerprint(raw)))
	}
	if !accept {
		return 0
	}
	if siteErr != nil {
		return cliError("there is no proven key on the site to accept")
	}
	if _, err := pinRecoveryKey(path, raw, pinAcceptedAsRoot); err != nil {
		return cliError("%v", err)
	}
	fmt.Printf("Recorded %s. Restores and copies of this site are approved with it from now on.\n", shortFingerprint(recoveryKeyFingerprint(raw)))
	return 0
}
