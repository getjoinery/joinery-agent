package main

// Root's own record of this site's recovery key.
//
// A destructive job on this machine runs only once someone answers a challenge
// sealed to the site's backup recovery key (approval.go). The site keeps that
// key in its settings table, and its web tier can write that table. Read from
// there alone, the key would be whatever the web tier last wrote: a web
// compromise could put in a key of its own, prove it, and answer every
// approval, which makes a web write a root restore. Nothing the management
// node does closes that, because the web tier can also point this agent at
// another management node (leave.go, join.go).
//
// So root keeps its own copy. The first proven key root sees is recorded here,
// in a root-only file, and an approval is sealed only to the key in this file.
// When the site's key changes, approvals stop until the change is confirmed:
// on the site's own Backups page, with the PREVIOUS recovery key (the
// recovery-key scope in approval.go), or as root at this machine with
// `joinery-agent recovery-key accept` when the previous key is lost. A web
// compromise can make restores wait; it cannot make one run.
//
// A removal of a container site (decommission_site) is approved with that
// site's own key, read by the host from the site's database, and is not held
// to a record here: the most a compromise of that site's web tier gains is the
// removal of that same site.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"joinery-agent/xwing"
)

const recoveryKeyPinFileName = "recovery_key.json"

// RecoveryKeyPinPath is where root's record lives, beside the identity:
// /etc/joinery-agent, which a container carries on its _agent volume.
func RecoveryKeyPinPath() string {
	if v := os.Getenv("AGENT_RECOVERY_KEY_PIN_PATH"); v != "" {
		return v
	}
	return filepath.Join(agentConfigDir, recoveryKeyPinFileName)
}

// How a key came to be recorded, as the record and the CLI say it.
const (
	pinFirstSeen      = "first seen"
	pinConfirmed      = "confirmed on the site with the previous key"
	pinAcceptedAsRoot = "accepted as root at this machine"
)

// RecoveryKeyPin is the record.
type RecoveryKeyPin struct {
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	PinnedTime  string `json:"pinned_time"`
	How         string `json:"how"`
	// DeclinedFingerprint is a changed key someone declined on the Backups
	// page, at DeclinedTime; it is not asked about again for a day
	// (declineQuiet), so a decline is an answer and not a wedge.
	DeclinedFingerprint string `json:"declined_fingerprint,omitempty"`
	DeclinedTime        string `json:"declined_time,omitempty"`
}

// declineQuiet is how long a declined key is not asked about again.
const declineQuiet = 24 * time.Hour

// declineHolds reports whether fpr was declined less than declineQuiet ago.
func (p *RecoveryKeyPin) declineHolds(fpr string, now time.Time) bool {
	if fpr == "" || fpr != p.DeclinedFingerprint {
		return false
	}
	at, err := time.Parse("2006-01-02 15:04:05", p.DeclinedTime)
	return err == nil && now.Before(at.Add(declineQuiet))
}

// recoveryKeyFingerprint is the fingerprint the site's proof setting carries:
// the hex SHA-256 of the raw key.
func recoveryKeyFingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// shortFingerprint is what a person compares on a screen.
func shortFingerprint(fpr string) string {
	if len(fpr) > 16 {
		return fpr[:16]
	}
	return fpr
}

// Raw is the recorded key's bytes.
func (p *RecoveryKeyPin) Raw() ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(p.PublicKey)
	if err != nil || len(raw) != xwing.PublicKeyBytes {
		return nil, fmt.Errorf("the recorded key is not an X-Wing public key")
	}
	if recoveryKeyFingerprint(raw) != p.Fingerprint {
		return nil, fmt.Errorf("the recorded key does not match its recorded fingerprint")
	}
	return raw, nil
}

// LoadRecoveryKeyPin reads root's record: nil with no error when there is
// none yet. A file anything but root could have written is an error, never a
// record: trusting it would hand the choice of key to whoever wrote it.
func LoadRecoveryKeyPin(path string) (*RecoveryKeyPin, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s is open beyond its owner (mode %04o); something other than root could have written it", path, perm)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("%s is owned by uid %d, not by this agent's user", path, st.Uid)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p RecoveryKeyPin
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %v", path, err)
	}
	if _, err := p.Raw(); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return &p, nil
}

// writeRecoveryKeyPin replaces the record in one rename, 0600.
func writeRecoveryKeyPin(path string, p *RecoveryKeyPin) error {
	body, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".recovery_key.*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(body, '\n')); err != nil {
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
	return os.Rename(tmp.Name(), path)
}

// pinRecoveryKey records raw as this site's key.
func pinRecoveryKey(path string, raw []byte, how string) (*RecoveryKeyPin, error) {
	p := &RecoveryKeyPin{
		PublicKey:   base64.StdEncoding.EncodeToString(raw),
		Fingerprint: recoveryKeyFingerprint(raw),
		PinnedTime:  time.Now().UTC().Format("2006-01-02 15:04:05"),
		How:         how,
	}
	if err := writeRecoveryKeyPin(path, p); err != nil {
		return nil, fmt.Errorf("root's record of the recovery key could not be written to %s: %v", path, err)
	}
	return p, nil
}

// recoveryKeyPinner holds an approval to root's record. Its zero value uses
// the real path.
type recoveryKeyPinner struct {
	path string
}

func (r recoveryKeyPinner) where() string {
	if r.path != "" {
		return r.path
	}
	return RecoveryKeyPinPath()
}

// recipient is the key an approval is sealed to, given the site's proven key:
// root's record of it, taken now when there is none yet. A site key that is
// not the recorded one is refused, naming both and how to confirm the change.
func (r recoveryKeyPinner) recipient(siteKey []byte) ([]byte, error) {
	path := r.where()
	pin, err := LoadRecoveryKeyPin(path)
	if err != nil {
		return nil, fmt.Errorf("root's record of this site's recovery key is unusable, so nothing is approved "+
			"against it: %v. Fix or remove the file as root, then run joinery-agent recovery-key accept", err)
	}
	if pin == nil {
		pin, err = pinRecoveryKey(path, siteKey, pinFirstSeen)
		if err != nil {
			return nil, err
		}
	}
	recorded, err := pin.Raw()
	if err != nil {
		return nil, err
	}
	if fpr := recoveryKeyFingerprint(siteKey); fpr != pin.Fingerprint && fpr == pin.DeclinedFingerprint {
		return nil, fmt.Errorf("this site's recovery key (fingerprint %s) is not the one root recorded for it "+
			"(%s, %s), and the change to it was declined on this machine's Backups page at %s. The agent asks "+
			"about it again a day after the decline; to accept it sooner, run joinery-agent recovery-key accept "+
			"as root on this machine", shortFingerprint(fpr), shortFingerprint(pin.Fingerprint), pin.PinnedTime, pin.DeclinedTime)
	} else if fpr != pin.Fingerprint {
		return nil, fmt.Errorf("this site's recovery key (fingerprint %s) is not the one root recorded for it "+
			"(%s, %s). If you changed it, confirm the new key on this machine's Backups page with your previous "+
			"recovery key; if the previous key is lost, run joinery-agent recovery-key accept as root on this "+
			"machine", shortFingerprint(fpr), shortFingerprint(pin.Fingerprint), pin.PinnedTime)
	}
	return recorded, nil
}

// reportRecoveryKeyRecord is check_status's recovery_key: root's record and
// the site's proven key, by fingerprint, and whether they agree. Fingerprints
// only; the record's file is never sent.
func reportRecoveryKeyRecord(store approvalStore, path string) map[string]interface{} {
	out := map[string]interface{}{"recorded": false}
	pin, err := LoadRecoveryKeyPin(path)
	switch {
	case err != nil:
		out["error"] = "root's record is unusable"
	case pin != nil:
		out["recorded"] = true
		out["fingerprint"] = pin.Fingerprint
		out["how"] = pin.How
		out["pinned_time"] = pin.PinnedTime
		if pin.DeclinedFingerprint != "" {
			out["declined_fingerprint"] = pin.DeclinedFingerprint
			out["declined_time"] = pin.DeclinedTime
		}
	}
	site := &SettingsApproval{store: store, scope: restoreScope}
	if raw, err := site.provenRecoveryKey(); err == nil {
		fpr := recoveryKeyFingerprint(raw)
		out["site_fingerprint"] = fpr
		if pin != nil {
			out["matches"] = fpr == pin.Fingerprint
		}
	}
	return out
}
