package primitives

// The key of a backup this machine did not make, opened as its restore is
// approved (B20).
//
// A site moved here keeps the backups its previous server made: that server
// hands their records over (copy_export's history), and they restore here
// through the ordinary staging. Their chains are sealed to the previous
// server's own key, which never left it, and to the site's recovery key. So
// stage_chain stages one without a key (BackupStaging::stage_key), and the
// restore's approval, which asks for the recovery key anyway, opens it: the
// statement carries the recovery box (ApprovalKeyBox), the operator's browser
// works out the one value that opens it, and the box is finished here as
// copy_take_key finishes one (openRecoverySealed). The key is written where a
// chain staged with this machine's own key keeps it, and the restore runs as
// any other.
//
// HOSTILE-CALLER REVIEW (rule 5). The management node chooses which staged
// chain to restore, as it always has: the manifest must still match this
// machine's ledger, and the approval still shows the chain, its age and where
// it came from. It never sees the recovery key or what the box holds: the value
// travels from the operator's browser to this site's settings and to this
// agent, never through the plane, and it opens this box and nothing else.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// chainKeyBox is the approval's key box for a staged chain with no key: its
// manifest's box sealed to the recovery key. Nil when the workspace holds the
// chain's key already (staged with this machine's own key).
func chainKeyBox(work string) (*ApprovalKeyBox, error) {
	keyPath := filepath.Join(work, chainKeyFile)
	if info, err := os.Stat(keyPath); err == nil && info.Mode().IsRegular() {
		return nil, nil
	}
	body, err := os.ReadFile(filepath.Join(work, chainManifestFile))
	if err != nil {
		return nil, refusedf("the staged chain at %s cannot be read: %v", work, err)
	}
	var m struct {
		Envelope struct {
			Recipients []struct {
				Kind        string `json:"kind"`
				Fingerprint string `json:"fingerprint"`
				Sealed      string `json:"sealed"`
				Alg         string `json:"alg"`
			} `json:"recipients"`
		} `json:"envelope"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, refusedf("the staged chain at %s has a manifest that is not one", work)
	}
	for _, r := range m.Envelope.Recipients {
		if r.Kind != "recovery" || !sha256Hex.MatchString(r.Fingerprint) {
			continue
		}
		sealed, err := base64.StdEncoding.DecodeString(r.Sealed)
		if err != nil || len(sealed) > copyTakeKeyMaxSealed {
			continue
		}
		ciphertext, ephemeral, ok := recoveryBoxParts(sealed, r.Alg)
		if !ok {
			continue
		}
		fingerprint := r.Fingerprint
		return &ApprovalKeyBox{
			Ciphertext:          ciphertext,
			EphemeralPublic:     ephemeral,
			RecoveryFingerprint: fingerprint,
			Open: func(shared, recoveryPublic []byte) error {
				sum := sha256.Sum256(recoveryPublic)
				got := hex.EncodeToString(sum[:])
				if subtle.ConstantTimeCompare([]byte(got), []byte(fingerprint)) != 1 {
					return fmt.Errorf("the key given has fingerprint %s, and this backup is sealed to the recovery key %s",
						got[:16], fingerprint[:16])
				}
				dataKey, err := openRecoverySealed(sealed, shared, recoveryPublic)
				if err != nil {
					return err
				}
				defer zero(dataKey)
				if len(dataKey) == 0 || len(dataKey) > 1024 || strings.ContainsAny(string(dataKey), "\n\r") {
					return errors.New("what the recovery key opened is not a chain key")
				}
				if err := writeFileAtomic(keyPath, dataKey, 0o600); err != nil {
					return fmt.Errorf("could not keep the chain's key: %w", err)
				}
				return nil
			},
		}, nil
	}
	return nil, refusedf("the staged chain at %s has no key, and its manifest seals none to the recovery key. "+
		"Prepare it again: a chain this machine made is staged with its key", work)
}
