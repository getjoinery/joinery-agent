package primitives

// copy_look and copy_take_key: a copy made from the site's backups alone,
// when the site's server is dead (specs/site_copy.md WP10, Phase 2).
//
// With a live source, the chain's data key reaches the copy in an export the
// source's owner approves on the source (copy_export, copy_import). With the
// source dead there is no one to seal it, and the one other holder of the key
// is the owner's backup recovery key: every chain's envelope carries the data
// key sealed to it (a libsodium sealed box). So the owner opens it, on THIS
// machine's own page, and the management node never sees the recovery key or
// what it opens.
//
//   copy_look      report the look path, so the owner can reach this copy's
//                  page past the quiet state (the management node shows it).
//   copy_take_key  read the chain's manifest from its storage provider and hold
//                  it to the job (copy_stored_manifest.go), stage the backup's
//                  statement on this site's own page (the chain, its newest
//                  run, when the provider stored it, its manifest hash, the
//                  recovery key's fingerprint) and wait for the owner. Their browser imports
//                  the recovery key and works out the one value that opens the
//                  sealed box: the X25519 of the recovery key with the box's
//                  ephemeral public key. The browser has no XSalsa20, so the
//                  box is finished here (openRecoverySealed). That value opens
//                  this one box and nothing else; the recovery key never leaves
//                  the browser. The opened key is written as the chain's
//                  chain.key and the stated manifest as the vouch, which is
//                  exactly what copy_import leaves, so copy_stage and
//                  copy_restore run as they always do.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What can a compromised management node do with these words? Name a chain
// of its choosing: this machine reads that chain's manifest from its storage
// itself, takes the run and the hash from the bytes, and asks the owner to
// open only the key that manifest seals. It could have made the whole chain
// itself, sealed to the recovery public key (which is public): then its
// provider stored it when it was made, after the site's server died, and the
// page shows that date beside the run (specs/storage_targets.md F7). It could
// sign a link to a server of its own, which answers any date it likes: the
// date is believed only from a provider's storage host, and anywhere else the
// page says it could not be checked. Opening the key gains it nothing it did
// not have. It cannot learn the recovery key: the page that takes it is
// served by this machine, and what comes back opens one box.
//
// The words run only on a dormant copy (quiet copy), so a live site never
// takes a chain key from anyone.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/salsa20/salsa"
)

// copyTakeKeyMaxSealed bounds the sealed data key a request carries: a chain
// key is a 44-character passphrase, sealed with 48 bytes of overhead.
const copyTakeKeyMaxSealed = 512

// CopyKeyRequest is what the copy's own page shows its owner.
type CopyKeyRequest struct {
	ChainID             string `json:"chain_id"`
	ManifestSHA256      string `json:"manifest_sha256"`
	RunTime             string `json:"run_time"`
	StoredTime          string `json:"stored_time"` // when the provider stored the manifest; "" when not checked
	StoredAt            string `json:"stored_at"`   // the provider that says so; "" when not checked
	RecoveryFingerprint string `json:"recovery_fingerprint"`
	EphemeralPublic     string `json:"ephemeral_public"`
	Site                string `json:"site"`
}

// KeyHandoff asks this machine's owner, on this machine's own site, for the
// value that opens a chain key sealed to their recovery key. Await stages the
// request and calls try with each answer; an answer try refuses is shown on
// the page as the reason and the wait goes on. It returns nil once try
// accepts one, and a refusal on a decline, a withdrawn job or the end of the
// wait.
type KeyHandoff interface {
	Await(ctx context.Context, jobID int64, req CopyKeyRequest, try func(shared, recoveryPublic []byte) error) error
}

func init() {
	Register(Primitive{
		Name:        "copy_look",
		Class:       ClassObserve,
		Description: "On a dormant copy, report the path that lets its owner look at it past the quiet state.",
		Params:      []ParamSpec{},
		Run:         copyLookRun,
		Timeout:     1 * time.Minute,
	})
	Register(Primitive{
		Name:  "copy_take_key",
		Class: ClassOperate,
		Description: "On a dormant copy made from backups, ask its owner on its own page to open the chain's key " +
			"with their recovery key, and take it.",
		Params: []ParamSpec{
			{Name: "chain_id", Type: ParamString, Required: true, MaxLen: 64, Pattern: chainIDPattern},
			{Name: "manifest_sha256", Type: ParamString, Required: true, MaxLen: 64, Pattern: sha256Hex},
			{Name: "run_time", Type: ParamString, MaxLen: 40},
			{Name: "recovery_fingerprint", Type: ParamString, Required: true, MaxLen: 64, Pattern: sha256Hex},
			{Name: "recovery_sealed", Type: ParamString, Required: true, MaxLen: copyTakeKeyMaxSealed},
			{Name: "site", Type: ParamString, MaxLen: 253},
			// A link to the chain's newest manifest, signed by the management
			// node for one object: this machine reads the backup itself rather
			// than taking the statement on the management node's word.
			{Name: "manifest_url", Type: ParamString, Required: true, MaxLen: 2048, Pattern: signedURLPattern},
		},
		Run:     copyTakeKeyRun,
		Timeout: ApprovalWindow + 5*time.Minute,
		Quiet:   QuietCopy,
	})
}

func copyLookRun(ctx context.Context, env *ExecEnv, params Params) (map[string]interface{}, error) {
	st, err := ReadSiteState(env)
	if err != nil {
		return nil, refusedf("copy_look: %v", err)
	}
	if env == nil || env.SiteRoot == "" || st.Reason != "copy" {
		return nil, refusedf("copy_look runs only on a dormant copy (quiet copy)")
	}
	look := copyLookPath(env)
	if look == "" {
		return nil, refusedf("this copy's quiet state holds no look secret")
	}
	return map[string]interface{}{"look_path": look}, nil
}

func copyTakeKeyRun(ctx context.Context, env *ExecEnv, params Params) (map[string]interface{}, error) {
	st, err := ReadSiteState(env)
	if err != nil {
		return nil, refusedf("copy_take_key: %v", err)
	}
	if env == nil || env.SiteRoot == "" || st.Reason != "copy" {
		return nil, refusedf("copy_take_key runs only on a dormant copy (quiet copy): a live site never takes a chain key")
	}
	if env.CopyKeyHandoff == nil {
		return nil, refusedf("this machine cannot ask its owner on its own page (no site database), so it takes no key")
	}
	sealed, err := base64.StdEncoding.DecodeString(params.String("recovery_sealed"))
	if err != nil || len(sealed) <= 32+box.Overhead {
		return nil, refusedf("copy_take_key: the sealed chain key is not a sealed box")
	}
	chainID := params.String("chain_id")
	manifest := params.String("manifest_sha256")
	fingerprint := params.String("recovery_fingerprint")
	stored, err := readStoredManifest(ctx, params.String("manifest_url"), chainID, manifest,
		params.String("recovery_sealed"), fingerprint)
	if err != nil {
		return nil, refusedf("copy_take_key: %v", err)
	}
	req := CopyKeyRequest{
		ChainID:             chainID,
		ManifestSHA256:      manifest,
		RunTime:             stored.NewestRun.Format(time.RFC3339),
		StoredAt:            stored.StoredAt,
		RecoveryFingerprint: fingerprint,
		EphemeralPublic:     base64.StdEncoding.EncodeToString(sealed[:32]),
		Site:                params.String("site"),
	}
	if !stored.StoredTime.IsZero() {
		req.StoredTime = stored.StoredTime.Format(time.RFC3339)
	}

	var dataKey []byte
	try := func(shared, recoveryPublic []byte) error {
		sum := sha256.Sum256(recoveryPublic)
		got := hex.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(got), []byte(fingerprint)) != 1 {
			return fmt.Errorf("that recovery key has fingerprint %s, and this backup is sealed to %s", got[:16], fingerprint[:16])
		}
		opened, err := openRecoverySealed(sealed, shared, recoveryPublic)
		if err != nil {
			return err
		}
		if len(opened) == 0 || len(opened) > 1024 || strings.ContainsAny(string(opened), "\n\r") {
			zero(opened)
			return errors.New("what the key opened is not a chain key")
		}
		dataKey = opened
		return nil
	}
	if err := env.CopyKeyHandoff.Await(ctx, JobIDFrom(ctx), req, try); err != nil {
		return nil, err
	}
	defer zero(dataKey)

	work := chainWorkspace(ctx, env, chainID)
	if err := os.MkdirAll(work, 0o700); err != nil {
		return nil, fmt.Errorf("could not make chain %s's workspace: %w", chainID, err)
	}
	_ = os.Chmod(work, 0o700)
	if err := writeFileAtomic(filepath.Join(work, chainKeyFile), dataKey, 0o600); err != nil {
		return nil, fmt.Errorf("could not write chain %s's key: %w", chainID, err)
	}
	if err := writeStateFile(env, copyVouchedFile, []byte(manifest+" "+chainID+"\n")); err != nil {
		return nil, fmt.Errorf("could not write the vouched run: %w", err)
	}
	return map[string]interface{}{
		"chain_id":             chainID,
		"manifest_sha256":      manifest,
		"recovery_fingerprint": fingerprint,
		"run_time":             req.RunTime,
		"stored_time":          req.StoredTime,
		"stored_at":            req.StoredAt,
	}, nil
}

// openRecoverySealed finishes opening a libsodium sealed box
// (crypto_box_seal) given the X25519 shared secret of the recipient's private
// key with the box's ephemeral public key, which is what the owner's browser
// works out with WebCrypto. The rest is crypto_box's: the key is HSalsa20 of
// that secret, the nonce BLAKE2b-192 of the ephemeral and recipient public
// keys, and XSalsa20-Poly1305 authenticates and opens.
func openRecoverySealed(sealed, shared, recipientPublic []byte) ([]byte, error) {
	if len(sealed) <= 32+box.Overhead || len(shared) != 32 || len(recipientPublic) != 32 {
		return nil, errors.New("the answer is not the shape the backup's key opens with")
	}
	allZero := true
	for _, b := range shared {
		allZero = allZero && b == 0
	}
	if allZero {
		return nil, errors.New("the answer is not the shape the backup's key opens with")
	}
	ephemeral := sealed[:32]
	h, err := blake2b.New(24, nil)
	if err != nil {
		return nil, err
	}
	h.Write(ephemeral)
	h.Write(recipientPublic)
	var nonce [24]byte
	copy(nonce[:], h.Sum(nil))

	var secret, key [32]byte
	var zeros [16]byte
	copy(secret[:], shared)
	salsa.HSalsa20(&key, &zeros, &secret, &salsa.Sigma)
	zero(secret[:])
	opened, ok := box.OpenAfterPrecomputation(nil, sealed[32:], &nonce, &key)
	zero(key[:])
	if !ok {
		return nil, errors.New("that answer does not open this backup's key: the recovery key does not match the one the backup was sealed to")
	}
	return opened, nil
}

// jobIDKey carries the job's id in the context Execute hands a primitive.
type jobIDKey struct{}

// WithJobID returns ctx carrying jobID.
func WithJobID(ctx context.Context, jobID int64) context.Context {
	return context.WithValue(ctx, jobIDKey{}, jobID)
}

// JobIDFrom is the id of the job a primitive is running for, or 0.
func JobIDFrom(ctx context.Context) int64 {
	if v, ok := ctx.Value(jobIDKey{}).(int64); ok {
		return v
	}
	return 0
}
