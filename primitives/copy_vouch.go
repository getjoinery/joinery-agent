package primitives

// copy_vouch and copy_take_vouch: the final copy of a switch-over, which
// carries no secret (specs/site_copy.md B44, step 8).
//
// By the final copy the copy T already holds everything secret a copy needs:
// the chain's data key, the certificate and the DKIM keys came in an export
// the owner approved on S (copy_export, copy_import). The final backup run
// extends that same chain, so the one new fact T needs is which manifest
// version S stands behind now. That fact is a hash, not a secret, so it needs
// no approval: and the approval could not be given anyway, because a frozen
// S answers every request, its owner's included, with the maintenance page.
//
//   copy_vouch       on S, frozen (quiet switchover): sign "this manifest of
//                    chain X, from my upload ledger, is mine", for T's key.
//   copy_take_vouch  on T, dormant (quiet copy): check that signature against
//                    the one S key the dormant install recorded, and replace
//                    the vouch with it, for a chain whose key T already holds.
//
// The vouch is signed under its own domain, so neither an export nor a
// request signature can be passed off as one, or one as them.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with these words?
// Ask S to vouch for a run: S vouches only for a manifest its own ledger
// recorded uploading, so T can only be pointed at S's own backup. Deliver a
// vouch late or again: one issued at or before the newest bundle T took is a
// replay, and refused, as an expired one is.
//
// What they cannot do:
//
//   - Move a secret. Nothing secret is in a vouch: no data key, no
//     certificate, no DKIM key. Secrets reach T only through copy_export.
//   - Give T a chain it holds no key for. copy_take_vouch refuses a chain
//     with no chain.key in its workspace: that key came in an approved export.
//   - Vouch from a live site or a copy. copy_vouch runs only on a site frozen
//     for its switch-over; refreshing a live site's copy is copy_export's, with
//     its approval.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CopyVouchDomain names a vouch: its signature prefix and the format field T
// checks first.
const CopyVouchDomain = "joinery-copy-vouch-v1"

// copyVouchLifetime is how long T accepts a vouch after S issued it. A vouch
// is made inside the switch-over's downtime and taken minutes later.
const copyVouchLifetime = time.Hour

// copyVouchMaxWire bounds a vouch as it travels: S's result and T's params.
const copyVouchMaxWire = 4096

// copyVouchBody is what S signs.
type copyVouchBody struct {
	Format         string `json:"format"`
	SourceNodeID   int64  `json:"source_node_id"`
	SourceKey      string `json:"source_key"`
	TargetKey      string `json:"target_key"`
	Issued         string `json:"issued"`
	Expires        string `json:"expires"`
	ChainID        string `json:"chain_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

func init() {
	Register(Primitive{
		Name:        "copy_vouch",
		Class:       ClassOperate,
		Description: "On a site frozen for its switch-over, sign the newest manifest of a backup chain for its copy. Carries no secret.",
		Params: []ParamSpec{
			{Name: "profile", Type: ParamEnum, Required: true, Values: []string{"site", "manager"}},
			{Name: "chain_id", Type: ParamString, Required: true, MaxLen: 64, Pattern: chainIDPattern},
			{Name: "target_public_key", Type: ParamString, Required: true, MaxLen: 64, Pattern: base64Key},
		},
		Run:     copyVouchRun,
		Timeout: 5 * time.Minute,
		Quiet:   QuietSwitchover,
	})
	Register(Primitive{
		Name:        "copy_take_vouch",
		Class:       ClassOperate,
		Description: "On a dormant copy, check the source's signed vouch and make it the run this copy applies, for a chain whose key it already holds.",
		Params: []ParamSpec{
			{Name: "vouch", Type: ParamString, Required: true, MaxLen: copyVouchMaxWire},
		},
		Run:     copyTakeVouchRun,
		Timeout: 5 * time.Minute,
		Quiet:   QuietCopy,
	})
}

func copyVouchRun(ctx context.Context, env *ExecEnv, params Params) (map[string]interface{}, error) {
	if env == nil || env.SiteRoot == "" {
		return nil, refusedf("copy_vouch: this machine has no site")
	}
	st, err := ReadSiteState(env)
	if err != nil {
		return nil, refusedf("copy_vouch: %v", err)
	}
	if st.Reason != "switchover" {
		return nil, refusedf("copy_vouch runs only on a site frozen for its switch-over (quiet switchover). " +
			"A live site's copy is refreshed with copy_export, which its owner approves")
	}
	target, err := decodeAgentKey(params.String("target_public_key"))
	if err != nil {
		return nil, refusedf("copy_vouch: the target key %v", err)
	}

	profile := BackupProfile(params.String("profile"))
	chainID := params.String("chain_id")
	relname := chainID + "/" + chainManifestFile
	manifest := filepath.Join(backupDirFor(ctx, env, profile), chainID, chainManifestFile)
	if info, err := os.Stat(manifest); err != nil || !info.Mode().IsRegular() {
		return nil, refusedf("this machine holds no manifest of chain %s (%s). The final backup run may have "+
			"started a new chain, which the copy holds no key for", chainID, manifest)
	}
	if err := verifyLedgered(env, profile, relname, manifest); err != nil {
		return nil, err
	}
	match, _ := ledgerMatchFor(env, profile, relname, manifest)
	sum, err := hashFile(manifest)
	if err != nil {
		return nil, refusedf("could not read chain %s's manifest: %v", chainID, err)
	}

	if env.Key == nil || env.NodeID == nil {
		return nil, refusedf("copy_vouch: this agent cannot reach its own key, so it cannot sign")
	}
	key, err := env.Key()
	if err != nil {
		return nil, refusedf("copy_vouch: %v", err)
	}
	nodeID, err := env.NodeID()
	if err != nil || nodeID <= 0 {
		return nil, refusedf("copy_vouch: this machine has no node id to sign as")
	}

	issued := time.Now().UTC()
	wire, err := signCopyVouch(copyVouchBody{
		Format:         CopyVouchDomain,
		SourceNodeID:   nodeID,
		SourceKey:      base64.StdEncoding.EncodeToString(key.PublicKey()),
		TargetKey:      base64.StdEncoding.EncodeToString(target),
		Issued:         issued.Format(time.RFC3339Nano),
		Expires:        issued.Add(copyVouchLifetime).Format(time.RFC3339Nano),
		ChainID:        chainID,
		ManifestSHA256: sum,
	}, func(msg []byte) ([]byte, error) { return key.SignDomain(CopyVouchDomain, msg) })
	if err != nil {
		return nil, refusedf("copy_vouch: could not sign: %v", err)
	}

	full := sha256.Sum256(target)
	return map[string]interface{}{
		"vouch":              wire,
		"chain_id":           chainID,
		"manifest_sha256":    sum,
		"uploaded":           match.UploadedTime,
		"target_fingerprint": hex.EncodeToString(full[:])[:16],
		"issued":             issued.Format(time.RFC3339Nano),
	}, nil
}

func copyTakeVouchRun(ctx context.Context, env *ExecEnv, params Params) (map[string]interface{}, error) {
	st, err := ReadSiteState(env)
	if err != nil {
		return nil, refusedf("copy_take_vouch: %v", err)
	}
	if env == nil || env.SiteRoot == "" || st.Reason != "copy" {
		return nil, refusedf("copy_take_vouch runs only on a dormant copy (quiet copy), and this site is not one")
	}
	if st.CopyOf <= 0 {
		return nil, refusedf("copy_take_vouch: this copy does not record which node it is a copy of")
	}
	source, err := recordedSourceKey(env)
	if err != nil {
		return nil, refusedf("copy_take_vouch: %v", err)
	}
	body, err := verifyCopyVouch(params.String("vouch"), source)
	if err != nil {
		return nil, refusedf("copy_take_vouch refused: %v", err)
	}
	if body.SourceNodeID != st.CopyOf {
		return nil, refusedf("copy_take_vouch refused: the vouch is from node %d, and this machine is a copy of node %d",
			body.SourceNodeID, st.CopyOf)
	}
	if env.Key == nil {
		return nil, refusedf("copy_take_vouch: this agent cannot reach its own key")
	}
	key, err := env.Key()
	if err != nil {
		return nil, refusedf("copy_take_vouch: %v", err)
	}
	own := base64.StdEncoding.EncodeToString(key.PublicKey())
	if subtle.ConstantTimeCompare([]byte(body.TargetKey), []byte(own)) != 1 {
		return nil, refusedf("copy_take_vouch refused: the vouch is for another machine's key, not this one's")
	}
	if !chainIDPattern.MatchString(body.ChainID) || len(body.ChainID) > 64 || !sha256Hex.MatchString(body.ManifestSHA256) {
		return nil, refusedf("copy_take_vouch refused: the vouch does not name a chain and a manifest hash")
	}

	issued, err1 := time.Parse(time.RFC3339Nano, body.Issued)
	expires, err2 := time.Parse(time.RFC3339Nano, body.Expires)
	if err1 != nil || err2 != nil {
		return nil, refusedf("copy_take_vouch refused: the vouch's times are not times")
	}
	now := time.Now().UTC()
	if now.After(expires) {
		return nil, refusedf("copy_take_vouch refused: the vouch expired at %s. Vouch again from the source",
			expires.Format(time.RFC3339))
	}
	if issued.After(now.Add(copyExportClockSkew)) {
		return nil, refusedf("copy_take_vouch refused: the vouch says it was issued at %s, ahead of this machine's "+
			"clock by more than %s. Check both machines' clocks", issued.Format(time.RFC3339), copyExportClockSkew)
	}
	// One high-water mark for exports and vouches: neither may be older than
	// the newest of either this copy took.
	if last, ok, err := lastImportIssued(env); err != nil {
		return nil, refusedf("copy_take_vouch: %v", err)
	} else if ok && !issued.After(last) {
		return nil, refusedf("copy_take_vouch refused: this vouch was issued at %s, and this copy has already taken "+
			"an export or vouch issued at %s. A vouch is taken once, and never an older one after a newer",
			issued.Format(time.RFC3339Nano), last.Format(time.RFC3339Nano))
	}

	work := chainWorkspace(ctx, env, body.ChainID)
	if info, err := os.Stat(filepath.Join(work, chainKeyFile)); err != nil || !info.Mode().IsRegular() {
		return nil, refusedf("copy_take_vouch refused: this copy holds no key for chain %s. Its key arrives only in "+
			"an export the source's owner approves: copy again before switching over", body.ChainID)
	}

	if err := writeStateFile(env, copyVouchedFile, []byte(body.ManifestSHA256+" "+body.ChainID+"\n")); err != nil {
		return nil, fmt.Errorf("could not write the vouched run: %w", err)
	}
	if err := writeStateFile(env, copyIssuedFile, []byte(issued.UTC().Format(time.RFC3339Nano)+"\n")); err != nil {
		return nil, fmt.Errorf("could not record the vouch as taken: %w", err)
	}
	return map[string]interface{}{
		"chain_id":        body.ChainID,
		"manifest_sha256": body.ManifestSHA256,
		"issued":          issued.UTC().Format(time.RFC3339Nano),
	}, nil
}

// copyVouchSigned is the message S signs and T verifies: the domain, a
// newline, then the body's exact bytes.
func copyVouchSigned(body []byte) []byte {
	return append([]byte(CopyVouchDomain+"\n"), body...)
}

// signCopyVouch builds the wire vouch from a body, signing with sign. The
// wire shape is the export bundle's: a base64 body and its signature.
func signCopyVouch(body copyVouchBody, sign func([]byte) ([]byte, error)) (string, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	sig, err := sign(copyVouchSigned(raw))
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(copyBundle{
		Body:      base64.StdEncoding.EncodeToString(raw),
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// verifyCopyVouch checks the signature against the one S key T trusts and
// returns the body. Nothing in the body is read before this passes.
func verifyCopyVouch(wire string, source ed25519.PublicKey) (copyVouchBody, error) {
	var b copyBundle
	var body copyVouchBody
	dec := json.NewDecoder(bytes.NewReader([]byte(wire)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return body, errors.New("the vouch is not a vouch")
	}
	raw, err1 := base64.StdEncoding.DecodeString(b.Body)
	sig, err2 := base64.StdEncoding.DecodeString(b.Signature)
	if err1 != nil || err2 != nil || len(sig) != ed25519.SignatureSize {
		return body, errors.New("the vouch is not a vouch")
	}
	if !ed25519.Verify(source, copyVouchSigned(raw), sig) {
		return body, errors.New("the vouch's signature is not the source's under the vouch domain: it was made by " +
			"another key, is something other than a vouch, or changed on the way")
	}
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	if err := strict.Decode(&body); err != nil {
		return body, errors.New("the signed body is not a vouch body")
	}
	if body.Format != CopyVouchDomain {
		return body, fmt.Errorf("the vouch is in format %q, and this agent reads %q", body.Format, CopyVouchDomain)
	}
	return body, nil
}
