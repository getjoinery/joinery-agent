package primitives

// copy_export: hand a copy of this site, on another machine, what it needs
// and cannot make for itself (specs/site_copy.md WP4). Run on the source S at
// the first copy, at each refresh and at the final copy.
//
// It returns one bundle, sealed to the copy's agent key and signed with this
// machine's (copy_seal.go). Inside:
//
//   - the chain the copy may apply: its id, the manifest hash this machine
//     recorded uploading (the vouch), and the chain's data key, opened here
//     with this machine's own backup_site_key. That key never travels: the
//     copy keeps its own.
//   - the host bundle (copy_host.go): the certificate and its account, any
//     DNS-01 credentials, the DKIM keys.
//
// Re-sent whole every time, so a certificate renewed here in between always
// reaches the copy.
//
// CLASS DESTRUCTIVE, for what the class means to this agent: never run
// unattended. Nothing here is deleted, but the bundle carries every secret
// the site has, and the party that dispatches it is the management node the
// design does not trust. So this machine's own operator approves each export
// (Q9) on this machine's own Backups page, with its own recovery key, against
// a statement that names the machine the secrets go to by the fingerprint of
// its key: the fingerprint the copy's own admin page shows. A management node
// that swapped in a key of its own would have the owner approve a fingerprint
// that is on no page but its own.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word? Ask
// for an export to a key it holds: the owner is shown that key's
// fingerprint, which matches no copy's page, and declines. Ask for an export
// the owner then approves to the real copy: the copy gets what it was going
// to get anyway.
//
// What it cannot do:
//
//   - Read the bundle. It is sealed to the key in the approved statement; the
//     statement's hash is inside the challenge, so the key cannot change
//     between the approval and the seal.
//   - Vouch for a run this machine did not make. The manifest must be one this
//     machine's upload ledger recorded, byte for byte.
//   - Choose a path. The chain id is pattern-bound and names a directory inside
//     this machine's own backup directory; the host bundle's directories are
//     compiled in.
//   - Run it on a dormant copy, where a bundle would be a copy's secrets
//     leaving for somewhere else. It runs on a live site and under `quiet
//     switchover` (the final copy), and is refused under `quiet copy`.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// siteKeyFile is this machine's backup keypair, under config/: base64 of
// the 32-byte secret key followed by the 32-byte public key
// (BackupEnvelope::SITE_KEY_FILE).
const siteKeyFile = "backup_site_key"

func init() {
	Register(Primitive{
		Name:        "copy_export",
		Class:       ClassDestructive,
		Description: "Seal this site's chain key, certificate and DKIM keys to a copy of it on another machine, once this machine's operator approves.",
		Params: []ParamSpec{
			// Whose backups the chain is among, as stage_chain names it.
			{Name: "profile", Type: ParamEnum, Required: true, Values: []string{"site", "manager"}},
			// The chain the copy will apply.
			{Name: "chain_id", Type: ParamString, Required: true, MaxLen: 64, Pattern: chainIDPattern},
			// The copy's agent public key, base64: what the bundle is sealed
			// to, and what the operator approves by its fingerprint.
			{Name: "target_public_key", Type: ParamString, Required: true, MaxLen: 64,
				Pattern: base64Key},
		},
		Ceremony: copyExportCeremony,
		Run:      copyExportRun,
		// The work is seconds; the operator's answer is the wait.
		Timeout: 10*time.Minute + ApprovalWindow,
		Quiet:   QuietSwitchover,
	})
}

// copyExportPlan is everything the export will hand over, checked, before
// the operator is asked or anything is sealed.
type copyExportPlan struct {
	chainID   string
	manifest  string
	sum       string
	uploaded  string
	target    ed25519.PublicKey
	hostFiles []copyHostFile
	host      copyHostSummary
}

func planCopyExport(ctx context.Context, env *ExecEnv, params Params) (*copyExportPlan, error) {
	if env == nil || env.SiteRoot == "" {
		return nil, refusedf("copy_export: this machine has no site to copy")
	}
	st, err := ReadSiteState(env)
	if err != nil {
		return nil, refusedf("copy_export: %v", err)
	}
	if st.Reason == "copy" {
		return nil, refusedf("copy_export refused: this site is itself a dormant copy, and a copy hands nothing on")
	}

	target, err := decodeAgentKey(params.String("target_public_key"))
	if err != nil {
		return nil, refusedf("copy_export: the target key %v", err)
	}
	if _, err := ed25519PublicToX25519(target); err != nil {
		return nil, refusedf("copy_export: the target key cannot be sealed to: %v", err)
	}

	profile := BackupProfile(params.String("profile"))
	chainID := params.String("chain_id")
	relname := chainID + "/" + chainManifestFile
	manifest := filepath.Join(backupDirFor(ctx, env, profile), chainID, chainManifestFile)
	if info, err := os.Stat(manifest); err != nil || !info.Mode().IsRegular() {
		return nil, refusedf("this machine no longer holds chain %s's manifest (%s), so it cannot open the "+
			"chain's key to hand over. Copy from a chain this machine still keeps: its newest", chainID, manifest)
	}
	// The vouch is only worth what the ledger is: the manifest must be bytes
	// this machine recorded uploading, under this name.
	if err := verifyLedgered(env, profile, relname, manifest); err != nil {
		return nil, err
	}
	match, _ := ledgerMatchFor(env, profile, relname, manifest)
	sum, err := hashFile(manifest)
	if err != nil {
		return nil, refusedf("could not read chain %s's manifest: %v", chainID, err)
	}

	files, host, err := collectHostFiles()
	if err != nil {
		return nil, refusedf("copy_export: the certificates and keys could not be gathered: %v", err)
	}
	return &copyExportPlan{
		chainID: chainID, manifest: manifest, sum: sum, uploaded: match.UploadedTime,
		target: target, hostFiles: files, host: host,
	}, nil
}

// copyExportCeremony composes the statement the operator approves and hands
// back the export scope's gate on this machine's own site.
func copyExportCeremony(ctx context.Context, env *ExecEnv, params Params) (ApprovalStatement, ApprovalGate, func(), error) {
	plan, err := planCopyExport(ctx, env, params)
	if err != nil {
		return ApprovalStatement{}, nil, nil, err
	}
	if env.ExportApproval == nil {
		return ApprovalStatement{}, nil, nil, refusedf("this node has no way to ask its own operator to approve " +
			"an export, so it will not hand anything over")
	}

	full := sha256.Sum256(plan.target)
	certs := "none"
	if len(plan.host.Lineages) > 0 {
		certs = strings.Join(plan.host.Lineages, ", ") + " (with its private key and its Let's Encrypt account)"
	}
	dkim := "none"
	if plan.host.DKIMKeys > 0 {
		dkim = fmt.Sprintf("%d private key(s)", plan.host.DKIMKeys)
	}
	uploaded := plan.uploaded
	if uploaded == "" {
		uploaded = "unknown"
	}
	return ApprovalStatement{
		Primitive: "copy_export",
		Summary: "Hand this site's backup key, certificate and DKIM keys to a copy of this site on another " +
			"machine, sealed so only that machine can open them.",
		Facts: []ApprovalFact{
			{Label: "Goes to the machine whose key fingerprint is", Value: hex.EncodeToString(full[:])[:16]},
			{Label: "Check", Value: "the same fingerprint is on that machine's own admin page. If it is not, decline."},
			{Label: "Its full key (SHA-256)", Value: hex.EncodeToString(full[:])},
			{Label: "Backup chain", Value: plan.chainID},
			{Label: "Newest run of it uploaded", Value: uploaded},
			{Label: "Certificates", Value: certs},
			{Label: "DKIM keys", Value: dkim},
		},
	}, env.ExportApproval, nil, nil
}

func copyExportRun(ctx context.Context, env *ExecEnv, params Params) (map[string]interface{}, error) {
	plan, err := planCopyExport(ctx, env, params)
	if err != nil {
		return nil, err
	}
	if env.Key == nil || env.NodeID == nil {
		return nil, refusedf("copy_export: this agent cannot reach its own key, so it cannot sign an export")
	}
	key, err := env.Key()
	if err != nil {
		return nil, refusedf("copy_export: %v", err)
	}
	nodeID, err := env.NodeID()
	if err != nil || nodeID <= 0 {
		return nil, refusedf("copy_export: this machine has no node id to sign an export as")
	}

	dataKey, err := openChainDataKey(env, plan.manifest)
	if err != nil {
		return nil, refusedf("chain %s's data key did not open with this machine's own backup key: %v",
			plan.chainID, err)
	}

	payload, err := json.Marshal(copyPayload{
		Chains: []copyChain{{ChainID: plan.chainID, DataKey: dataKey, Manifests: []string{plan.sum}}},
		Files:  plan.hostFiles,
	})
	if err != nil {
		return nil, err
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(payload)
	if err := zw.Close(); err != nil {
		return nil, err
	}
	zero(payload)

	sealed, err := sealToAgentKey(plan.target, gz.Bytes())
	if err != nil {
		return nil, refusedf("copy_export: %v", err)
	}

	issued := time.Now().UTC()
	wire, err := signCopyBundle(copyBundleBody{
		Format:       CopyExportDomain,
		SourceNodeID: nodeID,
		SourceKey:    base64.StdEncoding.EncodeToString(key.PublicKey()),
		TargetKey:    base64.StdEncoding.EncodeToString(plan.target),
		Issued:       issued.Format(time.RFC3339Nano),
		Expires:      issued.Add(copyExportLifetime).Format(time.RFC3339Nano),
		Sealed:       base64.StdEncoding.EncodeToString(sealed),
	}, func(msg []byte) ([]byte, error) { return key.SignDomain(CopyExportDomain, msg) })
	if err != nil {
		return nil, refusedf("copy_export: could not sign the export: %v", err)
	}
	if len(wire) > copyExportMaxBundle {
		return nil, refusedf("the export is %d bytes, more than one job carries (%d): this machine holds more "+
			"certificates and keys than a copy takes", len(wire), copyExportMaxBundle)
	}

	full := sha256.Sum256(plan.target)
	return map[string]interface{}{
		"bundle":             wire,
		"bundle_bytes":       len(wire),
		"chain_id":           plan.chainID,
		"manifest_sha256":    plan.sum,
		"target_fingerprint": hex.EncodeToString(full[:])[:16],
		"certificates":       plan.host.Lineages,
		"dkim_keys":          plan.host.DKIMKeys,
		"host_files":         plan.host.Files,
		"issued":             issued.Format(time.RFC3339Nano),
	}, nil
}

// openChainDataKey opens the chain data key from a manifest's envelope with
// this machine's own backup_site_key: libsodium sealed boxes, one per
// recipient (BackupEnvelope::build).
func openChainDataKey(env *ExecEnv, manifest string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(strings.TrimRight(env.SiteRoot, "/"), "config", siteKeyFile))
	if err != nil {
		return "", fmt.Errorf("this machine's backup key cannot be read: %v", err)
	}
	pair, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	zero(raw)
	if err != nil || len(pair) != 64 {
		return "", errors.New("this machine's backup key is not a keypair")
	}
	defer zero(pair)
	var priv, pub [32]byte
	copy(priv[:], pair[:32])
	copy(pub[:], pair[32:])
	defer zero(priv[:])

	body, err := os.ReadFile(manifest)
	if err != nil {
		return "", err
	}
	var m struct {
		Envelope struct {
			Recipients []struct {
				Kind   string `json:"kind"`
				Sealed string `json:"sealed"`
			} `json:"recipients"`
		} `json:"envelope"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return "", errors.New("the manifest is not a chain manifest")
	}
	for _, r := range m.Envelope.Recipients {
		blob, err := base64.StdEncoding.DecodeString(r.Sealed)
		if err != nil {
			continue
		}
		if opened, ok := box.OpenAnonymous(nil, blob, &pub, &priv); ok {
			return string(opened), nil
		}
	}
	return "", errors.New("no recipient of the chain's envelope is this machine's key")
}

// decodeAgentKey reads a base64 Ed25519 public key.
func decodeAgentKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("is not an agent public key")
	}
	return ed25519.PublicKey(raw), nil
}
