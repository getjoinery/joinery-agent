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
//   - the site's backup history, when asked for (history): the newest
//     manifest of each chain this machine's upload ledger holds
//     (ledgerHistory). The copy records them in its own ledger, so after the
//     switch the site's backups from before it restore there. Hashes and
//     times, read from the ledger as it is. Asked for only of a copy whose
//     agent reads it: an older one refuses a bundle with anything it does not
//     know.
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

	"joinery-agent/xwing"
)

// siteKeyFile is this machine's backup key, under config/: base64 of its
// 32-byte X-Wing seed (BackupEnvelope::SITE_KEY_FILE). siteKeyRetiredFile is
// the old X25519 keypair the converger moved aside when it minted the seed
// (base64 of the 32-byte secret then the 32-byte public key): chains begun
// before that are sealed to it (specs/post_quantum_sealing.md R7).
const (
	siteKeyFile        = "backup_site_key"
	siteKeyRetiredFile = "backup_site_key.retired"
)

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
			// The copy's X-Wing key and its agent key's signature over it
			// (AgentKEMDomain): what the bundle is sealed to, once the
			// signature verifies against target_public_key.
			{Name: "target_kem_public_key", Type: ParamString, Required: true, MaxLen: 2048},
			{Name: "target_kem_signature", Type: ParamString, Required: true, MaxLen: 128},
			// Hand over the site's backup history too.
			{Name: "history", Type: ParamBool},
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
	chainID     string
	manifest    string
	sum         string
	uploaded    string
	target      ed25519.PublicKey
	targetKEM   []byte
	hostFiles   []copyHostFile
	host        copyHostSummary
	profile     BackupProfile
	history     []copyHistoryChain
	withHistory bool
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
	// The bundle is sealed to the copy's X-Wing key, and only once its own
	// agent key (the one the owner approves by fingerprint) has signed it.
	targetKEM, err := VerifiedAgentKEM(target, params.String("target_kem_public_key"), params.String("target_kem_signature"))
	if err != nil {
		return nil, refusedf("copy_export: %v", err)
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
	plan := &copyExportPlan{
		chainID: chainID, manifest: manifest, sum: sum, uploaded: match.UploadedTime,
		target: target, targetKEM: targetKEM, hostFiles: files, host: host, profile: profile,
	}
	if params.Bool("history") {
		history, err := ledgerHistory(env, profile, copyHistoryMax)
		if err != nil {
			return nil, refusedf("copy_export: this machine's record of its backups could not be read: %v", err)
		}
		plan.history = history
		plan.withHistory = true
	}
	return plan, nil
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
		with := "with its private key and its Let's Encrypt account"
		if !plan.host.Account {
			with = "with its private key; no Let's Encrypt account goes, so the copy renews it under its own"
		}
		certs = strings.Join(plan.host.Lineages, ", ") + " (" + with + ")"
	}
	dkim := "none"
	if plan.host.DKIMKeys > 0 {
		dkim = fmt.Sprintf("%d private key(s)", plan.host.DKIMKeys)
	}
	uploaded := plan.uploaded
	if uploaded == "" {
		uploaded = "unknown"
	}
	facts := []ApprovalFact{
		{Label: "Goes to the machine whose key fingerprint is", Value: hex.EncodeToString(full[:])[:16]},
		{Label: "Check", Value: "the same fingerprint is on that machine's own admin page. If it is not, decline."},
		{Label: "Its full key (SHA-256)", Value: hex.EncodeToString(full[:])},
		{Label: "Backup chain", Value: plan.chainID},
		{Label: "Newest run of it uploaded", Value: uploaded},
		{Label: "Certificates", Value: certs},
		{Label: "DKIM keys", Value: dkim},
	}
	if plan.withHistory {
		facts = append(facts, ApprovalFact{Label: "Backup history", Value: fmt.Sprintf("the list of this site's %d "+
			"backup chain(s) this machine uploaded, so the copy can restore them after a switch", len(plan.history))})
	}
	return ApprovalStatement{
		Primitive: "copy_export",
		Summary: "Hand this site's backup key, certificate and DKIM keys to a copy of this site on another " +
			"machine, sealed so only that machine can open them.",
		Facts: facts,
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

	p := copyPayload{
		Chains: []copyChain{{ChainID: plan.chainID, DataKey: dataKey, Manifests: []string{plan.sum}}},
		Files:  plan.hostFiles,
	}
	if plan.withHistory {
		p.History = &copyHistory{Profile: string(plan.profile), Chains: plan.history}
	}
	payload, err := json.Marshal(p)
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

	sealed, err := xwing.Seal(gz.Bytes(), plan.targetKEM, CopySealScope)
	if err != nil {
		return nil, refusedf("copy_export: %v", err)
	}

	issued := time.Now().UTC()
	wire, err := signCopyBundle(copyBundleBody{
		Format:       CopyExportDomain,
		SourceNodeID: nodeID,
		SourceKey:    base64.StdEncoding.EncodeToString(key.PublicKey()),
		TargetKey:    base64.StdEncoding.EncodeToString(plan.target),
		Seal:         CopySealXWing,
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
		"history_chains":     len(plan.history),
		"issued":             issued.Format(time.RFC3339Nano),
	}, nil
}

// openChainDataKey opens the chain data key from a manifest's envelope with
// this machine's own backup key (BackupEnvelope::build): a version-2
// recipient ("alg": "xwing") with the X-Wing seed in backup_site_key, a
// version-1 one (a libsodium sealed box) with the retired X25519 keypair, or
// with a backup_site_key that is still a keypair on a machine not converged
// since. Each recipient is matched by its fingerprint, never tried blind.
func openChainDataKey(env *ExecEnv, manifest string) (string, error) {
	config := filepath.Join(strings.TrimRight(env.SiteRoot, "/"), "config")
	current, err := readSiteKey(filepath.Join(config, siteKeyFile))
	if err != nil {
		return "", fmt.Errorf("this machine's backup key cannot be read: %v", err)
	}
	defer zero(current)
	retired, _ := readSiteKey(filepath.Join(config, siteKeyRetiredFile))
	defer zero(retired)

	var seed, pair []byte
	for _, k := range [][]byte{current, retired} {
		switch len(k) {
		case xwing.SeedBytes:
			if seed == nil {
				seed = k
			}
		case 64:
			if pair == nil {
				pair = k
			}
		}
	}
	if seed == nil && pair == nil {
		return "", errors.New("this machine's backup key is neither an X-Wing seed nor a keypair")
	}
	var xwFpr, v1Fpr string
	if seed != nil {
		pub, err := xwing.PublicKey(seed)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(pub)
		xwFpr = hex.EncodeToString(sum[:])
	}
	if pair != nil {
		sum := sha256.Sum256(pair[32:])
		v1Fpr = hex.EncodeToString(sum[:])
	}

	body, err := os.ReadFile(manifest)
	if err != nil {
		return "", err
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
		return "", errors.New("the manifest is not a chain manifest")
	}
	for _, r := range m.Envelope.Recipients {
		blob, err := base64.StdEncoding.DecodeString(r.Sealed)
		if err != nil {
			continue
		}
		switch {
		case r.Alg == "xwing" && xwFpr != "" && r.Fingerprint == xwFpr:
			if opened, err := xwing.Open(blob, seed, xwing.ScopeDEK); err == nil {
				return string(opened), nil
			}
		case r.Alg == "" && v1Fpr != "" && r.Fingerprint == v1Fpr:
			var priv, pub [32]byte
			copy(priv[:], pair[:32])
			copy(pub[:], pair[32:])
			opened, ok := box.OpenAnonymous(nil, blob, &pub, &priv)
			zero(priv[:])
			if ok {
				return string(opened), nil
			}
		}
	}
	return "", errors.New("no recipient of the chain's envelope is this machine's key")
}

// readSiteKey reads a site key file's base64 bytes; nil when there is none.
func readSiteKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	zero(raw)
	if err != nil {
		return nil, fmt.Errorf("%s is not base64", filepath.Base(path))
	}
	return key, nil
}

// decodeAgentKey reads a base64 Ed25519 public key.
func decodeAgentKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("is not an agent public key")
	}
	return ed25519.PublicKey(raw), nil
}
