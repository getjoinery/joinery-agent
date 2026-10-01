package primitives

// copy_import: take in the source's export on a dormant copy
// (specs/site_copy.md WP4, Q6). It checks the bundle copy_export made on the
// source, opens it with this machine's agent key, and writes what the other
// copy words read:
//
//   - each chain's data key, as chain.key in that chain's workspace, where
//     copy_restore hands it to restore_chain.sh;
//   - the vouch: every manifest hash the source vouched for, written whole to
//     this site's state directory, read by copy_stage and copy_restore;
//   - the host bundle (copy_host.go): the certificate, its account, DNS-01
//     credentials and DKIM keys, in this machine's own directories.
//
// THE CHECKS, all before anything is written, in the order that gives the
// most useful refusal first:
//
//   - this site is a dormant copy (quiet copy): a live site never takes one;
//   - the signature is the source's, by the one key the dormant install
//     recorded (Q7), and the bundle names the source this machine is a copy of;
//   - the bundle is sealed to THIS machine's key;
//   - it has not expired, and it was issued after the newest bundle this
//     machine has imported (copy_import_issued): a replay is refused;
//   - the seal opens with this machine's key, and what is inside is a chain
//     list and host files that stay inside their own directories.
//
// The high-water mark is raised last, once everything is written, so a
// bundle that failed half way can be imported again.
//
// ClassOperate, and no approval. The owner approved at the source, where the
// secrets leave; here they arrive on a machine that holds nothing of anyone's
// yet. Re-importing is the refresh: the vouch is replaced whole, and the
// files are rewritten.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Deliver a bundle the source made for this copy, late or again: an
// expired or replayed one is refused, and an older one than the newest
// imported is refused the same way. Deliver none: the copy stays as it was.
//
// What it cannot do:
//
//   - Forge or alter one: the signature covers everything, and the key it is
//     checked against was recorded by the install the owner ran.
//   - Make this machine take a bundle sealed to another: the target key must
//     be this machine's, and only this machine's key opens the seal.
//   - Write outside the workspace, the state directory, or the certificate and
//     DKIM directories: chain ids are pattern-bound, and every host entry is a
//     root by name and a path that may not climb out of it.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func init() {
	Register(Primitive{
		Name:        "copy_import",
		Class:       ClassOperate,
		Description: "Check and open the source's signed export on a dormant copy, and write its chain keys, vouched runs and certificates.",
		Params: []ParamSpec{
			// The bundle copy_export returned on the source, as it was.
			{Name: "bundle", Type: ParamString, Required: true, MaxLen: copyExportMaxBundle},
		},
		Run:         copyImportRun,
		Quiet:       QuietCopy,
		ParamsBytes: ChainParamsBytes,
	})
}

func copyImportRun(ctx context.Context, env *ExecEnv, params Params) (map[string]interface{}, error) {
	st, err := ReadSiteState(env)
	if err != nil {
		return nil, refusedf("copy_import: %v", err)
	}
	if env == nil || env.SiteRoot == "" || st.Reason != "copy" {
		return nil, refusedf("copy_import runs only on a dormant copy (quiet copy), and this site is not one: " +
			"a live site never takes another machine's secrets")
	}
	if st.CopyOf <= 0 {
		return nil, refusedf("copy_import: this copy does not record which node it is a copy of")
	}

	source, err := recordedSourceKey(env)
	if err != nil {
		return nil, refusedf("copy_import: %v", err)
	}
	body, err := verifyCopyBundle(params.String("bundle"), source)
	if err != nil {
		return nil, refusedf("copy_import refused: %v", err)
	}
	if body.SourceNodeID != st.CopyOf {
		return nil, refusedf("copy_import refused: the bundle is from node %d, and this machine is a copy of node %d",
			body.SourceNodeID, st.CopyOf)
	}

	if env.Key == nil {
		return nil, refusedf("copy_import: this agent cannot reach its own key, so it cannot open an export")
	}
	key, err := env.Key()
	if err != nil {
		return nil, refusedf("copy_import: %v", err)
	}
	own := base64.StdEncoding.EncodeToString(key.PublicKey())
	if subtle.ConstantTimeCompare([]byte(body.TargetKey), []byte(own)) != 1 {
		return nil, refusedf("copy_import refused: the bundle is sealed to another machine's key, not this one's")
	}

	issued, err1 := time.Parse(time.RFC3339Nano, body.Issued)
	expires, err2 := time.Parse(time.RFC3339Nano, body.Expires)
	if err1 != nil || err2 != nil {
		return nil, refusedf("copy_import refused: the bundle's times are not times")
	}
	now := time.Now().UTC()
	if now.After(expires) {
		return nil, refusedf("copy_import refused: the bundle expired at %s. Export again from the source",
			expires.Format(time.RFC3339))
	}
	if issued.After(now.Add(copyExportClockSkew)) {
		return nil, refusedf("copy_import refused: the bundle says it was issued at %s, ahead of this machine's "+
			"clock by more than %s. Check both machines' clocks", issued.Format(time.RFC3339), copyExportClockSkew)
	}
	if last, ok, err := lastImportIssued(env); err != nil {
		return nil, refusedf("copy_import: %v", err)
	} else if ok && !issued.After(last) {
		return nil, refusedf("copy_import refused: this bundle was issued at %s, and this copy has already imported "+
			"one issued at %s. A bundle is taken once, and never an older one after a newer",
			issued.Format(time.RFC3339Nano), last.Format(time.RFC3339Nano))
	}

	sealed, err := base64.StdEncoding.DecodeString(body.Sealed)
	if err != nil {
		return nil, refusedf("copy_import refused: the sealed part is not readable")
	}
	opened, err := key.OpenSealed(sealed)
	if err != nil {
		return nil, refusedf("copy_import refused: %v", err)
	}
	payload, err := readCopyPayload(opened)
	zero(opened)
	if err != nil {
		return nil, refusedf("copy_import refused: %v", err)
	}

	// Everything is checked. Write: the chain keys, the host files, the vouch,
	// and last the high-water mark.
	var vouch strings.Builder
	var chains []string
	for _, c := range payload.Chains {
		work := chainWorkspace(ctx, env, c.ChainID)
		if err := os.MkdirAll(work, 0o700); err != nil {
			return nil, fmt.Errorf("could not make chain %s's workspace: %w", c.ChainID, err)
		}
		_ = os.Chmod(work, 0o700)
		if err := writeFileAtomic(filepath.Join(work, chainKeyFile), []byte(c.DataKey), 0o600); err != nil {
			return nil, fmt.Errorf("could not write chain %s's key: %w", c.ChainID, err)
		}
		for _, m := range c.Manifests {
			fmt.Fprintf(&vouch, "%s %s\n", m, c.ChainID)
		}
		chains = append(chains, c.ChainID)
	}
	notes, err := installHostFiles(payload.Files)
	if err != nil {
		return nil, fmt.Errorf("could not install the certificates and keys: %w", err)
	}
	if err := writeStateFile(env, copyVouchedFile, []byte(vouch.String())); err != nil {
		return nil, fmt.Errorf("could not write the vouched runs: %w", err)
	}
	if err := writeStateFile(env, copyIssuedFile, []byte(issued.UTC().Format(time.RFC3339Nano)+"\n")); err != nil {
		return nil, fmt.Errorf("could not record the bundle as taken: %w", err)
	}

	sort.Strings(chains)
	return map[string]interface{}{
		"chains":     chains,
		"host_files": len(payload.Files),
		"notes":      notes,
		"issued":     issued.UTC().Format(time.RFC3339Nano),
	}, nil
}

// lastImportIssued is the issue time of the newest bundle this copy took.
func lastImportIssued(env *ExecEnv) (time.Time, bool, error) {
	raw, err := readTrustedStateFile(env, copyIssuedFile)
	if errors.Is(err, fs.ErrNotExist) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(raw)))
	if err != nil {
		return time.Time{}, false, fmt.Errorf("the record of the last bundle taken is not a time")
	}
	return t, true, nil
}

// readCopyPayload decompresses and checks what the seal held.
func readCopyPayload(gz []byte) (copyPayload, error) {
	var p copyPayload
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return p, errors.New("the opened bundle is not what an export holds")
	}
	raw, err := io.ReadAll(io.LimitReader(zr, copyExportMaxPayload+1))
	if err != nil || len(raw) > copyExportMaxPayload {
		return p, errors.New("the opened bundle is not what an export holds")
	}
	defer zero(raw)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, errors.New("the opened bundle is not what an export holds")
	}
	if len(p.Chains) == 0 {
		return p, errors.New("the bundle names no chain")
	}
	for _, c := range p.Chains {
		if !chainIDPattern.MatchString(c.ChainID) || len(c.ChainID) > 64 {
			return p, fmt.Errorf("the bundle names %q, which is not a chain id", c.ChainID)
		}
		if c.DataKey == "" || len(c.DataKey) > 1024 || strings.ContainsAny(c.DataKey, "\n\r") {
			return p, fmt.Errorf("the bundle's key for %s is not a chain key", c.ChainID)
		}
		if len(c.Manifests) == 0 {
			return p, fmt.Errorf("the bundle vouches for no run of %s", c.ChainID)
		}
		for _, m := range c.Manifests {
			if !sha256Hex.MatchString(m) {
				return p, fmt.Errorf("the bundle vouches for %q, which is not a manifest hash", m)
			}
		}
	}
	if len(p.Files) > copyHostMaxFiles {
		return p, errors.New("the bundle carries more host files than a copy takes")
	}
	return p, nil
}
