package primitives

// The cryptography of a site copy's export (specs/site_copy.md WP4).
//
// The source S hands its copy T the secrets T cannot make for itself: each
// chain's data key, the certificate and its account, the DKIM keys. They
// travel through the management node, which the design assumes may be
// compromised, so two things hold whatever it does:
//
//   - ONLY T CAN READ THE BUNDLE. It is sealed to T's agent key: the key the
//     owner approved T's join by, and the fingerprint the export approval on
//     S names (Q8). S seals to exactly the key the owner saw; a management
//     node that substituted its own key would have to make the owner approve
//     a fingerprint that is not on T's own page.
//   - ONLY S CAN HAVE WRITTEN IT. It is signed with S's agent key under its
//     own domain prefix, and T trusts the one S key its dormant install
//     recorded (Q7).
//
// THE SEAL is the v2 seal (X-Wing, specs/post_quantum_sealing.md R6) to the
// copy's KEM key, under CopySealScope. The copy's agent key signs that KEM
// key (AgentKEMDomain), so the source seals only to a key the approved
// identity vouches for.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"joinery-agent/xwing"
)

// CopyExportDomain names everything an export is: its signature prefix, its
// seal's HKDF context, and the format field T checks first.
const CopyExportDomain = "joinery-copy-export-v1"

// The machine's own X-Wing key (specs/post_quantum_sealing.md R6). An Ed25519
// identity has no ML-KEM half, so each agent holds a KEM seed beside its
// identity and SIGNS the public half with the identity key under
// AgentKEMDomain: the message is AgentKEMDomain, a newline, and the base64
// public key. The management node passes the key and signature on; a source
// seals to the key only once the signature verifies against the identity key
// the owner approved, so a management node that substituted its own KEM key
// would need the target's identity key to do it.
const (
	AgentKEMDomain = "joinery-agent-kem-v1"
	// CopySealScope is the v2 seal's scope for an export bundle.
	CopySealScope = CopyExportDomain + ":seal"
	// CopySealXWing marks a bundle sealed to the target's KEM key.
	CopySealXWing = "xwing"
)

// AgentKEMMessage is what the identity key signs for its KEM public key.
func AgentKEMMessage(kemPublicB64 string) []byte {
	return []byte(AgentKEMDomain + "\n" + kemPublicB64)
}

// VerifiedAgentKEM returns the raw KEM public key when sig is the identity
// key's signature over it, and refuses otherwise.
func VerifiedAgentKEM(identity ed25519.PublicKey, kemPublicB64, sigB64 string) ([]byte, error) {
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(kemPublicB64))
	if err != nil || len(pub) != xwing.PublicKeyBytes {
		return nil, errors.New("the copy has reported no post-quantum key of its own yet (its agent reports one from 1.99.0)")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || len(identity) != ed25519.PublicKeySize ||
		!ed25519.Verify(identity, AgentKEMMessage(base64.StdEncoding.EncodeToString(pub)), sig) {
		return nil, errors.New("the copy's post-quantum key is not signed by the agent key its owner approved, so nothing is sealed to it")
	}
	return pub, nil
}

// copyExportLifetime is how long T accepts a bundle after S issued it. An
// export is imported minutes after it is made — at the final copy, inside
// the downtime — so this bounds how long a bundle sitting in a job row on
// the management node stays usable, not how long anyone waits.
const copyExportLifetime = 6 * time.Hour

// copyExportClockSkew is how far ahead of T's clock S's may be. Further than
// this and the bundle's issue time would raise T's high-water mark past
// every honest bundle S makes for the next while.
const copyExportClockSkew = 15 * time.Minute

// copyExportMaxBundle bounds the bundle as it travels: S's job result must
// carry it (the result cap is 256 KiB) and so must T's job params. A copy
// whose certificates and keys do not fit is refused at S, naming the size.
const copyExportMaxBundle = 200 * 1024

// copyExportMaxPayload bounds what an opened bundle may decompress to.
const copyExportMaxPayload = 4 * 1024 * 1024

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// copyExportSigned is the message S signs and T verifies: the domain, a
// newline, then the body's exact bytes. The body travels base64-encoded, so
// what is verified is what was signed, with no JSON re-encoding between.
func copyExportSigned(body []byte) []byte {
	return append([]byte(CopyExportDomain+"\n"), body...)
}

// copyBundle is the bundle on the wire: a body and S's signature over it.
type copyBundle struct {
	Body      string `json:"body"`
	Signature string `json:"signature"`
}

// copyBundleBody is what S signs. Everything T checks before it opens the
// seal is here, in the clear and under the signature.
type copyBundleBody struct {
	Format       string `json:"format"`
	SourceNodeID int64  `json:"source_node_id"`
	SourceKey    string `json:"source_key"`
	TargetKey    string `json:"target_key"`
	Issued       string `json:"issued"`
	Expires      string `json:"expires"`
	Sealed       string `json:"sealed"`
	// Seal is CopySealXWing: the bundle is sealed to the copy's X-Wing key
	// (CopySealScope). A bundle without it is refused.
	Seal string `json:"seal,omitempty"`
}

// copyPayload is what the seal holds, gzipped.
type copyPayload struct {
	Chains []copyChain    `json:"chains"`
	Files  []copyHostFile `json:"files"`
	// History is the site's other backups, as S's upload ledger records
	// them: absent from an export made before it was added.
	History *copyHistory `json:"history,omitempty"`
}

// copyHistoryMax bounds the chains a history lists: far more than a ledger
// of BackupLedger::MAX_ENTRIES lines holds, and CopyStaging::MAX_HISTORY.
const copyHistoryMax = 500

// copyHistory is the newest manifest of each chain S's upload ledger holds,
// in the profile the export names. T records them in its own ledger, marked
// handed over (CopyStaging), so after the switch the site's backups from
// before it restore on T under their own names. Hashes, sizes and times: no
// secret, and nothing T can apply as a copy.
type copyHistory struct {
	Profile string             `json:"profile"`
	Chains  []copyHistoryChain `json:"chains"`
}

// copyHistoryChain is one chain's newest manifest, as S's ledger has it.
type copyHistoryChain struct {
	ChainID  string `json:"chain_id"`
	SHA256   string `json:"sha256"`
	Bytes    int64  `json:"bytes"`
	Uploaded string `json:"uploaded"` // UTC, the ledger's "2006-01-02 15:04:05"
}

// copyChain is one chain T may apply: its data key, and the manifest
// versions S vouches for.
type copyChain struct {
	ChainID   string   `json:"chain_id"`
	DataKey   string   `json:"data_key"`
	Manifests []string `json:"manifests"`
}

// copyHostFile is one entry of the host bundle (D5): a directory, a file
// with its bytes, or a symlink with its target. Its place is a root by name
// ("letsencrypt" or "dkim", copyHostRoots) and a path inside it, so neither
// side ever reads an absolute path off the other. Owner and group travel by
// name; T maps them to its own ids.
type copyHostFile struct {
	Root  string `json:"root"`
	Path  string `json:"path"`
	Kind  string `json:"kind"` // "dir", "file" or "link"
	Mode  uint32 `json:"mode,omitempty"`
	Owner string `json:"owner,omitempty"`
	Group string `json:"group,omitempty"`
	Data  string `json:"data,omitempty"`
	Link  string `json:"link,omitempty"`
}

// signCopyBundle builds the wire bundle from a body, signing with sign.
func signCopyBundle(body copyBundleBody, sign func([]byte) ([]byte, error)) (string, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	sig, err := sign(copyExportSigned(raw))
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

// verifyCopyBundle checks the signature against the one S key T trusts and
// returns the body. Nothing in the body is read before this passes.
func verifyCopyBundle(wire string, source ed25519.PublicKey) (copyBundleBody, error) {
	var b copyBundle
	var body copyBundleBody
	dec := json.NewDecoder(bytes.NewReader([]byte(wire)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return body, errors.New("the bundle is not an export bundle")
	}
	raw, err1 := base64.StdEncoding.DecodeString(b.Body)
	sig, err2 := base64.StdEncoding.DecodeString(b.Signature)
	if err1 != nil || err2 != nil || len(sig) != ed25519.SignatureSize {
		return body, errors.New("the bundle is not an export bundle")
	}
	if !ed25519.Verify(source, copyExportSigned(raw), sig) {
		return body, errors.New("the bundle's signature is not the source's: it was made by another key, or changed on the way")
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return body, errors.New("the signed body is not an export body")
	}
	if body.Format != CopyExportDomain {
		return body, fmt.Errorf("the bundle is in format %q, and this agent reads %q", body.Format, CopyExportDomain)
	}
	return body, nil
}
