package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"joinery-agent/primitives"
)

// Node posture: the agent takes work from its control plane over an outbound
// HTTPS connection, authenticated by a per-node credential it generated itself.
//
// The credential is an Ed25519 keypair. The agent keeps the private half,
// root-owned and never sent anywhere; the plane is given the public half at
// pairing and stores only that. So the plane holds nothing that authenticates
// as the node — not a hash of something it once saw, but a verifier it could
// never have used in the first place. A bearer token would have satisfied the
// words ("the plane stores only a verifier") while crossing the plane on every
// single poll, through any TLS-terminating proxy and into any request log.
//
// Enrollment shares no secret at all (Phase 1.5, decision A6): the join is
// node-initiated — this agent generates the keypair when the local admin names
// a management node, sends only the public half, and a human over there
// approves the request after comparing key fingerprints across the two admin
// panels. Nothing that could enroll anyone ever exists outside this machine.

const (
	// identityFileName holds the node's own credential. Root-owned 0600: only
	// the root agent ever reads it. (The env file beside it is 0640 because
	// other tooling reads that one; nothing else reads this.)
	identityFileName = "node_identity.json"

	// agentConfigDir is the root-owned directory the installer already creates.
	agentConfigDir = "/etc/joinery-agent"
)

// NodeIdentity is this node's proof of who it is, and the one plane it answers.
type NodeIdentity struct {
	PlaneURL   string `json:"plane_url"`
	NodeID     int64  `json:"node_id"`
	NodeSlug   string `json:"node_slug"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
	PairedTime string `json:"paired_time"`
	// PollSeconds is what the plane suggested at pairing. Stored so a re-read
	// of this file reproduces the same cadence; ALWAYS passed through
	// clampPollInterval before it is used, because it came from the wire.
	PollSeconds int  `json:"poll_seconds,omitempty"`
	TLSInsecure bool `json:"tls_insecure,omitempty"`

	private ed25519.PrivateKey
}

// IdentityPath is where the identity file lives, overridable for tests.
func IdentityPath() string {
	if v := os.Getenv("AGENT_IDENTITY_PATH"); v != "" {
		return v
	}
	return filepath.Join(agentConfigDir, identityFileName)
}

// PendingIdentityPath is where take_node_id stages this machine's identity
// under its source's node id, beside the live one, until the management node
// confirms the swap (promoteStagedIdentity).
func PendingIdentityPath() string {
	return IdentityPath() + ".pending"
}

// promoteStagedIdentity replaces the live identity with the staged one, after
// checking it is the id the word staged and still this machine's key. Any
// mismatch deletes the staged file and keeps the live identity.
func promoteStagedIdentity(live *NodeIdentity, nodeID int64) error {
	pending := PendingIdentityPath()
	staged, err := LoadIdentity(pending)
	if err != nil || staged == nil {
		_ = os.Remove(pending)
		return fmt.Errorf("the staged identity cannot be read (%v)", err)
	}
	if staged.NodeID != nodeID || staged.PublicKey != live.PublicKey || staged.PrivateKey != live.PrivateKey {
		_ = os.Remove(pending)
		return fmt.Errorf("the staged identity is not this machine's key under node %d", nodeID)
	}
	return os.Rename(pending, IdentityPath())
}

// LoadIdentity reads the node identity, or returns nil when this agent has
// never paired (which is the normal state of a control-plane-only agent).
func LoadIdentity(path string) (*NodeIdentity, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// The private key is in this file. A file anything but root could read is
	// not a credential store; refuse rather than carry on with a leaked key.
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("identity file %s is readable or writable beyond its owner (mode %04o) — "+
			"it holds this node's private key; fix with: chmod 600 %s", path, perm, path)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 0 && os.Geteuid() == 0 {
		return nil, fmt.Errorf("identity file %s is owned by uid %d, not root", path, st.Uid)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var id NodeIdentity
	if err := json.Unmarshal(raw, &id); err != nil {
		return nil, fmt.Errorf("identity file %s is not valid JSON: %w", path, err)
	}
	if err := id.hydrate(); err != nil {
		return nil, fmt.Errorf("identity file %s has an unusable private key", path)
	}
	if id.NodeID <= 0 || id.PlaneURL == "" {
		return nil, fmt.Errorf("identity file %s names no node or no plane", path)
	}
	return &id, nil
}

// hydrate decodes the stored private key into the signing key this identity
// actually uses. Every path that produces a NodeIdentity must call it — the one
// that was freshly paired as much as the one that was read back from disk,
// because an identity that cannot sign is not an identity.
func (id *NodeIdentity) hydrate() error {
	key, err := base64.StdEncoding.DecodeString(id.PrivateKey)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("private key is not a usable Ed25519 private key")
	}
	id.private = ed25519.PrivateKey(key)
	return nil
}

// Save writes the identity atomically at 0600.
func (id *NodeIdentity) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// Sign produces the signature the plane verifies against the public half it was
// given at pairing. The signed message is a fixed, newline-joined field list —
// no key=value soup, nothing optional, nothing order-dependent on a map — so
// two different requests cannot produce the same bytes to sign.
func (id *NodeIdentity) Sign(method, path, timestamp, nonce, bodySha256 string) string {
	message := SigningMessage(method, path, id.NodeID, timestamp, nonce, bodySha256)
	return base64.StdEncoding.EncodeToString(ed25519.Sign(id.private, []byte(message)))
}

// nodeKey lends this identity to the primitives as a primitives.NodeKey: the
// public half, a signature under another domain, and opening a seal. The
// private key never leaves this file's types.
type nodeKey struct{ id *NodeIdentity }

func (k nodeKey) PublicKey() ed25519.PublicKey {
	return k.id.private.Public().(ed25519.PublicKey)
}

// SignDomain signs a message that begins with its own domain and a newline,
// and refuses the request domain. A request signature's message begins
// "joinery-agent-v1\n", so a message that must begin with another domain's
// name and a newline can never be one.
func (k nodeKey) SignDomain(domain string, message []byte) ([]byte, error) {
	if domain == "" || domain == requestSigningDomain || strings.ContainsAny(domain, "\n\r") {
		return nil, fmt.Errorf("this agent does not sign under the domain %q", domain)
	}
	if !strings.HasPrefix(string(message), domain+"\n") {
		return nil, fmt.Errorf("a message signed under %q must begin with it", domain)
	}
	return ed25519.Sign(k.id.private, message), nil
}

func (k nodeKey) OpenSealed(blob []byte) ([]byte, error) {
	return primitives.OpenSealedToAgentKey(k.id.private, blob)
}

// currentNodeKey is this machine's agent key from its identity file right
// now, or an error on a machine that has not joined.
func currentNodeKey() (primitives.NodeKey, error) {
	id, err := LoadIdentity(IdentityPath())
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, fmt.Errorf("this machine has not joined a management node, so it has no agent key")
	}
	return nodeKey{id: id}, nil
}

// requestSigningDomain leads every request signature (SigningMessage).
const requestSigningDomain = "joinery-agent-v1"

// SigningMessage builds the canonical bytes both sides sign and verify. Any
// change here is a wire break, which is why the version string leads it.
func SigningMessage(method, path string, nodeID int64, timestamp, nonce, bodySha256 string) string {
	return strings.Join([]string{
		requestSigningDomain,
		strings.ToUpper(method),
		path,
		fmt.Sprintf("%d", nodeID),
		timestamp,
		nonce,
		bodySha256,
	}, "\n")
}

// newNonce returns 16 random bytes, base64. Signed but not stored by the plane
// in v1: a replayed claim re-claims this node's own job, and a replayed result
// lands on a job that is no longer running and is refused by the status guard.
// Both are no-ops, and the claim timeout covers the wedge a lost claim would
// otherwise leave.
func newNonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// GenerateIdentityKeys mints this node's credential. The private half is
// generated here and never leaves this machine.
func GenerateIdentityKeys() (pub, priv string, err error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(publicKey),
		base64.StdEncoding.EncodeToString(privateKey), nil
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}
