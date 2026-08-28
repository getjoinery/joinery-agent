package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Where the agent gets the bytes of its next binary.
//
// Two implementations, because two kinds of machine keep their artifact in two
// different places, and neither should be made to pretend it is the other:
//
//   - A machine with a Joinery site has the artifact DELIVERED to it. A
//     platform release writes public_html/agent_dist, and the agent reads a
//     directory. Nothing is fetched, nothing is asked of anyone, and a node
//     that can update itself without talking to a soul should keep doing so.
//   - A machine with no site — a relay, a Docker host — never receives a
//     release, so there is no directory to watch. It asks its management node
//     for the same bytes over the channel it already polls.
//
// WHAT DOES NOT CHANGE IS THE VERIFICATION. Both sources hand back an
// io.Reader, and loadAndVerify does exactly what it always did: decompress,
// check the sha256, verify the Ed25519 signature against the key compiled into
// this binary at build time. The plane cannot sign an agent — it does not hold
// the release key — so a hostile plane serving a hostile binary is refused by a
// check that never leaves this machine. This is a new delivery route for bytes
// that were always verified on arrival, not a new trust relationship, and the
// distinction is the whole reason it is safe for a control plane to serve them.
type artifactSource interface {
	// Manifest returns the raw bytes of the dist manifest. Raw, not a decoded
	// object, because CheckAndApply hashes them: a manifest that failed
	// verification is not retried until it CHANGES, and "changed" has to mean
	// the publisher's bytes changed rather than a re-encoding of them did.
	Manifest() ([]byte, error)

	// Open returns a reader over the artifact for one platform. The entry is
	// the manifest's own record of it; a source that addresses artifacts by
	// name uses entry.File, and one that asks a plane for "the binary for this
	// architecture" does not need it.
	Open(platform string, entry distBinary) (io.ReadCloser, error)

	// Describe names the source in a log line, so a refusal says where the
	// bytes it refused came from.
	Describe() string
}

// artifactFileName is what a manifest may call a file. It exists because the
// manifest is not always ours to trust: on the channel it arrives from the
// plane, and a "file" of "../../../etc/shadow" would otherwise become a path
// this root process opens. The signature check downstream would refuse the
// contents, so this is not the only thing standing between a hostile plane and
// an installed binary — but a refusal that never opens the file is better than
// one that opens it first, and the local source gets the same guard for free.
var artifactFileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// agentPlatform is the architecture token this build asks for. Compiled in
// from runtime.GOARCH, never read from the wire.
var agentPlatform = regexp.MustCompile(`^linux-[a-z0-9]{3,12}$`)

// Caps on what this agent will pull down. They bound a hostile plane, which is
// the party on the other end of the channel source: a machine that would sit
// and read for ever is a machine that can be taken off the air by the thing it
// depends on for updates.
const (
	// maxAgentArtifactBytes bounds the compressed artifact on the wire. The
	// real one is a few megabytes.
	maxAgentArtifactBytes = 64 << 20

	// maxAgentBinaryBytes bounds it after decompression, which is the number a
	// gzip bomb attacks. The real one is tens of megabytes.
	maxAgentBinaryBytes = 192 << 20

	// artifactHTTPTimeout is longer than remoteHTTPTimeout because this
	// transfer is megabytes rather than a job envelope, and a relay on a poor
	// link should still finish.
	artifactHTTPTimeout = 10 * time.Minute
)

// ── The local directory: a machine whose release delivered the artifact ──

type localDirSource struct{ dir string }

func (s localDirSource) Manifest() ([]byte, error) {
	return os.ReadFile(filepath.Join(s.dir, "manifest.json"))
}

func (s localDirSource) Open(platform string, entry distBinary) (io.ReadCloser, error) {
	if !artifactFileName.MatchString(entry.File) {
		return nil, fmt.Errorf("manifest names an unusable artifact file")
	}
	return os.Open(filepath.Join(s.dir, entry.File))
}

func (s localDirSource) Describe() string { return s.dir }

// ── The channel: a machine that asks its management node ──

// channelSource fetches from the plane this machine is paired to.
//
// It resolves the identity at each call rather than holding one, for the same
// reason the join watcher exists: a machine can be enrolled after the agent
// started, and an updater that captured "no identity" at boot would never
// notice it had one. Reading a small root-owned file once a minute is not a
// cost worth optimising away.
type channelSource struct {
	client *http.Client
}

func newChannelSource(tlsInsecure bool) *channelSource {
	client := newPlaneClient(tlsInsecure)
	client.Timeout = artifactHTTPTimeout
	return &channelSource{client: client}
}

func (s *channelSource) Describe() string {
	if id, err := LoadIdentity(IdentityPath()); err == nil && id != nil {
		return id.PlaneURL
	}
	return "the management node"
}

func (s *channelSource) Manifest() ([]byte, error) {
	id, err := s.identity()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), remoteHTTPTimeout)
	defer cancel()

	raw, err := signedArtifactEnvelope(ctx, s.client, id, artifactKindAgentManifest, "")
	if err != nil {
		return nil, err
	}
	var payload struct {
		Manifest string `json:"manifest"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("the management node sent an unreadable artifact manifest: %w", err)
	}
	if payload.Manifest == "" {
		// The plane has no agent artifact to offer. Not an error and not a
		// state worth alarming about: it is what a plane that has never
		// published looks like, and CheckAndApply treats an unreadable
		// manifest as "nothing shipped" exactly as it does for a directory
		// that does not exist.
		return nil, os.ErrNotExist
	}
	return []byte(payload.Manifest), nil
}

func (s *channelSource) Open(platform string, entry distBinary) (io.ReadCloser, error) {
	id, err := s.identity()
	if err != nil {
		return nil, err
	}
	if !agentPlatform.MatchString(platform) {
		return nil, fmt.Errorf("refusing to ask for an artifact for %q", platform)
	}
	// The node names an ARCHITECTURE, never a file. The plane resolves that to
	// whatever its own manifest says, so nothing this agent sends can be read
	// over there as a path — the same discipline delete_backup follows in the
	// other direction.
	ctx, cancel := context.WithTimeout(context.Background(), artifactHTTPTimeout)
	defer cancel()
	return signedArtifactStream(ctx, s.client, id, artifactKindAgentBinary, platform, maxAgentArtifactBytes)
}

func (s *channelSource) identity() (*NodeIdentity, error) {
	id, err := LoadIdentity(IdentityPath())
	if err != nil {
		return nil, err
	}
	if id == nil {
		// Not paired. Same shape as "no manifest here": there is nothing to
		// fetch and nothing has gone wrong.
		return nil, os.ErrNotExist
	}
	return id, nil
}

// chooseArtifactSource decides where this machine's next binary comes from.
//
// A site tree wins whenever there is one, and that ordering is deliberate: a
// node that already receives the artifact through its own upgrade should keep
// updating without a network round trip to anybody, and the nine machines in
// the field must behave in this release exactly as they did in the last one.
// The channel is what a machine falls back to when nothing delivers to it.
func chooseArtifactSource(cfg *Config, distDir string) artifactSource {
	if distDir != "" {
		return localDirSource{dir: distDir}
	}
	if cfg == nil {
		return nil
	}
	return newChannelSource(cfg.PlaneTLSInsecure)
}
