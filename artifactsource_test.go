package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A machine with no site tree has no directory a release delivers to, so it
// asks its management node for the same bytes. What must not change in the
// asking is the verification: the key is compiled into this binary, the plane
// does not hold the release key, and a plane that serves a binary it made
// itself is refused by a check that never leaves the machine.
//
// These tests exercise that over a real HTTP round trip rather than by calling
// loadAndVerify directly, because the thing worth proving is that a hostile
// plane on the far end of a socket cannot get a binary installed.

// planeArtifact is a fake control plane serving the artifact endpoint.
type planeArtifact struct {
	manifest []byte
	binaryGz []byte
	bundleGz []byte

	// requests records what the node asked for, so a test can assert the node
	// named an architecture rather than a file.
	requests []map[string]interface{}
}

func (p *planeArtifact) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != pathArtifact {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// The signature headers must be present; the endpoint is signed like
		// claim and result and a test that skipped them would prove less.
		for _, header := range []string{"X-Joinery-Agent-Node", "X-Joinery-Agent-Timestamp",
			"X-Joinery-Agent-Nonce", "X-Joinery-Agent-Signature"} {
			if r.Header.Get(header) == "" {
				t.Errorf("the artifact request carried no %s", header)
			}
		}

		body, _ := io.ReadAll(r.Body)
		var in map[string]interface{}
		json.Unmarshal(body, &in)
		p.requests = append(p.requests, in)

		switch in["kind"] {
		case artifactKindAgentManifest:
			writeEnvelope(w, map[string]interface{}{"manifest": string(p.manifest)})
		case artifactKindAgentBinary:
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(p.binaryGz)
		case artifactKindBundleInfo:
			sum := sha256.Sum256(p.bundleGz)
			writeEnvelope(w, map[string]interface{}{
				"available": len(p.bundleGz) > 0,
				"sha256":    hex.EncodeToString(sum[:]),
				"bytes":     len(p.bundleGz),
			})
		case artifactKindBundleBody:
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(p.bundleGz)
		default:
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"error": "unknown artifact kind"})
		}
	}
}

func writeEnvelope(w http.ResponseWriter, data map[string]interface{}) {
	json.NewEncoder(w).Encode(map[string]interface{}{"api_version": "1.0", "data": data})
}

// installTestIdentity writes a usable node credential where the channel source
// will look for it.
func installTestIdentity(t *testing.T, planeURL string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "node_identity.json")
	t.Setenv("AGENT_IDENTITY_PATH", path)

	pub, priv, err := GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	id := &NodeIdentity{PlaneURL: planeURL, NodeID: 7, NodeSlug: "siteless", PublicKey: pub, PrivateKey: priv}
	if err := id.Save(path); err != nil {
		t.Fatal(err)
	}
}

// signedAgentArtifact builds a gzipped binary and the manifest that describes
// it, signed with key.
func signedAgentArtifact(t *testing.T, priv ed25519.PrivateKey, version string, binary []byte) (manifest, gzipped []byte) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(binary)
	gz.Close()

	sum := sha256.Sum256(binary)
	m, err := json.Marshal(distManifest{
		Version: version,
		Binaries: map[string]distBinary{
			"linux-amd64": {
				File:      "joinery-agent-linux-amd64.gz",
				Sha256:    hex.EncodeToString(sum[:]),
				Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, binary)),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return m, buf.Bytes()
}

// channelUpdater wires an Updater to a fake plane, the way a siteless machine
// is wired: no dist directory at all.
func channelUpdater(t *testing.T, plane *planeArtifact, pub ed25519.PublicKey, running string) (*Updater, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(plane.handler(t))
	t.Cleanup(server.Close)
	installTestIdentity(t, server.URL)

	installDir := t.TempDir()
	install := filepath.Join(installDir, "joinery-agent")
	if err := os.WriteFile(install, []byte("OLD-BINARY"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &Updater{
		source:      newChannelSource(false),
		installPath: install,
		platform:    "linux-amd64",
		pubKey:      pub,
		running:     running,
		warned:      map[string]bool{},
	}, server
}

func TestASitelessMachineUpdatesItselfOverTheChannel(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	manifest, gzipped := signedAgentArtifact(t, priv, "2.0.0", []byte("NEW-BINARY-CONTENTS"))
	plane := &planeArtifact{manifest: manifest, binaryGz: gzipped}

	u, _ := channelUpdater(t, plane, pub, "1.11.0")
	if !u.CheckAndApply() {
		t.Fatal("a correctly signed artifact served over the channel must install")
	}

	installed, err := os.ReadFile(u.installPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(installed) != "NEW-BINARY-CONTENTS" {
		t.Fatalf("the installed binary is %q", installed)
	}
	if _, err := os.Stat(u.bakPath()); err != nil {
		t.Error("the previous binary must be kept as .bak — the rollback path is unchanged by the new delivery route")
	}
}

// The point of the whole design: the plane serves the bytes and cannot vouch
// for them. A plane that signs a binary with its own key is a plane that
// installed nothing.
func TestAPlaneCannotSignItsOwnAgent(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader) // what the agent trusts
	_, planeKey, _ := ed25519.GenerateKey(rand.Reader)

	manifest, gzipped := signedAgentArtifact(t, planeKey, "2.0.0", []byte("HOSTILE"))
	plane := &planeArtifact{manifest: manifest, binaryGz: gzipped}

	u, _ := channelUpdater(t, plane, pub, "1.11.0")
	if u.CheckAndApply() {
		t.Fatal("a binary signed by the plane rather than the publisher must be refused")
	}
	installed, _ := os.ReadFile(u.installPath)
	if string(installed) != "OLD-BINARY" {
		t.Fatal("the running binary was replaced by something that did not verify")
	}
	if _, state := u.HeartbeatInfo(); state != updateStateVerifyFailed {
		t.Errorf("update state is %q, want %q", state, updateStateVerifyFailed)
	}
}

// The node names an ARCHITECTURE, never a file. Anything else and the request
// carries a string the plane has to resolve as a path.
func TestTheNodeNamesAnArchitectureNotAFile(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	manifest, gzipped := signedAgentArtifact(t, priv, "2.0.0", []byte("NEW"))
	plane := &planeArtifact{manifest: manifest, binaryGz: gzipped}

	u, _ := channelUpdater(t, plane, pub, "1.11.0")
	u.CheckAndApply()

	if len(plane.requests) < 2 {
		t.Fatalf("expected a manifest request and a binary request; got %d", len(plane.requests))
	}
	for _, req := range plane.requests {
		for key, value := range req {
			text, ok := value.(string)
			if !ok {
				continue
			}
			if strings.Contains(text, "/") || strings.Contains(text, ".gz") {
				t.Errorf("the node sent %s=%q — an artifact request must carry no file name and no path", key, text)
			}
		}
	}
	binaryReq := plane.requests[len(plane.requests)-1]
	if binaryReq["platform"] != "linux-amd64" {
		t.Errorf("the binary request should name the architecture; got %v", binaryReq["platform"])
	}
}

// A plane that will not stop sending must produce a failed update, never an
// agent that reads a relay out of memory.
func TestAnOversizedArtifactIsAbandoned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	manifest, _ := signedAgentArtifact(t, priv, "2.0.0", []byte("NEW"))

	// A body far past the wire cap. The stream gives up rather than buffering.
	plane := &planeArtifact{manifest: manifest, binaryGz: bytes.Repeat([]byte{0x1f}, 64)}
	u, server := channelUpdater(t, plane, pub, "1.11.0")
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]interface{}
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &in)
		if in["kind"] == artifactKindAgentManifest {
			writeEnvelope(w, map[string]interface{}{"manifest": string(manifest)})
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		chunk := bytes.Repeat([]byte{0}, 1<<20)
		for sent := 0; sent < maxAgentArtifactBytes+(2<<20); sent += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})

	if u.CheckAndApply() {
		t.Fatal("an artifact past the wire cap must not install")
	}
	installed, _ := os.ReadFile(u.installPath)
	if string(installed) != "OLD-BINARY" {
		t.Fatal("the running binary was replaced from an over-long transfer")
	}
}

// A manifest the plane cannot offer is not an error. An unpaired machine, or
// one whose plane has never published, is quiet rather than alarming.
func TestNoArtifactOnOfferIsQuiet(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	plane := &planeArtifact{manifest: nil}
	u, _ := channelUpdater(t, plane, pub, "1.11.0")

	if u.CheckAndApply() {
		t.Fatal("a plane with no artifact must install nothing")
	}
	if bundled, state := u.HeartbeatInfo(); bundled != "" || state != "" {
		t.Errorf("nothing on offer should read as nothing, not as a fault; got %q/%q", bundled, state)
	}
}

// A machine that has a site tree keeps reading its own directory. The nine
// machines in the field must behave in this release exactly as they did in the
// last one, and the source choice is where that is decided.
func TestASiteHavingMachineStillReadsItsOwnDirectory(t *testing.T) {
	source := chooseArtifactSource(&Config{Siteless: false}, "/var/www/html/site/public_html/agent_dist")
	if _, ok := source.(localDirSource); !ok {
		t.Fatalf("a machine with a shipped artifact directory must read it, not fetch; got %T", source)
	}
	if _, ok := chooseArtifactSource(&Config{Siteless: true}, "").(*channelSource); !ok {
		t.Fatal("a machine with no shipped directory must fetch over the channel")
	}
}

// A manifest naming a file that climbs out of the directory is refused before
// anything is opened. The signature would catch the contents; refusing the name
// means a root process never opens the file at all.
func TestALocalManifestCannotNameAPathOutsideItsDirectory(t *testing.T) {
	source := localDirSource{dir: t.TempDir()}
	if _, err := source.Open("linux-amd64", distBinary{File: "../../../etc/shadow"}); err == nil {
		t.Fatal("a manifest naming a path outside the artifact directory must be refused")
	}
}
