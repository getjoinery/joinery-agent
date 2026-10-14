package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"joinery-agent/primitives"
)

// A release's core archive, fetched and verified for site_install
// (specs/site_container_engine.md D9).
//
// A host with no site of its own installs one only from a tree it can prove:
// the plane streams the published core archive of the version named, and
// before anything in it runs, the tree is checked here the way the support
// bundle is (bundle.go), and more strictly than upgrade.php checks a release:
// the manifest's signature against the release key compiled into this binary,
// every listed file present and matching, and no file the manifest does not
// list but the ones a published core archive carries unlisted (reviewer2 WP5
// R6: PackageSignature::excluded's paths would let a plane add any file under
// config/, vendor/ or a cache segment). Where this machine holds the release
// log's keys, the release's own statement must record that manifest as `core`
// in the public log. The plane serves bytes it cannot sign, so a hostile plane
// earns a refusal, never a run.
//
// The tree is unpacked root-owned under releaseStagingRoot and removed by the
// cleanup the caller is handed; nothing of it outlives the job.

const (
	// maxReleaseArchiveBytes bounds the compressed archive on the wire. The
	// real one is about 50 MB.
	maxReleaseArchiveBytes = 512 << 20

	// maxReleaseUnpackedBytes bounds what those bytes become.
	maxReleaseUnpackedBytes = 2 << 30

	// maxReleaseEntries bounds the file count: the real one is about 2,000.
	maxReleaseEntries = 100000

	// releaseArchiveTimeout bounds the transfer.
	releaseArchiveTimeout = 30 * time.Minute
)

// releaseStagingRoot is where a fetched release is unpacked. A variable so a
// test can point it at a scratch directory.
var releaseStagingRoot = "/var/lib/joinery-agent/release"

// releaseVersionPattern is the only shape a version may take here, as the
// plane's ReleaseManifestSource::valid_version takes it.
var releaseVersionPattern = regexp.MustCompile(`^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$`)

// The files a published core archive carries that its manifest does not list:
// the site's config template, which a release manifest never lists
// (PackageSignature::excluded), and nothing else. agent_release_tree_rule_test
// on the plane reads this line and the newest published core archive, and
// fails when the two differ.
var releaseUnlistedFiles = []string{"config/default_Globalvars_site.php"}

// releaseCoreStatement is where the core release's statement sits in its tree.
const releaseCoreStatement = "public_html/RELEASE_STATEMENT"

func releaseUnlisted(rel string) bool {
	for _, f := range releaseUnlistedFiles {
		if rel == f {
			return true
		}
	}
	return false
}

// statementSubject is PackageSignature::statementSubject: the sha256 of a
// manifest with the lines that list a release statement left out, which is
// what a release statement records for the package.
func statementSubject(body []byte) string {
	line := regexp.MustCompile(`^[0-9a-f]{64}\s+(\S.*)$`)
	var kept []string
	for _, l := range strings.Split(string(body), "\n") {
		if m := line.FindStringSubmatch(l); m != nil && path.Base(strings.ReplaceAll(m[1], `\`, "/")) == "RELEASE_STATEMENT" {
			continue
		}
		kept = append(kept, l)
	}
	sum := sha256.Sum256([]byte(strings.Join(kept, "\n")))
	return hex.EncodeToString(sum[:])
}

// releaseTreeChecks is what verifies a fetched tree: the compiled release key
// and the release-log keys this machine holds.
type releaseTreeChecks struct {
	pubKey ed25519.PublicKey
	held   func() releaseLogKeys
}

// verifyReleaseTree checks an unpacked core release against its own manifest,
// both ways, that it is the version asked for, and, where the log's keys are
// held, that its statement records it.
func (c releaseTreeChecks) verifyReleaseTree(root, version string) error {
	what := "release " + version
	body, err := verifySignedTree(root, c.pubKey, what, releaseUnlisted)
	if err != nil {
		return err
	}
	got, err := os.ReadFile(filepath.Join(root, "public_html", "VERSION"))
	if err != nil || strings.TrimSpace(string(got)) != version {
		return fmt.Errorf("%s's tree says it is version %q", what, strings.TrimSpace(string(got)))
	}
	held := releaseLogKeys{}
	if c.held != nil {
		held = c.held()
	}
	if !held.holds() {
		return nil
	}
	statement, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(releaseCoreStatement)))
	if err != nil {
		return fmt.Errorf("%s carries no release statement, and this machine holds the release log's keys", what)
	}
	if _, err := verifyReleaseStatement(statement, "core", statementSubject(body), held); err != nil {
		return fmt.Errorf("%s is not shown to be in the public log: %v", what, err)
	}
	return nil
}

// releaseFetcher is ExecEnv.FetchRelease: nil where this build carries no
// usable release key, so nothing can be verified and nothing is fetched.
func releaseFetcher(cfg *Config) func(ctx context.Context, version string) (string, primitives.ManifestVerifier, func(), error) {
	key, err := base64.StdEncoding.DecodeString(updatePubKeyB64)
	if cfg == nil || updatePubKeyB64 == "" || err != nil || len(key) != ed25519.PublicKeySize {
		return nil
	}
	checks := releaseTreeChecks{
		pubKey: ed25519.PublicKey(key),
		held:   func() releaseLogKeys { return heldReleaseLogKeys(bakedReleaseLogKeys(), agentStateDir()) },
	}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.PlaneTLSInsecure},
		TLSHandshakeTimeout: 15 * time.Second,
	}}
	return func(ctx context.Context, version string) (string, primitives.ManifestVerifier, func(), error) {
		return fetchRelease(ctx, client, checks, version)
	}
}

func releaseArchiveRequestBody(id *NodeIdentity, version string) []byte {
	body, _ := json.Marshal(map[string]interface{}{
		"node_id": id.NodeID,
		"kind":    artifactKindReleaseArchive,
		"version": version,
	})
	return body
}

// fetchRelease streams the core archive of version from the plane, unpacks it
// into a fresh folder of its own and verifies it. The cleanup removes the
// folder; on any error there is nothing left to clean.
func fetchRelease(ctx context.Context, client *http.Client, checks releaseTreeChecks, version string) (string, primitives.ManifestVerifier, func(), error) {
	if !releaseVersionPattern.MatchString(version) {
		return "", nil, nil, fmt.Errorf("%q is not a release version", version)
	}
	id, err := LoadIdentity(IdentityPath())
	if err != nil {
		return "", nil, nil, err
	}
	if id == nil {
		return "", nil, nil, errors.New("this machine is not enrolled with a management node")
	}
	if err := os.MkdirAll(releaseStagingRoot, 0o700); err != nil {
		return "", nil, nil, fmt.Errorf("cannot create %s: %w", releaseStagingRoot, err)
	}
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", nil, nil, err
	}
	dir := filepath.Join(releaseStagingRoot, version+"."+hex.EncodeToString(suffix[:]))
	cleanup := func() { os.RemoveAll(dir) }

	ctx, cancel := context.WithTimeout(ctx, releaseArchiveTimeout)
	defer cancel()
	req, url, err := newSignedRequest(ctx, id, pathArtifact, releaseArchiveRequestBody(id, version))
	if err != nil {
		return "", nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if _, envErr := readCappedEnvelope(resp, url); envErr != nil {
			return "", nil, nil, envErr
		}
		return "", nil, nil, fmt.Errorf("plane returned HTTP %d for %s", resp.StatusCode, url)
	}
	body := &cappedBody{body: resp.Body, remaining: maxReleaseArchiveBytes + 1, max: maxReleaseArchiveBytes, url: url}
	verifier, err := checks.unpackAndVerify(body, dir, version)
	if err != nil {
		cleanup()
		return "", nil, nil, err
	}
	return dir, verifier, cleanup, nil
}

// unpackAndVerify unpacks an archive into dir and verifies it, handing back a
// verifier over its manifest for the script the caller will run from it.
func (c releaseTreeChecks) unpackAndVerify(r io.Reader, dir, version string) (primitives.ManifestVerifier, error) {
	lim := treeLimits{what: "release " + version, entries: maxReleaseEntries, bytes: maxReleaseUnpackedBytes}
	if err := unpackTree(r, dir, lim); err != nil {
		return nil, err
	}
	if err := c.verifyReleaseTree(dir, version); err != nil {
		return nil, err
	}
	body, _ := os.ReadFile(filepath.Join(dir, primitivesManifestName))
	sigRaw, _ := os.ReadFile(filepath.Join(dir, primitivesSignatureName))
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil {
		return nil, err
	}
	return primitives.NewSignedTreeVerifier(dir, body, signature, c.pubKey)
}

// identityPlaneURL is ExecEnv.PlaneURL: the management node this machine is
// enrolled with, read from its own identity at the moment of use.
func identityPlaneURL() (string, error) {
	id, err := LoadIdentity(IdentityPath())
	if err != nil {
		return "", err
	}
	if id == nil || id.PlaneURL == "" {
		return "", errors.New("this machine is not enrolled with a management node")
	}
	return id.PlaneURL, nil
}
