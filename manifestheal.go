package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"joinery-agent/primitives"
)

// Getting back the ability to run scripts, without a human on the box.
//
// THE PROBLEM THIS EXISTS FOR. The agent verifies every site script against a
// signed per-file manifest before running it as root. When that MANIFEST is the
// thing that cannot be used — absent, unparseable, or signed by a key this
// binary does not carry — every script primitive is refused at once, and
// apply_update is a script primitive. The upgrade that would deliver a good
// manifest is refused by the check that is failing. Nothing in the agent's
// vocabulary writes a file, so nothing in it can get the node out: the only
// non-script primitives are delete_backup, restart_agent and ssl_probe.
//
// That happened on a live public site for four days and was recovered by hand
// over SSH. Once SSH is retired there is no by-hand.
//
// WHY THIS IS SAFE, AND WHY IT IS NOT A NEW TRUST RELATIONSHIP. The manifest is
// fetched from the plane and then verified against the release key compiled into
// THIS BINARY, exactly as an agent binary is. The plane does not hold the
// release key and cannot sign a manifest; a hostile plane serving a hostile
// manifest costs this machine one wasted fetch and nothing else. The bytes
// travel over a channel; the verdict never leaves the machine.
//
// WHAT IT WILL NOT DO, WHICH MATTERS MORE THAN WHAT IT WILL. It fires only when
// the MANIFEST cannot be used. A file that does not match its signed hash is a
// different event with an opposite remedy: the manifest is doing its job and the
// file on disk is not the file that was published. Delivering a fresh manifest
// there would overwrite the only evidence that a root-run file was modified.
// The structure enforces this rather than remembering it — a hash mismatch is
// raised by SignedTreeVerifier.Verify, and this path is driven by
// ArtifactManifests.Usable, which only ever reports on loading the manifest.
//
// SCOPE: THE CORE RELEASE ONLY. A plugin or theme carries its own manifest, and
// a node whose PLUGIN manifest is bad still has a working apply_update, so it
// can be repaired by an ordinary upgrade. Core is the case with no way out.
// Widening this to other artifacts needs the plane to serve a manifest for an
// arbitrary installed component version; the endpoint already takes the owner,
// so it is a change of caller rather than of contract.
type manifestHealer struct {
	siteRoot string
	verifier *primitives.ArtifactManifests
	pubKey   ed25519.PublicKey
	client   *http.Client

	// How the manifest is obtained. A field so the recovery decision can be
	// tested end to end against every answer a plane can give — including the
	// hostile ones — without a network. nil means fetch over the channel.
	fetcher func(version string) (*manifestPair, error)

	mu sync.Mutex
	// The bytes of the last manifest that failed verification. A verdict holds
	// until what is on offer CHANGES — the same rule the self-update path uses,
	// and for the same reason: re-fetching bytes already refused is noise that
	// hides the one line saying why.
	failedSum string
	// Warnings are said once per distinct situation, not once a minute.
	warned map[string]bool
}

// newManifestHealer returns nil when this machine has nothing to heal: no site
// tree, no release key, or a verifier that is not manifest-backed (a machine
// with no site runs off the support bundle and has no release manifest at all).
func newManifestHealer(cfg *Config, verifier primitives.ManifestVerifier) *manifestHealer {
	if cfg == nil || cfg.SiteRoot == "" {
		return nil
	}
	artifacts, ok := verifier.(*primitives.ArtifactManifests)
	if !ok || artifacts == nil {
		return nil
	}
	if updatePubKeyB64 == "" {
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(updatePubKeyB64)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil
	}
	return &manifestHealer{
		siteRoot: cfg.SiteRoot,
		verifier: artifacts,
		pubKey:   ed25519.PublicKey(key),
		client:   newPlaneClient(cfg.PlaneTLSInsecure),
		warned:   map[string]bool{},
	}
}

// CheckAndHeal looks at whether this node can verify its own core scripts and,
// if it cannot, tries once to fetch a manifest that it can.
//
// Returns true when a manifest was installed. Cheap in the ordinary case: one
// file read and one signature check, no network, and it runs on the same clock
// as the self-update check.
func (h *manifestHealer) CheckAndHeal() bool {
	if h == nil {
		return false
	}

	// Core is owner "". Nil means the manifest loads and verifies, which is the
	// answer almost every minute of this agent's life.
	if err := h.verifier.Usable(""); err == nil {
		h.mu.Lock()
		h.failedSum = ""
		h.warned = map[string]bool{}
		h.mu.Unlock()
		return false
	} else {
		h.warnOnce("unusable-"+err.Error(),
			"script primitives are refused on this node: %v", err)
	}

	version, err := h.installedVersion()
	if err != nil {
		h.warnOnce("version", "manifest recovery: cannot tell which release this site runs: %v", err)
		return false
	}

	get := h.fetcher
	if get == nil {
		get = h.fetch
	}
	pair, err := get(version)
	if err != nil {
		if errors.Is(err, errNoManifestOffered) {
			h.warnOnce("none-"+version,
				"manifest recovery: the management node has no signed manifest for %s — "+
					"this node cannot run script primitives until one is delivered", version)
			return false
		}
		// Transport. Says nothing about the artifact, so it is retried on the
		// next tick and not latched.
		h.warnOnce("fetch-"+version, "manifest recovery: could not fetch the manifest for %s: %v — will retry",
			version, err)
		return false
	}

	sum := sha256.Sum256(pair.manifest)
	digest := hex.EncodeToString(sum[:])

	h.mu.Lock()
	seen := h.failedSum == digest
	h.mu.Unlock()
	if seen {
		return false
	}

	if !ed25519.Verify(h.pubKey, pair.manifest, pair.signature) {
		h.mu.Lock()
		h.failedSum = digest
		h.mu.Unlock()
		log.Printf("=== Manifest recovery === REFUSED the manifest offered for %s", version)
		log.Printf("  It does not verify against this agent's compiled-in release key.")
		log.Printf("  Not retrying until what is offered changes.")
		return false
	}

	if err := h.install(pair); err != nil {
		h.warnOnce("install-"+digest, "manifest recovery: verified the manifest for %s but could not install it: %v",
			version, err)
		return false
	}

	h.mu.Lock()
	h.failedSum = ""
	h.warned = map[string]bool{}
	h.mu.Unlock()

	log.Printf("=== Manifest recovery === installed the signed release manifest for %s", version)
	if err := h.verifier.Usable(""); err != nil {
		// Installed and still unusable. Worth its own line: it means the tree
		// itself has moved on from any manifest this plane can offer, and no
		// amount of re-fetching will help.
		log.Printf("  Scripts still do not verify: %v", err)
	} else {
		log.Printf("  Script primitives are available again on this node.")
	}
	return true
}

// errNoManifestOffered is the plane saying it has nothing for this version —
// pruned by retention, or published before signed manifests. An ordinary answer.
var errNoManifestOffered = errors.New("no manifest offered")

type manifestPair struct {
	manifest  []byte
	signature []byte
}

// installedVersion reads the release this site believes it is running.
//
// From the site tree, which is exactly the tree whose trustworthiness is in
// question — and that is acceptable, because being wrong here is safe. A wrong
// version yields a manifest whose signature covers a different tree; it fails
// verification and is refused, which is the same outcome as asking for nothing.
// Nothing is executed on the strength of this string, and it never reaches a
// path: the plane resolves it against its own layout.
func (h *manifestHealer) installedVersion() (string, error) {
	raw, err := os.ReadFile(filepath.Join(h.siteRoot, "public_html", "VERSION"))
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(raw))
	if v == "" {
		return "", errors.New("the site carries an empty VERSION")
	}
	if len(v) > 24 {
		return "", errors.New("the site carries an unreadable VERSION")
	}
	for _, r := range v {
		if (r < '0' || r > '9') && r != '.' {
			return "", fmt.Errorf("the site carries an unreadable VERSION (%q)", v)
		}
	}
	return v, nil
}

// fetch asks the plane for the signed manifest of the core release at version.
func (h *manifestHealer) fetch(version string) (*manifestPair, error) {
	id, err := LoadIdentity(IdentityPath())
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, errors.New("this machine is not enrolled with a management node")
	}

	ctx, cancel := context.WithTimeout(context.Background(), remoteHTTPTimeout)
	defer cancel()

	raw, err := signedPlanePostCapped(ctx, h.client, id, pathArtifact,
		releaseManifestRequestBody(id, "", version), maxReleaseManifestBytes)
	if err != nil {
		return nil, err
	}

	var payload struct {
		Available bool   `json:"available"`
		Manifest  string `json:"manifest"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("the management node sent an unreadable manifest answer: %w", err)
	}
	if !payload.Available || payload.Manifest == "" || payload.Signature == "" {
		return nil, errNoManifestOffered
	}

	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("the management node sent an unreadable manifest signature")
	}
	return &manifestPair{manifest: []byte(payload.Manifest), signature: sig}, nil
}

// install writes a verified pair to the site root.
//
// THE DIRECTORY IS HOSTILE, not just the files in it. install.sh runs
// `chown -R www-data:www-data /var/www/`, so on a real node the web user owns
// the site root AND ITS PARENT (getjoinery: /var/www/html is www-data:www-data
// 755). That means a web-layer compromise can rename the site root aside and
// leave a symlink with the same name. Any root process that then resolves the
// site root BY PATH follows that link: the temp file is created inside whatever
// directory it points at, chowned to www-data, and renamed to a fixed name
// there. /etc/logrotate.d/RELEASE_MANIFEST is read by root daily and takes
// postrotate scripts; /etc/apt/apt.conf.d/ takes Pre-Invoke hooks. The attacker
// owns the dropped file and rewrites it afterwards. That is root execution from
// the web layer, out of the code whose entire job is to defend that boundary.
//
// So the site root is resolved ONCE, to a descriptor, and everything afterwards
// is relative to that descriptor:
//
//   - O_NOFOLLOW|O_DIRECTORY refuses outright if the site root is a symlink,
//     rather than quietly resolving it.
//   - openat/fchmod/fchown/renameat all act on the descriptor, so there is no
//     path to re-resolve and therefore no window between checking and acting.
//     Lstat-then-act, which this used to do, is time-of-check/time-of-use
//     against exactly the same swap — it narrows the window instead of removing
//     it.
//   - Ownership comes from fstat of that descriptor, not from any file the web
//     user can create.
//
// Residual, stated rather than papered over: an attacker who can replace an
// INTERMEDIATE component (/var/www/html itself) redirects the open before
// O_NOFOLLOW sees the last one. It buys nothing, and the condition is worth
// writing down so the next reader does not have to re-derive it: the redirected
// path must ALREADY END in a real directory whose last component is this site's
// own name (/etc/logrotate.d/getjoinery, say), because O_NOFOLLOW then requires
// a real directory there. No such directory exists under a root-owned sensitive
// path, and creating one needs the write privilege being attacked; one the
// attacker creates itself lands the file somewhere it already owns, which is
// nothing. A full openat walk from / would only add cover against such a
// directory existing by coincidence.
func (h *manifestHealer) install(pair *manifestPair) error {
	dirfd, err := unix.Open(h.siteRoot,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("site root %s could not be opened as a real directory: %w", h.siteRoot, err)
	}
	defer unix.Close(dirfd)

	var dst unix.Stat_t
	if err := unix.Fstat(dirfd, &dst); err != nil {
		return err
	}
	uid, gid := int(dst.Uid), int(dst.Gid)

	// The signature first, then the manifest. Both orders leave a window in
	// which the pair does not match, and neither removes it — whichever lands
	// first is briefly paired with the other's old contents. It is harmless
	// because of WHEN this runs: only on a node whose manifest is already
	// unusable, so a reader in that window sees the refusal it was already
	// getting, and the next check settles it.
	if err := writeAt(dirfd, "RELEASE_MANIFEST.sig",
		[]byte(base64.StdEncoding.EncodeToString(pair.signature)+"\n"), uid, gid); err != nil {
		return err
	}
	return writeAt(dirfd, "RELEASE_MANIFEST", pair.manifest, uid, gid)
}

// writeAt lands one file inside an already-opened directory, atomically.
//
// The mode of an existing file is preserved — the web user reads these during an
// upgrade and a root-only manifest would trade this failure for a quieter one —
// but only when what is there is a regular file, read through the same
// descriptor so it cannot be swapped between the look and the use.
func writeAt(dirfd int, name string, body []byte, uid, gid int) error {
	mode := uint32(0o644)
	var existing unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if existing.Mode&unix.S_IFMT != unix.S_IFREG {
			return fmt.Errorf("%s is not a regular file — refusing to replace it", name)
		}
		// Permission bits only. Carrying setuid/setgid/sticky off a file the
		// web user may have created would give a manifest a bit it has no use
		// for; harmless today because Fchown then sets the owner to the
		// directory's, but there is no reason to propagate it.
		mode = existing.Mode & 0o777
	}

	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := "." + name + "-" + hex.EncodeToString(suffix)

	fd, err := unix.Openat(dirfd, tmp,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tmp)
	committed := false
	defer func() {
		f.Close()
		if !committed {
			unix.Unlinkat(dirfd, tmp, 0)
		}
	}()

	if _, err := f.Write(body); err != nil {
		return err
	}
	// Through the descriptor, never by name: openat with a mode is subject to
	// umask, and a chmod by path is one more thing to redirect.
	if err := unix.Fchmod(fd, mode); err != nil {
		return err
	}
	if uid >= 0 && gid >= 0 {
		if err := unix.Fchown(fd, uid, gid); err != nil {
			return err
		}
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := unix.Renameat(dirfd, tmp, dirfd, name); err != nil {
		return err
	}
	committed = true
	return nil
}

func (h *manifestHealer) warnOnce(key, format string, args ...interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.warned[key] {
		return
	}
	h.warned[key] = true
	log.Printf(format, args...)
}

// maxReleaseManifestBytes bounds the one plane answer that is larger than a job.
//
// NOT the same number as the plane's ReleaseManifestSource::MAX_MANIFEST_BYTES,
// on purpose. That one bounds the RAW manifest; this one bounds the whole JSON
// envelope carrying it — the escaping, the signature and the available/owner/
// version fields ride along, so an equal number here would refuse a manifest the
// plane was willing to serve. The headroom covers that. (Academic at the real
// size: 0.8.370's manifest is 186,343 bytes.)
const maxReleaseManifestBytes = 12 << 20

// healCheckInterval is deliberately slower than the update check. A node in this
// state is broken until somebody publishes something; asking every minute would
// not make that happen sooner.
const healCheckInterval = 10 * time.Minute
