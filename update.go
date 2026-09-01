package main

import (
	"errors"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// updatePubKeyB64 is the Ed25519 public key (base64, 32 raw bytes) that agent
// binaries must be signed with before the agent will install them. Injected
// at build time:
//
//	go build -ldflags "-X main.updatePubKeyB64=<base64>"
//
// A build without a key never self-updates. The signature requirement is the
// security boundary: the site tree the manifest lives in is writable by the
// web user, and the agent runs as root — installing an unsigned binary from
// the tree would turn a web-layer compromise into root.
var updatePubKeyB64 = ""

// Update states surfaced through the heartbeat row (ahb_update_state).
const (
	updateStateCurrent       = "current"
	updateStatePending       = "update_pending"
	updateStateVerifyFailed  = "verify_failed"
	updateStateFetchFailed   = "fetch_failed"
	updateStateUnsignedBuild = "unsigned_build"
	updateStateNoBinary      = "no_binary"
	updateStateRejected      = "version_rejected"
)

type distManifest struct {
	Version  string                  `json:"version"`
	Binaries map[string]distBinary   `json:"binaries"`
}

type distBinary struct {
	File      string `json:"file"`
	Sha256    string `json:"sha256"`
	Signature string `json:"signature"`
}

// Updater watches the shipped agent_dist directory (delivered by platform
// releases) and replaces the running binary when a newer, correctly signed
// version appears. All checks run between jobs — never mid-job.
type Updater struct {
	// source is where the bytes come from: the shipped directory on a machine
	// a release delivers to, the channel on a machine nothing delivers to.
	// Nil when neither exists, which is a build with no config at all.
	source artifactSource

	// distDir is the shipped directory when there is one, and empty on a
	// machine that fetches. Kept beside the source because one thing besides
	// the binary lives in that directory — the systemd unit — and it is
	// converged from a file rather than fetched.
	distDir     string
	installPath string
	platform    string // e.g. linux-amd64
	pubKey      ed25519.PublicKey
	running     string

	// convergeService installs the shipped systemd unit when it differs from
	// the live one, so Restart=always is in place before the swap-and-exit.
	// Nil-able for tests.
	convergeService func(distDir string)

	mu                sync.Mutex
	bundled           string
	state             string
	failedManifestSum string // backoff: a manifest that failed verification is not retried until it changes
	warned            map[string]bool
}

// NewUpdater builds the production updater. Returns a disabled-but-harmless
// updater (with a logged reason) when the install path or key are unusable.
func NewUpdater(cfg *Config, runningVersion string) *Updater {
	distDir := ""
	if cfg != nil {
		distDir = cfg.AgentDistDir
	}
	u := &Updater{
		source:          chooseArtifactSource(cfg, distDir),
		distDir:         distDir,
		platform:        "linux-" + runtime.GOARCH,
		running:         runningVersion,
		convergeService: convergeSystemdUnit,
		warned:          map[string]bool{},
	}
	if exe, err := os.Executable(); err == nil {
		if resolved, err2 := filepath.EvalSymlinks(exe); err2 == nil {
			u.installPath = resolved
		} else {
			u.installPath = exe
		}
	} else {
		log.Printf("self-update disabled: cannot determine own binary path: %v", err)
	}
	if updatePubKeyB64 != "" {
		key, err := base64.StdEncoding.DecodeString(updatePubKeyB64)
		if err != nil || len(key) != ed25519.PublicKeySize {
			log.Printf("self-update disabled: embedded update public key is malformed")
		} else {
			u.pubKey = ed25519.PublicKey(key)
		}
	}
	return u
}

// HeartbeatInfo returns the bundled version and update state for the
// heartbeat row. Safe to call from the heartbeat goroutine.
func (u *Updater) HeartbeatInfo() (bundled, state string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.bundled, u.state
}

func (u *Updater) setState(bundled, state string) {
	u.mu.Lock()
	u.bundled = bundled
	u.state = state
	u.mu.Unlock()
}

func (u *Updater) warnOnce(key, format string, args ...interface{}) {
	if u.warned[key] {
		return
	}
	u.warned[key] = true
	log.Printf(format, args...)
}

func (u *Updater) bakPath() string      { return u.installPath + ".bak" }
func (u *Updater) rejectedPath() string { return u.installPath + ".rejected" }
func (u *Updater) pendingPath() string  { return u.installPath + ".pending" }

// markPendingConfirmation records, at swap time, that a version is installed but
// has never been seen to work. The next process to start is the one on trial.
func (u *Updater) markPendingConfirmation(version string) {
	if err := os.WriteFile(u.pendingPath(), []byte(version+"\n0\n"), 0644); err != nil {
		log.Printf("self-update: could not record pending confirmation: %v", err)
	}
}

// CheckFailedBoot is the update watchdog, and it runs before anything else can
// go wrong. It answers one question: did the previous start of this binary die
// before proving itself?
//
// The trigger is deliberately not an error class. Classifying init failures as
// binary-attributable or not is a taxonomy nobody can keep correct — the old
// code tried, and a PostgreSQL outage was enough to make it condemn a perfectly
// good release and refuse it until a newer one shipped. Reaching ConfirmHealthy
// is a fact about the binary that no outage can fake, so the watchdog asks about
// that instead. Together with the lazy database and the config retry, which
// removed the environmental ways to exit early, "died before confirming" now
// means the binary, by construction rather than by judgement.
//
// Returns true when it restored the previous binary; the caller exits so the
// supervisor comes back on the known-good one.
func (u *Updater) CheckFailedBoot() bool {
	if u.installPath == "" {
		return false
	}
	data, err := os.ReadFile(u.pendingPath())
	if err != nil {
		return false
	}

	parts := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)
	version := strings.TrimSpace(parts[0])
	attempts := 0
	if len(parts) > 1 {
		attempts, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
	}

	// A marker naming some other version is debris from an older swap that this
	// binary has nothing to do with.
	if version != u.running {
		os.Remove(u.pendingPath())
		return false
	}

	if attempts == 0 {
		// First start on trial. Record the attempt so that if this process dies
		// before ConfirmHealthy, the next start knows to give up on it.
		if err := os.WriteFile(u.pendingPath(), []byte(version+"\n1\n"), 0644); err != nil {
			log.Printf("self-update: could not record boot attempt: %v", err)
		}
		return false
	}

	log.Printf("=== Self-update watchdog === v%s was installed and did not reach a healthy start; rolling back", u.running)
	os.Remove(u.pendingPath())
	return u.RestoreBackupBinary()
}

// ConfirmHealthy is called once the agent has fully initialised (config, DB,
// schema). Reaching it after an update means the new binary works: the
// previous binary is no longer needed, and a rejection marker for our own
// version is stale.
func (u *Updater) ConfirmHealthy() {
	if u.installPath == "" {
		return
	}
	// Clearing the pending marker IS the confirmation: from here the watchdog has
	// nothing to act on, and this version is one the machine has seen work.
	os.Remove(u.pendingPath())
	if err := os.Remove(u.bakPath()); err == nil {
		log.Printf("self-update: confirmed healthy on v%s — removed previous binary backup", u.running)
	}
	if data, err := os.ReadFile(u.rejectedPath()); err == nil && strings.TrimSpace(string(data)) == u.running {
		os.Remove(u.rejectedPath())
	}
}

// RestoreBackupBinary is the boot fallback: called when the agent fails fatal
// initialisation. If a .bak from a recent update exists, the running (new)
// version is recorded as rejected and the previous binary is put back so the
// supervisor restarts into a known-good agent instead of crash-looping.
// Returns true when a restore happened.
func (u *Updater) RestoreBackupBinary() bool {
	if u.installPath == "" {
		return false
	}
	if _, err := os.Stat(u.bakPath()); err != nil {
		return false
	}
	if err := os.WriteFile(u.rejectedPath(), []byte(u.running+"\n"), 0644); err != nil {
		log.Printf("self-update fallback: could not record rejected version: %v", err)
	}
	if err := os.Rename(u.bakPath(), u.installPath); err != nil {
		log.Printf("self-update fallback: could not restore previous binary: %v", err)
		return false
	}
	log.Printf("=== Self-update fallback === v%s failed to initialise; restored previous binary and marked v%s rejected", u.running, u.running)
	return true
}

// CheckAndApply looks at the shipped manifest and installs a new binary when
// one is available and verifiable. Returns true when the binary on disk was
// replaced — the caller should exit cleanly so the supervisor restarts into
// the new version.
func (u *Updater) CheckAndApply() bool {
	if u.installPath == "" || u.source == nil {
		return false
	}

	raw, err := u.source.Manifest()
	if err != nil {
		// Nothing on offer: a release that shipped no artifact, a tree that is
		// not a control plane's, or a machine that fetches and is not paired
		// to anything yet. None of those is an error, and none of them is this
		// agent's problem to solve.
		u.setState("", "")
		return false
	}
	manifestSum := fmt.Sprintf("%x", sha256.Sum256(raw))

	var m distManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		u.setState("", updateStateVerifyFailed)
		u.warnOnce("manifest-"+manifestSum, "self-update: manifest.json is unreadable: %v", err)
		return false
	}

	if m.Version == "" || m.Version == u.running {
		u.setState(m.Version, updateStateCurrent)
		return false
	}

	// A version that failed to boot is never reinstalled; a new release
	// supersedes the rejection.
	if data, err := os.ReadFile(u.rejectedPath()); err == nil {
		rejected := strings.TrimSpace(string(data))
		if rejected == m.Version {
			u.setState(m.Version, updateStateRejected)
			u.warnOnce("rejected-"+m.Version, "self-update: v%s previously failed to initialise here — holding at v%s until a newer release ships", m.Version, u.running)
			return false
		}
		os.Remove(u.rejectedPath())
	}

	if u.pubKey == nil {
		u.setState(m.Version, updateStateUnsignedBuild)
		u.warnOnce("nokey", "self-update: v%s is available but this build carries no update public key — install manually once from a published build", m.Version)
		return false
	}

	u.mu.Lock()
	backoff := u.failedManifestSum == manifestSum
	u.mu.Unlock()
	if backoff {
		u.setState(m.Version, updateStateVerifyFailed)
		return false
	}

	entry, ok := m.Binaries[u.platform]
	if !ok {
		u.setState(m.Version, updateStateNoBinary)
		u.warnOnce("noarch-"+manifestSum, "self-update: manifest v%s has no binary for %s", m.Version, u.platform)
		return false
	}

	binary, err := u.fetchAndVerify(entry)
	if err != nil {
		if !errors.Is(err, errArtifactRefused) {
			// Transport, not verdict. The bytes were not all there — a
			// publish mid-swap, a request that timed out, a plane restarting
			// — and none of that says anything about the artifact. The next
			// check tries again; only a verdict holds until the manifest
			// changes. (The first live 1.16.0 rollout hit exactly this: the
			// fetch landed in the second the publisher was writing the file,
			// and the agent filed 'context canceled' as a bad signature.)
			u.setState(m.Version, updateStateFetchFailed)
			u.warnOnce("fetch-"+manifestSum, "self-update: could not fetch v%s from %s: %v — will retry", m.Version, u.source.Describe(), err)
			return false
		}
		u.mu.Lock()
		u.failedManifestSum = manifestSum
		u.mu.Unlock()
		u.setState(m.Version, updateStateVerifyFailed)
		log.Printf("=== Self-update === REFUSED v%s: %v", m.Version, err)
		log.Printf("  The artifact from %s does not verify against this agent's embedded public key.", u.source.Describe())
		log.Printf("  Not retrying until the manifest changes.")
		return false
	}

	if err := u.install(binary); err != nil {
		u.mu.Lock()
		u.failedManifestSum = manifestSum
		u.mu.Unlock()
		u.setState(m.Version, updateStateVerifyFailed)
		log.Printf("=== Self-update === FAILED installing v%s: %v", m.Version, err)
		return false
	}

	// On trial from here until a process running it reaches ConfirmHealthy. If
	// none ever does, the watchdog on a later start puts the old binary back.
	u.markPendingConfirmation(m.Version)

	if u.convergeService != nil {
		u.convergeService(u.distDir)
	}

	u.setState(m.Version, updateStatePending)
	log.Printf("=== Self-update === installed v%s (was v%s); exiting for supervisor restart", m.Version, u.running)
	return true
}

// errArtifactRefused marks a failure that is the artifact's own fault — a wrong
// checksum, a wrong signature, a size past the ceiling. That verdict holds until
// the manifest changes. Everything on the way to it (opening, reading,
// decompressing) is transport, and transport is retried.
var errArtifactRefused = errors.New("artifact refused")

// fetchAndVerify opens the artifact at whichever source this agent uses and
// hands the bytes to the verification that has never moved.
func (u *Updater) fetchAndVerify(entry distBinary) ([]byte, error) {
	r, err := u.source.Open(u.platform, entry)
	if err != nil {
		return nil, fmt.Errorf("open artifact: %w", err)
	}
	defer r.Close()
	return u.loadAndVerify(entry, r)
}

// loadAndVerify reads the gzipped binary, checks its sha256, and verifies the
// publisher signature over the raw binary bytes.
//
// It takes a READER, and that is the only thing about this function the channel
// changed. The key it verifies against is compiled into this binary, so the
// answer is the same whether the bytes came off a local disk or off a control
// plane — and a plane cannot sign an agent, which is what makes it safe for one
// to serve these bytes at all.
func (u *Updater) loadAndVerify(entry distBinary, r io.Reader) ([]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("artifact is not gzip: %w", err)
	}
	// One byte past the ceiling, so an artifact that is exactly at it is not
	// mistaken for one that overran. A gzip bomb from a hostile plane is the
	// case this exists for: without it, "decompress everything you are sent"
	// is an out-of-memory condition a relay cannot recover from.
	binary, err := io.ReadAll(io.LimitReader(gz, maxAgentBinaryBytes+1))
	if err != nil {
		return nil, fmt.Errorf("decompress artifact: %w", err)
	}
	if len(binary) > maxAgentBinaryBytes {
		return nil, fmt.Errorf("%w: the artifact decompresses to more than this agent's %d-byte limit", errArtifactRefused, maxAgentBinaryBytes)
	}

	sum := sha256.Sum256(binary)
	expected, err := hex.DecodeString(entry.Sha256)
	if err != nil || !bytes.Equal(sum[:], expected) {
		return nil, fmt.Errorf("%w: sha256 mismatch", errArtifactRefused)
	}

	sig, err := base64.StdEncoding.DecodeString(entry.Signature)
	if err != nil || !ed25519.Verify(u.pubKey, binary, sig) {
		return nil, fmt.Errorf("%w: signature verification failed", errArtifactRefused)
	}
	return binary, nil
}

// install writes the verified binary next to the current one, keeps the
// current one as .bak, and renames the new one into place. Rename over the
// live path is atomic and leaves the running process on its old inode — no
// ETXTBSY, no torn binary.
func (u *Updater) install(binary []byte) error {
	dir := filepath.Dir(u.installPath)
	tmp, err := os.CreateTemp(dir, ".joinery-agent-new-*")
	if err != nil {
		return fmt.Errorf("create temp binary: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op after successful rename

	if _, err := tmp.Write(binary); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp binary: %w", err)
	}
	if err := tmp.Chmod(0755); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp binary: %w", err)
	}

	current, err := os.ReadFile(u.installPath)
	if err != nil {
		return fmt.Errorf("read current binary for backup: %w", err)
	}
	if err := os.WriteFile(u.bakPath(), current, 0755); err != nil {
		return fmt.Errorf("write backup binary: %w", err)
	}

	if err := os.Rename(tmpPath, u.installPath); err != nil {
		os.Remove(u.bakPath())
		return fmt.Errorf("rename new binary into place: %w", err)
	}
	return nil
}

// convergeSystemdUnit installs the shipped unit file when it differs from the
// live one, so Restart=always (which self-update's clean exit depends on) is
// in place before the restart. No-op on cron-supervised hosts.
func convergeSystemdUnit(distDir string) {
	const livePath = "/etc/systemd/system/joinery-agent.service"
	if distDir == "" {
		// A machine that fetches its binary has no shipped directory and so no
		// unit to converge from. Its unit was written by the installer at first
		// install and is not re-derived here — inventing a path to read one
		// from is exactly what the siteless posture refuses to do.
		return
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return // cron supervision — the keepalive restarts us regardless of exit code
	}
	if os.Geteuid() != 0 {
		return
	}
	shipped, err := os.ReadFile(filepath.Join(distDir, "joinery-agent.service"))
	if err != nil {
		return
	}
	live, _ := os.ReadFile(livePath)
	if bytes.Equal(bytes.TrimSpace(shipped), bytes.TrimSpace(live)) {
		return
	}
	if err := os.WriteFile(livePath, shipped, 0644); err != nil {
		log.Printf("self-update: could not converge systemd unit: %v", err)
		return
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		log.Printf("self-update: systemctl daemon-reload failed: %v", err)
		return
	}
	log.Printf("self-update: converged systemd unit from shipped copy")
}
