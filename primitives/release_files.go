package primitives

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// The deployment files a platform upgrade replaces BEFORE it deploys anything
// (specs/release_file_repair.md).
//
// utils/upgrade.php copies these five over the live ones first, so that the new
// upgrade logic runs against the new release. A run that then stops short of a
// deploy — a check it fails, a timeout, a reboot — leaves the old release with
// new deployment files in it. They no longer match the installed signed
// manifest, so this agent refuses to run upgrade.php, every apply_update after
// that is refused the same way, and no release can fix it, because the fix
// would be an apply_update.
//
// So the agent, which lives outside the upgrade's process group and survives
// whatever kills it, keeps a copy of these files while they match the manifest
// and puts them back if they stop matching without a release having gone in.
//
// WHAT IT WILL WRITE. Only bytes whose sha256 is the one the installed, signed
// manifest lists for that exact path. A snapshot that was corrupted or planted
// restores nothing; a plane that offers the wrong bytes restores nothing. The
// manifest decides, and it is verified against the key compiled into this binary
// before any hash in it is believed.
//
// WHAT IT WILL NOT WRITE. Any path outside this list, any file while the
// manifest is unusable (that is manifestheal.go's case, with the opposite
// remedy), and anything over a symlink: the site root is web-writable on a real
// node, so every component of the path is opened relative to a descriptor with
// O_NOFOLLOW, as manifestheal.go's install does.
var SelfUpdateFiles = []string{
	"public_html/utils/upgrade.php",
	"public_html/utils/update_database.php",
	"public_html/includes/DatabaseUpdater.php",
	"public_html/includes/DeploymentHelper.php",
	"public_html/includes/PackageSignature.php",
}

// IsSelfUpdateFile reports whether rel is one of the five.
func IsSelfUpdateFile(rel string) bool {
	for _, f := range SelfUpdateFiles {
		if f == rel {
			return true
		}
	}
	return false
}

// releaseFilesDir is where the kept copies live, beside the node's identity:
// root-only, outside the web-writable site tree. A var so tests can point it
// at a temporary directory.
var releaseFilesDir = "/etc/joinery-agent/release-files"

// SetReleaseFilesDirForTests redirects the snapshot directory. Test-only.
func SetReleaseFilesDirForTests(dir string) func() {
	prev := releaseFilesDir
	releaseFilesDir = dir
	return func() { releaseFilesDir = prev }
}

var versionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// maxReleaseFileBytes bounds one file read or written here. The real files are
// around 150 KB; this leaves room and bounds a hostile plane.
const maxReleaseFileBytes = 4 << 20

// ExpectedHash is the sha256 the installed signed manifest lists for a core
// file, or the reason it cannot say. It exists so a restore can check bytes it
// holds in memory rather than a file already on disk (Verify takes a path).
func (a *ArtifactManifests) ExpectedHash(rel string) (string, error) {
	v, err := a.verifierFor(owningArtifact(rel))
	if err != nil {
		return "", err
	}
	want, ok := v.Hashes[rel]
	if !ok {
		return "", &NotInManifestError{Rel: rel}
	}
	return want, nil
}

func relSHA(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// releaseManifest returns the node's core manifest, or why it cannot be used.
func releaseManifest(env *ExecEnv) (*ArtifactManifests, error) {
	if env == nil || env.SiteRoot == "" {
		return nil, errors.New("this machine has no site, so there is no release to keep files for")
	}
	artifacts, ok := env.Manifest.(*ArtifactManifests)
	if !ok || artifacts == nil {
		return nil, errors.New("this agent has no manifest-backed verifier")
	}
	if err := artifacts.Usable(""); err != nil {
		return nil, err
	}
	return artifacts, nil
}

// InstalledVersion is the release the site says it runs: the VERSION file, as a
// strict number, or "" when it is missing or malformed.
func InstalledVersion(env *ExecEnv) string {
	if env == nil || env.WebRoot == "" {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(env.WebRoot, "VERSION"))
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(raw))
	if !versionPattern.MatchString(v) {
		return ""
	}
	return v
}

// readSelfUpdateFile reads one of the five from the site tree, bounded.
func readSelfUpdateFile(env *ExecEnv, rel string) ([]byte, error) {
	f, err := os.Open(filepath.Join(env.SiteRoot, filepath.FromSlash(rel)))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxReleaseFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxReleaseFileBytes {
		return nil, errors.New("file is larger than this agent reads")
	}
	return b, nil
}

// DifferingSelfUpdateFiles names the self-update files that are missing or do
// not match the installed signed manifest. checked is false when the manifest
// could not be used: no claim is made about files then, and the caller reports
// the manifest instead.
func DifferingSelfUpdateFiles(env *ExecEnv) (names []string, checked bool) {
	artifacts, err := releaseManifest(env)
	if err != nil {
		return nil, false
	}
	names = []string{}
	for _, rel := range SelfUpdateFiles {
		want, err := artifacts.ExpectedHash(rel)
		if err != nil {
			continue // a release that does not list it has nothing to compare
		}
		b, err := readSelfUpdateFile(env, rel)
		if err != nil || relSHA(b) != want {
			names = append(names, rel)
		}
	}
	return names, true
}

// ── The kept copies ──

func snapshotFile(rel string) string {
	return filepath.Join(releaseFilesDir, "files", strings.ReplaceAll(rel, "/", "__"))
}

func snapshotVersion() string {
	raw, err := os.ReadFile(filepath.Join(releaseFilesDir, "VERSION"))
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(raw))
	if !versionPattern.MatchString(v) {
		return ""
	}
	return v
}

// writePlain writes a root-only file in the snapshot directory, atomically.
func writePlain(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// TakeReleaseSnapshot keeps a copy of each self-update file that currently
// matches the installed manifest, tagged with the release's VERSION. A file that
// does not match is never kept: a snapshot is only ever of a file the publisher
// signed. A snapshot of another release is dropped first.
func TakeReleaseSnapshot(env *ExecEnv) error {
	artifacts, err := releaseManifest(env)
	if err != nil {
		return err
	}
	version := InstalledVersion(env)
	if version == "" {
		return errors.New("the site's VERSION cannot be read")
	}
	if have := snapshotVersion(); have != "" && have != version {
		_ = os.RemoveAll(releaseFilesDir + "/files")
	}
	kept := 0
	for _, rel := range SelfUpdateFiles {
		want, err := artifacts.ExpectedHash(rel)
		if err != nil {
			continue
		}
		b, err := readSelfUpdateFile(env, rel)
		if err != nil || relSHA(b) != want {
			continue
		}
		if err := writePlain(snapshotFile(rel), b); err != nil {
			return err
		}
		kept++
	}
	if kept == 0 {
		return nil
	}
	return writePlain(filepath.Join(releaseFilesDir, "VERSION"), []byte(version+"\n"))
}

// snapshotBytes returns the kept copy of rel when it exists, belongs to this
// release, and hashes to want. Anything else is "no usable copy".
func snapshotBytes(version, rel, want string) ([]byte, bool) {
	if snapshotVersion() != version {
		return nil, false
	}
	b, err := os.ReadFile(snapshotFile(rel))
	if err != nil || len(b) > maxReleaseFileBytes || relSHA(b) != want {
		return nil, false
	}
	return b, true
}

// RestoreSelfUpdateFiles puts back every self-update file that no longer matches
// the manifest, from the kept copies, when the release has not changed since
// they were taken. Returns the files it restored.
func RestoreSelfUpdateFiles(env *ExecEnv) ([]string, error) {
	artifacts, err := releaseManifest(env)
	if err != nil {
		return nil, err
	}
	version := InstalledVersion(env)
	if version == "" || snapshotVersion() != version {
		return nil, nil // another release is installed; its manifest speaks for its files
	}
	var restored []string
	var firstErr error
	for _, rel := range SelfUpdateFiles {
		want, err := artifacts.ExpectedHash(rel)
		if err != nil {
			continue
		}
		if b, err := readSelfUpdateFile(env, rel); err == nil && relSHA(b) == want {
			continue
		}
		b, ok := snapshotBytes(version, rel, want)
		if !ok {
			continue
		}
		if _, err := WriteReleaseFile(env.SiteRoot, rel, b, want); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", rel, err)
			}
			continue
		}
		restored = append(restored, rel)
	}
	return restored, firstErr
}

// SelfUpdateGuard is what an apply_update leaves behind it: nothing when the
// release went in or the files are untouched, and the signed files back in place
// when the run stopped short.
type SelfUpdateGuard struct{ env *ExecEnv }

// BeginSelfUpdateGuard keeps the copies before the upgrade runs. Best effort:
// a node that cannot keep them still upgrades, and says why in its log.
func BeginSelfUpdateGuard(env *ExecEnv) *SelfUpdateGuard {
	if err := TakeReleaseSnapshot(env); err != nil {
		log.Printf("release files: not kept before the upgrade: %v", err)
	}
	return &SelfUpdateGuard{env: env}
}

// Finish runs after the upgrade ends, however it ended, and also when the agent
// starts, so a run that took the agent down with it is settled too.
func (g *SelfUpdateGuard) Finish() { RecoverSelfUpdateFiles(g.env) }

// RecoverSelfUpdateFiles is the settle step on its own, for the agent's start.
func RecoverSelfUpdateFiles(env *ExecEnv) {
	// An upgrade still running (an orphan of an agent that was restarted) is
	// mid-way through its own work; its files are not ours to touch.
	if env == nil || env.SiteRoot == "" || !lockFree(filepath.Join(env.SiteRoot, "uploads", ".upgrade.lock")) {
		return
	}
	restored, err := RestoreSelfUpdateFiles(env)
	if len(restored) > 0 {
		log.Printf("release files: the upgrade stopped before deploying; put back %s from the copies kept before it ran",
			strings.Join(restored, ", "))
	}
	if err != nil {
		log.Printf("release files: could not put a file back: %v", err)
	}
}

// ── Writing a release file ──

// WriteReleaseFile replaces one self-update file with body, after checking that
// body hashes to want. It returns the bytes it replaced (nil if there were
// none), and keeps them under releaseFilesDir/replaced so the evidence of a
// modified file survives the repair.
//
// Every directory is opened relative to the one before it with O_NOFOLLOW, the
// file is written beside its final name and renamed over it, and mode and owner
// of the file replaced are kept (the web user reads these during an upgrade).
func WriteReleaseFile(siteRoot, rel string, body []byte, want string) ([]byte, error) {
	if !IsSelfUpdateFile(rel) {
		return nil, fmt.Errorf("%s is not a file this agent restores", rel)
	}
	if relSHA(body) != want {
		return nil, errors.New("the bytes offered are not the file the signed manifest lists")
	}
	if len(body) > maxReleaseFileBytes {
		return nil, errors.New("file is larger than this agent writes")
	}

	dirfd, err := unix.Open(siteRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("site root %s could not be opened as a real directory: %w", siteRoot, err)
	}
	parts := strings.Split(rel, "/")
	for _, dir := range parts[:len(parts)-1] {
		next, err := unix.Openat(dirfd, dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(dirfd)
		if err != nil {
			return nil, fmt.Errorf("%s is not a real directory: %w", dir, err)
		}
		dirfd = next
	}
	defer unix.Close(dirfd)
	name := parts[len(parts)-1]

	var dirStat unix.Stat_t
	if err := unix.Fstat(dirfd, &dirStat); err != nil {
		return nil, err
	}
	uid, gid, mode := int(dirStat.Uid), int(dirStat.Gid), uint32(0o644)

	var replaced []byte
	var existing unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if existing.Mode&unix.S_IFMT != unix.S_IFREG {
			return nil, fmt.Errorf("%s is not a regular file — refusing to replace it", rel)
		}
		uid, gid, mode = int(existing.Uid), int(existing.Gid), existing.Mode&0o777
		if fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0); err == nil {
			f := os.NewFile(uintptr(fd), name)
			replaced, _ = io.ReadAll(io.LimitReader(f, maxReleaseFileBytes+1))
			f.Close()
		}
	}

	tmp := "." + name + ".restore"
	_ = unix.Unlinkat(dirfd, tmp, 0)
	fd, err := unix.Openat(dirfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), tmp)
	committed := false
	defer func() {
		f.Close()
		if !committed {
			_ = unix.Unlinkat(dirfd, tmp, 0)
		}
	}()
	if _, err := f.Write(body); err != nil {
		return nil, err
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return nil, err
	}
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}

	// What is about to be replaced is kept first, so a failure to keep it stops
	// the repair rather than losing the evidence.
	if len(replaced) > 0 {
		keep := filepath.Join(releaseFilesDir, "replaced",
			strings.ReplaceAll(rel, "/", "__")+"."+time.Now().UTC().Format("20060102T150405Z"))
		if err := writePlain(keep, replaced); err != nil {
			return nil, fmt.Errorf("could not keep the file being replaced: %w", err)
		}
	}
	if err := unix.Renameat(dirfd, tmp, dirfd, name); err != nil {
		return nil, err
	}
	committed = true
	return replaced, nil
}
