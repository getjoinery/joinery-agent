package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// joinery-agent verify-package DIR: is this directory, as it sits on disk, a
// package our release keys signed, and, on a machine that holds the release
// log's keys, one the public log records? It is the check a machine with no
// PHP (a Docker host) needs for the package fix channel
// (specs/package_fixes_automatic.md WP6): the channel's directory carries
// ACTIVE, WITHDRAWN, CHANNEL and its RELEASE_MANIFEST, signature and
// RELEASE_STATEMENT, and the host script asks this binary before it reads a
// line of ACTIVE.
//
// The rules are PackageSignature::verify()'s for a package whose manifest
// lists its files by bare name (its root is ''), and the verdict names are
// that verifier's, so the two answer alike: the manifest signed by a release
// key this machine trusts (the keys compiled in, or the set a logged release
// recorded in the agent's state directory), every file present listed with
// its hash and every listed file present, and, where the log's keys are held,
// the statement the manifest lists logged and recording the manifest's
// statement subject. The checks are the support bundle's (verifySignedTree,
// verifyStatementRecording). It reads and never writes: no key a statement
// proves is kept, and no trusted set is recorded.

// Verdicts, PackageSignature's.
const (
	pkgSigned           = "signed"
	pkgUnsigned         = "unsigned"
	pkgUnknownKey       = "unknown_key"
	pkgNoKeys           = "no_keys"
	pkgTampered         = "tampered"
	pkgExtraFile        = "extra_file"
	pkgMissingFile      = "missing_file"
	pkgUnreadable       = "unreadable"
	pkgUnlogged         = "unlogged"
	pkgUnauthorizedKeys = "unauthorized_keys"
)

// packageVerdict is one verdict and the reason for it, in words.
type packageVerdict struct {
	name string
	why  string
}

func (v packageVerdict) String() string { return "verdict: " + v.name + ": " + v.why }

// manifestLine is PackageSignature::parse's line.
var (
	manifestLine     = regexp.MustCompile(`^([0-9a-f]{64})\s+(\S.*)$`)
	manifestLineEnd  = regexp.MustCompile(`\r\n|\r|\n`)
	manifestClimbing = regexp.MustCompile(`(^|/)\.\.($|/)`)
)

// parsePackageManifest is PackageSignature::parse: path => sha256, or false
// when a line is not "<sha256>  <path>" or a path reaches outside the package.
func parsePackageManifest(body []byte) (map[string]string, bool) {
	out := map[string]string{}
	for _, line := range manifestLineEnd.Split(string(body), -1) {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		m := manifestLine.FindStringSubmatch(line)
		if m == nil {
			return nil, false
		}
		p := strings.ReplaceAll(m[2], `\`, "/")
		if p[0] == '/' || manifestClimbing.MatchString(p) {
			return nil, false
		}
		out[p] = m[1]
	}
	return out, true
}

// commonRoot is PackageSignature::commonRoot: the longest directory prefix
// every listed path shares, "" when none.
func commonRoot(paths []string) string {
	var common []string
	for i, p := range paths {
		dirs := strings.Split(p, "/")
		dirs = dirs[:len(dirs)-1]
		if i == 0 {
			common = dirs
			continue
		}
		keep := 0
		for keep < len(common) && keep < len(dirs) && common[keep] == dirs[keep] {
			keep++
		}
		common = common[:keep]
		if len(common) == 0 {
			return ""
		}
	}
	return strings.Join(common, "/")
}

// statementLines is PackageSignature::statementLines: path => sha256 of
// every listed RELEASE_STATEMENT, the lines statementSubject leaves out.
func statementLines(body []byte) map[string]string {
	lines := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		if m := manifestLine.FindStringSubmatch(line); m != nil {
			p := strings.ReplaceAll(m[2], `\`, "/")
			if path.Base(p) == releaseStatementName {
				lines[p] = m[1]
			}
		}
	}
	return lines
}

// readPackageStatement is PackageSignature::readStatement: the one statement
// the manifest lists, which must be the file in the package, so every line
// statementSubject leaves out is the statement being verified.
func readPackageStatement(dir string, body []byte) ([]byte, error) {
	lines := statementLines(body)
	if len(lines) == 0 {
		return nil, fmt.Errorf("the package carries no %s", releaseStatementName)
	}
	var first, hash string
	for p, h := range lines {
		if hash != "" && h != hash {
			return nil, fmt.Errorf("the package lists more than one %s, and they differ", releaseStatementName)
		}
		if first == "" || p < first {
			first = p
		}
		hash = h
	}
	f, err := os.Open(filepath.Join(dir, filepath.FromSlash(first)))
	if err != nil {
		return nil, errors.New("the listed statement is not the file in the package")
	}
	defer f.Close()
	doc, err := io.ReadAll(io.LimitReader(f, maxReleaseStatementBytes+1))
	if err != nil || len(doc) > maxReleaseStatementBytes {
		return nil, errors.New("the listed statement is not the file in the package")
	}
	if sum := sha256.Sum256(doc); hex.EncodeToString(sum[:]) != hash {
		return nil, errors.New("the listed statement is not the file in the package")
	}
	return doc, nil
}

// verifyPackageDir judges the package at dir against the keys c holds.
func (c releaseTreeChecks) verifyPackageDir(dir string) packageVerdict {
	dir = strings.TrimRight(dir, "/")
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return packageVerdict{pkgUnreadable, "there is no directory at " + dir + " to verify"}
	}
	manifestPath := filepath.Join(dir, primitivesManifestName)
	signaturePath := filepath.Join(dir, primitivesSignatureName)
	if !isRegular(manifestPath) || !isRegular(signaturePath) {
		return packageVerdict{pkgUnsigned, "the package carries no " + primitivesManifestName + " and signature, so nobody we know built it"}
	}

	held := releaseLogKeys{}
	if c.held != nil {
		held = c.held()
	}
	trust := heldReleaseTrust(c.keyDir, c.releaseKeys, held.statement)
	keys := trust.releasePublicKeys()
	if len(keys) == 0 {
		return packageVerdict{pkgNoKeys, "this machine trusts no release key: this build carries none, and no release recorded a set in " + c.keyDir}
	}

	body, err := os.ReadFile(manifestPath)
	sigRaw, serr := os.ReadFile(signaturePath)
	signature, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil || serr != nil || derr != nil || len(body) == 0 || len(signature) != 64 {
		return packageVerdict{pkgUnreadable, "the manifest or its signature is not in the format the publisher writes"}
	}
	listed, ok := parsePackageManifest(body)
	if !ok {
		return packageVerdict{pkgUnreadable, `the manifest has a line that is not "<sha256>  <path>"`}
	}
	var paths []string
	for p := range listed {
		paths = append(paths, p)
	}
	if root := commonRoot(paths); root != "" {
		return packageVerdict{pkgUnreadable, "the manifest describes " + root + "/; this check reads a package whose manifest lists its files by their names in " + dir}
	}

	// The statement first, as the bundle's: its key chain may carry the
	// release keys the manifest is signed with (specs/release_key_rotation.md
	// R2). A statement that does not hold is the verdict only once the
	// signature and the files are known good, as PackageSignature has it.
	var logged *releaseLogVerdict
	var unlogged error
	if held.holds() {
		doc, err := readPackageStatement(dir, body)
		if err == nil {
			subject := statementSubject(body)
			logged, err = verifyStatementRecording(doc, held, trust, func(p statementPayload) error {
				if !p.recordsValue(subject) {
					return errors.New("the logged statement does not record this package")
				}
				return nil
			})
		}
		if err != nil {
			unlogged = err
		} else {
			keys = logged.releaseKeys()
		}
	}

	if signerOf(keys, body, signature) == nil {
		return packageVerdict{pkgUnknownKey, fmt.Sprintf("the manifest is signed, but not by any of the %d key(s) this machine trusts%s",
			len(keys), retiredNote(c.keyDir, body, signature))}
	}
	if link := firstSymlink(dir); link != "" {
		return packageVerdict{pkgExtraFile, "a symlink is present at " + link + ", which no manifest lists"}
	}
	checked, signer, err := verifySignedTree(dir, keys, "the package", nil)
	if err != nil {
		var fault *treeFault
		if errors.As(err, &fault) {
			return packageVerdict{fault.kind, err.Error()}
		}
		return packageVerdict{pkgUnreadable, err.Error()}
	}
	if !bytes.Equal(checked, body) {
		return packageVerdict{pkgUnreadable, "the manifest changed while it was being checked"}
	}
	signed := fmt.Sprintf("%d file(s) verified", len(listed))
	if unlogged != nil {
		return packageVerdict{pkgUnlogged, "signed by a key this machine trusts, but not shown to be in the public log: " + unlogged.Error()}
	}
	if logged != nil {
		if _, err := logged.settle(signer); err != nil {
			return packageVerdict{pkgUnauthorizedKeys, err.Error()}
		}
		signed += fmt.Sprintf(", logged publicly at %s index %d", logged.origin, logged.index)
	}
	return packageVerdict{pkgSigned, signed}
}

func isRegular(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.Mode().IsRegular()
}

// firstSymlink is the first symlink under dir, relative to it, or "": a link
// is not a file anybody signed, whatever it points at.
func firstSymlink(dir string) string {
	found := ""
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			found, _ = filepath.Rel(dir, p)
			return filepath.SkipAll
		}
		return nil
	})
	return filepath.ToSlash(found)
}

// cliVerifyPackage is joinery-agent verify-package DIR: one verdict line,
// exit 0 only for signed.
func cliVerifyPackage(args []string) int {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		return cliError("usage: joinery-agent verify-package DIR")
	}
	checks := releaseTreeChecks{
		releaseKeys: bakedReleaseKeys(),
		keyDir:      agentStateDir(),
		held:        func() releaseLogKeys { return heldReleaseLogKeys(bakedReleaseLogKeys(), agentStateDir()) },
	}
	v := checks.verifyPackageDir(args[0])
	fmt.Println(v.String())
	if v.name != pkgSigned {
		return 1
	}
	return 0
}
