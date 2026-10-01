package primitives

// What a dormant copy keeps in its site's state directory, beside the state
// itself (specs/site_copy.md WP4). Root's directory: nothing the site runs
// can write here, and every record is refused when anything but its owner
// could have.
//
//   - copy_of_key: the source's agent public key, base64. Written by the
//     dormant install (install.sh --copy-of-key) beside copy_of. The one key
//     copy_import trusts a bundle from (Q7).
//   - vouched: the runs this copy may apply, one `<manifest sha256> <chain
//     id>` line each. Written whole by copy_import, read by copy_stage
//     before it downloads and by copy_restore before it applies.
//   - copy_import_issued: the issue time of the newest bundle imported. A
//     bundle issued at or before it is a replay, and refused.
//
// Clearing the state (_site_state.sh) removes all three with copy_of, so a
// promoted copy stops trusting its source's key.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// sha256Hex is a manifest hash as the vouch records it.
var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// base64Key is a 32-byte key in standard base64.
var base64Key = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)

// chainIDPattern is a chain id: it names a workspace, so no separator and no
// dot. The pattern every chain word binds.
var chainIDPattern = regexp.MustCompile(`^chain-[0-9_]+$`)

const (
	copyOfKeyFile    = "copy_of_key"
	copyIssuedFile   = "copy_import_issued"
	copyStateMaxRead = 1 << 20
)

// readTrustedStateFile reads a record from the site's state directory, or
// says why it vouches for nothing. Absent is fs.ErrNotExist, for the caller
// to name.
func readTrustedStateFile(env *ExecEnv, name string) ([]byte, error) {
	path := filepath.Join(siteStateDir(env), name)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%s is writable by other accounts (mode %04o), so it vouches for nothing",
			path, info.Mode().Perm())
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 && st.Uid != 0 {
		return nil, fmt.Errorf("%s is owned by uid %d, not root, so it vouches for nothing", path, st.Uid)
	}
	if info.Size() > copyStateMaxRead {
		return nil, fmt.Errorf("%s is too large to be what it should be", path)
	}
	return os.ReadFile(path)
}

// writeStateFile replaces a record in the site's state directory whole:
// written beside it at mode 0600 and renamed over it, so a reader sees the
// old record or the new one and never half of either.
func writeStateFile(env *ExecEnv, name string, body []byte) error {
	return writeFileAtomic(filepath.Join(siteStateDir(env), name), body, 0o600)
}

// writeFileAtomic writes body to path through a temporary file in the same
// directory, at mode before any byte lands.
func writeFileAtomic(path string, body []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// recordedSourceKey is the source's agent key the dormant install recorded.
func recordedSourceKey(env *ExecEnv) (ed25519.PublicKey, error) {
	raw, err := readTrustedStateFile(env, copyOfKeyFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("this copy has no record of its source's key (%s is absent). The dormant install "+
			"records it from --copy-of-key; without it no export can be trusted",
			filepath.Join(siteStateDir(env), copyOfKeyFile))
	}
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("the recorded source key (%s) is not an agent public key",
			filepath.Join(siteStateDir(env), copyOfKeyFile))
	}
	return ed25519.PublicKey(key), nil
}

// vouchedManifests is every manifest hash the source vouched for under one
// chain id. Empty, with no error, when it vouched for none of that chain.
func vouchedManifests(env *ExecEnv, chainID string) ([]string, error) {
	path := filepath.Join(siteStateDir(env), copyVouchedFile)
	raw, err := readTrustedStateFile(env, copyVouchedFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("this copy has no runs vouched for by its source (%s is absent): "+
			"the vouch is written when the source's signed export is imported (copy_import)", path)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read this copy's vouched runs: %v", err)
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && fields[1] == chainID && sha256Hex.MatchString(fields[0]) {
			out = append(out, fields[0])
		}
	}
	return out, nil
}
