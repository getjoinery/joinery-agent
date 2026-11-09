package primitives

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Where a restore's chain data key lives.
//
// A chain is staged into {backups}/restore_<chain>/, and backups/ is the site
// web user's folder: the staging scripts run as that user (AsSiteUser), and the
// host converger hands everything under it to that user every minute. So root
// never writes there, and a key root recovered (copy_take_key, copy_import, a
// recovery-key approval) is kept in root's own state for the site instead,
// {siteStateDir}/chain_keys/<chain>.key, which the web user cannot read.
//
// A chain staged with this machine's own site key leaves its key in the
// workspace: the web user can already derive that one from its own key file.
// At restore time root copies it into its own state (adoptWorkspaceKey),
// reading through os.Root on the backups folder so no link leads it outside.

const chainKeysDir = "chain_keys"

// chainKeyMax bounds what is accepted as a chain key file.
const chainKeyMax = 1024

// chainKeyKeep is how long a key outlives its workspace before it is pruned.
const chainKeyKeep = 7 * 24 * time.Hour

func chainKeyPath(env *ExecEnv, chainID string) string {
	return filepath.Join(siteStateDir(env), chainKeysDir, chainID+".key")
}

// adoptedKeyPath is where a site-staged key is copied for a restore. Apart
// from the keys root opened, and taken afresh from the workspace on every
// restore, so a chain staged again with a good key is never held to an
// earlier bad one.
func adoptedKeyPath(env *ExecEnv, chainID string) string {
	return filepath.Join(siteStateDir(env), chainKeysDir, chainID+adoptedSuffix)
}

const adoptedSuffix = ".site.key"

// writeChainKey keeps one chain's key, opened by root, in root's state for
// the site.
func writeChainKey(ctx context.Context, env *ExecEnv, chainID string, key []byte) error {
	return keepChainKey(ctx, env, chainID, key, chainKeyPath(env, chainID))
}

func keepChainKey(ctx context.Context, env *ExecEnv, chainID string, key []byte, path string) error {
	if !chainIDPattern.MatchString(chainID) {
		return fmt.Errorf("%q is not a chain id", chainID)
	}
	if len(key) == 0 || len(key) > chainKeyMax {
		return errors.New("that is not a chain key")
	}
	dir := filepath.Join(siteStateDir(env), chainKeysDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is not a directory only this agent can open, so no key is kept there", dir)
	}
	pruneChainKeys(ctx, env, chainID)
	return writeFileAtomic(path, key, 0o600)
}

// haveChainKey reports whether root holds the chain's key already.
func haveChainKey(env *ExecEnv, chainID string) bool {
	info, err := os.Lstat(chainKeyPath(env, chainID))
	return err == nil && info.Mode().IsRegular()
}

// restoreKeyFile is the key file a restore reads: the key root opened, or
// else the workspace's site-staged key, copied afresh into root's state.
func restoreKeyFile(ctx context.Context, env *ExecEnv, chainID string) (string, error) {
	if haveChainKey(env, chainID) {
		return chainKeyPath(env, chainID), nil
	}
	if err := adoptWorkspaceKey(ctx, env, chainID); err != nil {
		return "", err
	}
	return adoptedKeyPath(env, chainID), nil
}

// adoptWorkspaceKey copies the workspace's chain.key into root's state. The
// file is read through os.Root on the backups folder: a link out of it is an
// error, never a file root reads.
func adoptWorkspaceKey(ctx context.Context, env *ExecEnv, chainID string) error {
	key, err := readWorkspaceKey(ctx, env, chainID)
	if err != nil {
		return err
	}
	defer zero(key)
	return keepChainKey(ctx, env, chainID, key, adoptedKeyPath(env, chainID))
}

func readWorkspaceKey(ctx context.Context, env *ExecEnv, chainID string) ([]byte, error) {
	r, err := openBackupRoot(ctx, env)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	name := chainWorkspacePrefix + chainID + "/" + chainKeyFile
	f, err := r.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > chainKeyMax {
		return nil, fmt.Errorf("%s in the backups folder is not a chain key", name)
	}
	key, err := io.ReadAll(io.LimitReader(f, chainKeyMax+1))
	if err != nil {
		return nil, err
	}
	if len(key) == 0 || len(key) > chainKeyMax {
		return nil, fmt.Errorf("%s in the backups folder is not a chain key", name)
	}
	// Byte for byte: the restore reads the file as the key, newline and all.
	return key, nil
}

// workspaceHasKey reports whether staging left a key in the workspace.
func workspaceHasKey(ctx context.Context, env *ExecEnv, chainID string) bool {
	r, err := openBackupRoot(ctx, env)
	if err != nil {
		return false
	}
	defer r.Close()
	info, err := r.Stat(chainWorkspacePrefix + chainID + "/" + chainKeyFile)
	return err == nil && info.Mode().IsRegular()
}

// openBackupRoot opens the site's backups folder as an os.Root: paths beneath
// it cannot leave it, through a link or "..". The folder itself must be a real
// directory, not a link.
func openBackupRoot(ctx context.Context, env *ExecEnv) (*os.Root, error) {
	base := backupBase(ctx, env)
	info, err := os.Lstat(base)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a real directory (a link or a file)", base)
	}
	return os.OpenRoot(base)
}

// pruneChainKeys removes keys whose workspace has been gone for a week, each
// time a key is kept (so at every restore and every key root opens). A
// copy's key arrives before its chain is downloaded, so a key with no
// workspace yet is not stale until then. keep is never pruned.
func pruneChainKeys(ctx context.Context, env *ExecEnv, keep string) {
	dir := filepath.Join(siteStateDir(env), chainKeysDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	r, err := openBackupRoot(ctx, env)
	if err != nil {
		return
	}
	defer r.Close()
	now := time.Now()
	for _, e := range entries {
		chainID, ok := strings.CutSuffix(e.Name(), adoptedSuffix)
		if !ok {
			chainID, ok = strings.CutSuffix(e.Name(), ".key")
		}
		if !ok || chainID == keep || !chainIDPattern.MatchString(chainID) {
			continue
		}
		if _, err := r.Lstat(chainWorkspacePrefix + chainID); !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		info, err := e.Info()
		if err != nil || now.Sub(info.ModTime()) < chainKeyKeep {
			continue
		}
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
}
