package primitives

// The host bundle of a site copy (specs/site_copy.md D5): what the site needs
// from its machine that no backup carries. The certificate lineage and the
// ACME account it renews under, any DNS-01 credentials, and the DKIM keys.
// S collects it (copy_export) and T installs it (copy_import); both halves
// live here so the shape has one home.
//
// WHAT IS TAKEN, and why only that. v1 copies a site that is alone on its
// machine, so every lineage in certbot's renewal directory is the site's.
// Of each lineage only the CURRENT version travels: the four files live/
// points at, the live/ links themselves, and its renewal file. certbot keeps
// every version it ever issued in archive/, and a years-old site's archive
// would outgrow the bundle while carrying nothing T can use. The account
// directory travels whole (renewal needs it); so do the DNS-01 credential
// files certbot keeps beside it, and the DKIM key tree.
//
// PATHS NEVER CROSS. Each entry names a root ("letsencrypt", "dkim") and a
// path inside it; T resolves both against its own directories, and refuses a
// path that is absolute, climbs out, or a link that points anywhere but its
// own lineage's archive.

import (
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// The machine directories the bundle reads from and writes to. Variables only
// so a test can point them at a fixture; nothing in production sets them.
var (
	CopyLetsEncryptDir = "/etc/letsencrypt"
	CopyDKIMDir        = "/etc/opendkim/keys"
)

// copyHostRoots maps a root's name to its directory on this machine.
func copyHostRoots() map[string]string {
	return map[string]string{"letsencrypt": CopyLetsEncryptDir, "dkim": CopyDKIMDir}
}

// The bounds on what a host bundle may hold. Real ones are a few files of a
// few kilobytes; these are far above that and far below what a job carries.
const (
	copyHostMaxFiles     = 500
	copyHostMaxFileBytes = 64 * 1024
	copyHostMaxBytes     = 1024 * 1024
)

// lineageName is a certbot lineage: the name of its renewal file and of its
// live/ and archive/ directories.
var lineageName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// lineageFiles are the four files certbot's live/ directory links to.
var lineageFiles = []string{"cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"}

// copyHostSummary is what the host bundle holds, for the approval statement
// and the result.
type copyHostSummary struct {
	Lineages []string
	DKIMKeys int
	Files    int
	Bytes    int
}

// hostCollector gathers entries once each, directories before what is in them.
type hostCollector struct {
	entries []copyHostFile
	seen    map[string]bool
	bytes   int
}

func (c *hostCollector) key(root, rel string) string { return root + ":" + rel }

// dir adds rel and every directory above it, up to the root itself (rel ".").
func (c *hostCollector) dir(root, base, rel string) error {
	rel = filepath.Clean(rel)
	if rel != "." {
		if err := c.dir(root, base, filepath.Dir(rel)); err != nil {
			return err
		}
	}
	if c.seen[c.key(root, rel)] {
		return nil
	}
	info, err := os.Lstat(filepath.Join(base, rel))
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", filepath.Join(base, rel))
	}
	c.seen[c.key(root, rel)] = true
	c.entries = append(c.entries, hostEntry(root, rel, "dir", info))
	return nil
}

func (c *hostCollector) file(root, base, rel string) error {
	if c.seen[c.key(root, rel)] {
		return nil
	}
	if err := c.dir(root, base, filepath.Dir(rel)); err != nil {
		return err
	}
	path := filepath.Join(base, rel)
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > copyHostMaxFileBytes {
		return fmt.Errorf("%s is %d bytes, more than a certificate or key file can be", path, info.Size())
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	c.bytes += len(body)
	if c.bytes > copyHostMaxBytes || len(c.entries) >= copyHostMaxFiles {
		return fmt.Errorf("the certificates and keys on this machine are more than a copy carries (%d files, %d bytes)",
			len(c.entries), c.bytes)
	}
	e := hostEntry(root, rel, "file", info)
	e.Data = base64.StdEncoding.EncodeToString(body)
	c.seen[c.key(root, rel)] = true
	c.entries = append(c.entries, e)
	return nil
}

func (c *hostCollector) link(root, base, rel, target string, info os.FileInfo) {
	e := hostEntry(root, rel, "link", info)
	e.Mode = 0
	e.Link = target
	c.seen[c.key(root, rel)] = true
	c.entries = append(c.entries, e)
}

// tree adds every directory and regular file under rel; anything else (a
// link, a socket) is left out, as nothing in these trees should be one.
func (c *hostCollector) tree(root, base, rel string) error {
	return filepath.WalkDir(filepath.Join(base, rel), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		r, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return c.dir(root, base, r)
		case d.Type().IsRegular():
			return c.file(root, base, r)
		}
		return nil
	})
}

func hostEntry(root, rel, kind string, info os.FileInfo) copyHostFile {
	e := copyHostFile{Root: root, Path: filepath.ToSlash(rel), Kind: kind, Mode: uint32(info.Mode().Perm())}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		if u, err := user.LookupId(strconv.FormatUint(uint64(st.Uid), 10)); err == nil {
			e.Owner = u.Username
		}
		if g, err := user.LookupGroupId(strconv.FormatUint(uint64(st.Gid), 10)); err == nil {
			e.Group = g.Name
		}
	}
	return e
}

// collectHostFiles reads this machine's host bundle.
func collectHostFiles() ([]copyHostFile, copyHostSummary, error) {
	c := &hostCollector{seen: map[string]bool{}}
	var sum copyHostSummary

	le := CopyLetsEncryptDir
	if _, err := os.Stat(le); err == nil {
		renewals, _ := filepath.Glob(filepath.Join(le, "renewal", "*.conf"))
		sort.Strings(renewals)
		for _, conf := range renewals {
			name := strings.TrimSuffix(filepath.Base(conf), ".conf")
			if !lineageName.MatchString(name) {
				continue
			}
			if err := c.file("letsencrypt", le, filepath.Join("renewal", name+".conf")); err != nil {
				return nil, sum, err
			}
			if err := collectLineage(c, le, name); err != nil {
				return nil, sum, err
			}
			sum.Lineages = append(sum.Lineages, name)
		}
		if _, err := os.Stat(filepath.Join(le, "accounts")); err == nil {
			if err := c.tree("letsencrypt", le, "accounts"); err != nil {
				return nil, sum, err
			}
		}
		inis, _ := filepath.Glob(filepath.Join(le, "*.ini"))
		sort.Strings(inis)
		for _, ini := range inis {
			if info, err := os.Lstat(ini); err == nil && info.Mode().IsRegular() {
				if err := c.file("letsencrypt", le, filepath.Base(ini)); err != nil {
					return nil, sum, err
				}
			}
		}
	}

	if _, err := os.Stat(CopyDKIMDir); err == nil {
		before := len(c.entries)
		if err := c.tree("dkim", CopyDKIMDir, "."); err != nil {
			return nil, sum, err
		}
		for _, e := range c.entries[before:] {
			if e.Kind == "file" && strings.HasSuffix(e.Path, ".private") {
				sum.DKIMKeys++
			}
		}
	}

	sum.Files = len(c.entries)
	sum.Bytes = c.bytes
	return c.entries, sum, nil
}

// collectLineage adds one lineage's current version: each live/ link, and
// the archive file it points at, which must be in the lineage's own archive.
func collectLineage(c *hostCollector, le, name string) error {
	for _, f := range lineageFiles {
		rel := filepath.Join("live", name, f)
		path := filepath.Join(le, rel)
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("the certificate %s is incomplete: %v", name, err)
		}
		if info.Mode().IsRegular() {
			if err := c.file("letsencrypt", le, rel); err != nil {
				return err
			}
			continue
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("%s is neither a file nor a link", path)
		}
		target, err := os.Readlink(path)
		if err != nil {
			return err
		}
		archived, err := lineageArchiveTarget(name, target)
		if err != nil {
			return fmt.Errorf("%s: %v", path, err)
		}
		if err := c.file("letsencrypt", le, archived); err != nil {
			return err
		}
		if err := c.dir("letsencrypt", le, filepath.Dir(rel)); err != nil {
			return err
		}
		c.link("letsencrypt", le, rel, target, info)
	}
	return nil
}

// lineageArchiveTarget is where a live/ link of lineage name points, as a
// path inside the letsencrypt root, or an error unless it is a file directly
// in that lineage's archive directory. certbot writes the link relative
// (../../archive/<name>/cert3.pem); nothing else is accepted, on either side.
func lineageArchiveTarget(name, target string) (string, error) {
	if filepath.IsAbs(target) {
		return "", fmt.Errorf("links to %s, an absolute path; certbot links within its own tree", target)
	}
	resolved := filepath.Clean(filepath.Join("live", name, target))
	if filepath.Dir(resolved) != filepath.Join("archive", name) {
		return "", fmt.Errorf("links to %s, outside its own lineage's archive", target)
	}
	return resolved, nil
}

// installHostFiles writes the host bundle into this machine's directories:
// directories first, then files, then links, each in its place under its
// root. Every path is checked before anything is written. Returns notes for
// the result (an owner this machine has no account for, written as root).
func installHostFiles(entries []copyHostFile) ([]string, error) {
	roots := copyHostRoots()
	type placed struct {
		e    copyHostFile
		path string
		data []byte
	}
	var dirs, files, links []placed
	for _, e := range entries {
		base, ok := roots[e.Root]
		if !ok {
			return nil, fmt.Errorf("the host bundle names a root %q this machine does not know", e.Root)
		}
		rel := filepath.FromSlash(e.Path)
		if e.Path == "" || filepath.IsAbs(rel) || filepath.Clean(rel) != rel || rel == ".." ||
			strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("the host bundle names a path %q that is not inside its root", e.Path)
		}
		p := placed{e: e, path: filepath.Join(base, rel)}
		switch e.Kind {
		case "dir":
			dirs = append(dirs, p)
		case "file":
			data, err := base64.StdEncoding.DecodeString(e.Data)
			if err != nil || len(data) > copyHostMaxFileBytes {
				return nil, fmt.Errorf("the host bundle's %s is not a file it could carry", e.Path)
			}
			p.data = data
			files = append(files, p)
		case "link":
			parts := strings.Split(e.Path, "/")
			if e.Root != "letsencrypt" || len(parts) != 3 || parts[0] != "live" || !lineageName.MatchString(parts[1]) {
				return nil, fmt.Errorf("the host bundle carries a link at %q; only certbot's live/ links travel", e.Path)
			}
			if _, err := lineageArchiveTarget(parts[1], e.Link); err != nil {
				return nil, fmt.Errorf("the host bundle's link %s %v", e.Path, err)
			}
			links = append(links, p)
		default:
			return nil, fmt.Errorf("the host bundle carries an entry of kind %q", e.Kind)
		}
	}

	var notes []string
	owners := func(e copyHostFile) (int, int) {
		uid, gid := 0, 0
		if e.Owner != "" {
			if u, err := user.Lookup(e.Owner); err == nil {
				uid, _ = strconv.Atoi(u.Uid)
			} else {
				notes = append(notes, fmt.Sprintf("%s: this machine has no account %q, so it is root's", e.Path, e.Owner))
			}
		}
		if e.Group != "" {
			if g, err := user.LookupGroup(e.Group); err == nil {
				gid, _ = strconv.Atoi(g.Gid)
			}
		}
		return uid, gid
	}
	chown := func(path string, e copyHostFile) {
		if os.Geteuid() != 0 {
			return
		}
		uid, gid := owners(e)
		_ = os.Lchown(path, uid, gid)
	}

	for _, d := range dirs {
		if err := os.MkdirAll(d.path, 0o700); err != nil {
			return notes, err
		}
		if err := os.Chmod(d.path, os.FileMode(d.e.Mode&0o777)); err != nil {
			return notes, err
		}
		chown(d.path, d.e)
	}
	for _, f := range files {
		if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
			return notes, err
		}
		if err := writeFileAtomic(f.path, f.data, os.FileMode(f.e.Mode&0o777)); err != nil {
			return notes, err
		}
		chown(f.path, f.e)
	}
	for _, l := range links {
		if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
			return notes, err
		}
		tmp := l.path + ".copy-import"
		_ = os.Remove(tmp)
		if err := os.Symlink(l.e.Link, tmp); err != nil {
			return notes, err
		}
		if err := os.Rename(tmp, l.path); err != nil {
			_ = os.Remove(tmp)
			return notes, err
		}
		chown(l.path, l.e)
	}
	return notes, nil
}
