package primitives

// site_state_report: what every site state directory on this machine holds
// (specs/site_copy.md WP5, specs/site_copy_final_test.md).
//
// A site's state directory, /etc/joinery/sites/{site}, is where a machine
// keeps what makes a site quiet and what makes it a copy: the state line, the
// copy_of record and the source's key, the vouched runs, the look secret, the
// forward address, the held cron files. On a container host the same
// directory holds the host's side: the run spec, the id block, the quiet
// record. Every one of them is written by the machine and read by the
// machine, and until this word nothing could show the plane what was there.
// A kept copy whose clearing left a copy_of behind would refuse every operate
// word as a dormant copy, and the plane could only see the refusals.
//
// It answers with each site directory's entries (name, kind, size, mode,
// whether root owns it, when it last changed), the values of the few records
// that are plain facts the plane set itself (the state line, copy_of, forward,
// the host's quiet record and id block), and the agent's own reading of its
// site, the one the dispatcher acts on.
//
// HOSTILE-CALLER REVIEW (rule 5 of specs/agent_recipes_and_vocabulary.md).
//
// What is the worst a compromised management node can do with this word? Learn
// which sites on this machine are quiet or copies, of which node, forwarding
// to which address, and when each record changed. The plane wrote all of it:
// it froze the site, made the copy and named the forward address. host_report
// already names the sites.
//
// What it cannot do:
//
//   - Read a secret. The look secret, the run spec, the source's key, the
//     vouched runs and the history are named and sized, never read. Only the
//     records in stateValueRecords are read, a first line of at most 64 bytes,
//     printed only when every byte is in a safe set.
//   - Point anywhere. NO PARAMETERS: the directory is compiled in.
//   - Follow a link. A symbolic link is reported as one, never followed or
//     read, at any depth.
//   - Flood the plane: at most stateReportMaxSites sites, stateReportMaxEntries
//     entries each, three levels deep.
//
// OBSERVE: it opens nothing for writing, so it runs on a quiet site as every
// read does. Machine: on a container host it reports the host's records.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func init() {
	Register(Primitive{
		Name:        "site_state_report",
		Class:       ClassObserve,
		Machine:     true,
		Description: "What every site state directory on this machine holds (the quiet state, a copy's records, a host's run specs): names, sizes and times, the values of the plain records only.",
		Params:      nil,
		Run:         runSiteStateReport,
	})
}

const (
	stateReportMaxSites   = 100
	stateReportMaxEntries = 64
	stateReportMaxDepth   = 3
	stateValueMaxBytes    = 64
)

// stateValueRecords are the records whose first line is printed: facts the
// plane set, never a secret. Everything else is named and sized only.
var stateValueRecords = map[string]bool{
	"state":   true, // quiet copy | quiet switchover
	"copy_of": true, // the source's node id
	"forward": true, // the copy's address while a switch settles
	"quiet":   true, // a host's record: copy | switchover
	"idblock": true, // a host's id block number
}

var (
	stateSafeName  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	stateSafeValue = regexp.MustCompile(`^[A-Za-z0-9 ._:-]*$`)
)

func runSiteStateReport(_ context.Context, env *ExecEnv, _ Params) (map[string]interface{}, error) {
	out := map[string]interface{}{"sites_dir": SiteStateDir}
	if env != nil && env.SiteRoot != "" {
		site := filepath.Base(env.SiteRoot)
		st, err := ReadSiteState(env)
		reading := map[string]interface{}{"site": site, "reason": st.Reason, "copy_of": st.CopyOf}
		if err != nil {
			reading["error"] = err.Error()
		}
		out["reading"] = reading
	}

	dirents, err := os.ReadDir(SiteStateDir)
	if errors.Is(err, fs.ErrNotExist) {
		out["exists"] = false
		out["sites"] = []interface{}{}
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", SiteStateDir, err)
	}
	out["exists"] = true

	sites := []interface{}{}
	truncated := false
	for _, d := range dirents {
		// Only site directories: the top level also holds the host's network
		// lock, which says nothing about a site.
		if !d.IsDir() || strings.HasPrefix(d.Name(), ".") {
			continue
		}
		if len(sites) == stateReportMaxSites {
			truncated = true
			break
		}
		entries := []interface{}{}
		if walkStateDir(filepath.Join(SiteStateDir, d.Name()), "", 1, &entries) {
			truncated = true
		}
		sites = append(sites, map[string]interface{}{"site": stateName(d.Name()), "entries": entries})
	}
	out["sites"] = sites
	out["truncated"] = truncated
	return out, nil
}

// walkStateDir appends dir's entries, prefixed rel, and those of its
// subdirectories to stateReportMaxDepth. True when the entry cap cut it short.
func walkStateDir(dir, rel string, depth int, entries *[]interface{}) bool {
	dirents, err := os.ReadDir(dir)
	if err != nil {
		*entries = append(*entries, map[string]interface{}{"name": rel, "error": err.Error()})
		return false
	}
	for _, d := range dirents {
		if len(*entries) >= stateReportMaxEntries {
			return true
		}
		name := stateName(d.Name())
		if rel != "" {
			name = rel + "/" + name
		}
		path := filepath.Join(dir, d.Name())
		info, err := os.Lstat(path)
		if err != nil {
			*entries = append(*entries, map[string]interface{}{"name": name, "error": err.Error()})
			continue
		}
		e := map[string]interface{}{
			"name":     name,
			"mode":     fmt.Sprintf("%04o", info.Mode().Perm()),
			"modified": info.ModTime().UTC().Format(time.RFC3339),
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			e["root_owned"] = st.Uid == 0
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			e["kind"] = "symlink"
		case info.IsDir():
			e["kind"] = "dir"
		case info.Mode().IsRegular():
			e["kind"] = "file"
			e["bytes"] = info.Size()
			if rel == "" && stateValueRecords[d.Name()] {
				if v, ok := stateValue(path); ok {
					e["value"] = v
				}
			}
		default:
			e["kind"] = "other"
		}
		*entries = append(*entries, e)
		if info.IsDir() && depth < stateReportMaxDepth {
			if walkStateDir(path, name, depth+1, entries) {
				return true
			}
		}
	}
	return false
}

// stateValue is a record's first line, when it is short and every byte is
// safe to print.
func stateValue(path string) (string, bool) {
	// Never a link, and never a pipe swapped in after the walk looked.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", false
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	buf := make([]byte, stateValueMaxBytes+1)
	n, _ := io.ReadFull(f, buf)
	line := strings.TrimRight(strings.SplitN(string(buf[:n]), "\n", 2)[0], "\r")
	if len(line) > stateValueMaxBytes || !stateSafeValue.MatchString(line) {
		return "", false
	}
	return line, true
}

// stateName is a directory entry's name as printed: itself when it is a plain
// name, quoted and cut short when it is not.
func stateName(name string) string {
	if stateSafeName.MatchString(name) {
		return name
	}
	if len(name) > 64 {
		name = name[:64]
	}
	return strconv.QuoteToASCII(name)
}
