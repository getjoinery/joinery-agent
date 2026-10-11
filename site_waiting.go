package main

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// A site whose config lives on the data root (an encrypted machine's,
// specs/hosted_data_promise_disk_encryption.md D9): while the data root is
// locked, or still starting, config/ is an empty mountpoint, and the agent
// starts beside the unlock (D4) so its management node can still reach it.
// Its config is absent then, and that must not read as "this machine has no
// site": machine posture would give a site's machine the powers only a
// siteless one has.

// dataBindsPath and mountInfoPath are package variables so a test can point
// them at its own files.
var (
	dataBindsPath = "/etc/joinery/data_binds"
	mountInfoPath = "/proc/self/mountinfo"
)

// siteConfigAwaitsDataRoot: the config's folder is a recorded bind of the
// data root (joinery_data_root.sh, /etc/joinery/data_binds) and is not
// mounted now. A folder that is mounted and still has no config has no site.
func siteConfigAwaitsDataRoot(configPath string) bool {
	dir := filepath.Clean(filepath.Dir(configPath))
	f, err := os.Open(dataBindsPath)
	if err != nil {
		return false
	}
	defer f.Close()
	recorded := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && !strings.HasPrefix(fields[0], "#") && filepath.Clean(fields[1]) == dir {
			recorded = true
			break
		}
	}
	return recorded && !isMountPoint(dir)
}

// isMountPoint reads /proc/self/mountinfo: its fifth field is the mount
// point, with a space escaped as \040 (a site path holds none).
func isMountPoint(dir string) bool {
	f, err := os.Open(mountInfoPath)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) > 4 && fields[4] == dir {
			return true
		}
	}
	return false
}

// siteConfigWatchInterval and siteConfigWatchExit: how often a waiting site
// looks for its config, and how the process ends once it is readable (the
// supervisor starts it again, and the start reads it). Package variables so a
// test can drive the watcher.
var (
	siteConfigWatchInterval = 15 * time.Second
	siteConfigWatchExit     = func() { os.Exit(0) }
)

// watchSiteConfig waits for a waiting site's config to be readable, then
// restarts the agent to read it, once no job is running.
func watchSiteConfig(path string, jobLock *sync.Mutex) {
	for {
		time.Sleep(siteConfigWatchInterval)
		if _, err := parseGlobalvars(path); err == nil {
			log.Printf("the site config at %s is readable now (the data root is mounted): restarting to read it", path)
			jobLock.Lock()
			siteConfigWatchExit()
			jobLock.Unlock()
			return
		}
	}
}
