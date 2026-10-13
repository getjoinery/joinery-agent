package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// joinery-agent bundle install FILE [--statement=FILE]: a support bundle from
// a file on this machine, the release's own (install.sh docker hands it
// agent_dist/support_bundle.tar.gz). A Docker host that never joins a
// management node then has its host converger too: the converge a bundle's
// arrival runs installs the converger's timer, and from then on the host's
// data root ticks like any other host's.
//
// The bytes are held to exactly what a bundle from a management node is held
// to (installFrom): the signed manifest inside, checked against the release
// key compiled into this binary, every file hashed both ways, and, on a
// machine that holds release-log keys, the release statement beside it in the
// public log. Where the bytes came from earns nothing. A management node this
// machine joins later replaces the bundle whenever it offers other bytes, so
// the binary and the bundle stay the management node's release.
//
// The command succeeds only when the host converged: on a host that never
// joins, nothing else would install the host timer.
func cliBundle(args []string) int {
	if len(args) < 2 || args[0] != "install" {
		return cliError("usage: joinery-agent bundle install FILE [--statement=FILE]")
	}
	file := args[1]
	statementPath := ""
	for _, a := range args[2:] {
		v, ok := strings.CutPrefix(a, "--statement=")
		if !ok {
			return cliError("unrecognised argument %q; see `joinery-agent help`", a)
		}
		statementPath = v
	}
	if os.Geteuid() != 0 {
		return cliError("bundle install runs as root: it writes %s", BundleRoot())
	}
	cfg := cliConfig()
	b := NewBundleSync(cfg)
	if b == nil {
		return cliError("this machine takes no support bundle: it has a site tree to verify against, or this build carries no release key")
	}
	// A job the agent started before this command runs scripts from the tree
	// this command would swap. One that starts while this runs meets a swap
	// as it meets one the agent makes itself.
	if pid := liveJobMarkerPid(); pid != 0 {
		return cliError("the agent is running a job (pid %d, %s); run this again when it finishes", pid, jobMarkerPath)
	}
	if code := installBundleFile(b, file, statementPath); code != 0 {
		return code
	}
	// The converge a bundle's arrival runs (bundle_converge.go): it installs
	// the host converger's timer, under the same job marker a job would hold.
	if err := convergeAfterBundle(cfg, nil, &sync.Mutex{}); err != nil {
		return cliError("the bundle is installed at %s, but the converge that installs the host converger did not run: %v", BundleRoot(), err)
	}
	return 0
}

// installBundleFile installs FILE through installFrom, the statement read from
// statementPath when this machine is held to the public log. The same bytes
// already in place are not swapped again.
func installBundleFile(b *BundleSync, file, statementPath string) int {
	f, err := os.Open(file)
	if err != nil {
		return cliError("cannot read the bundle: %v", err)
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > maxBundleArtifactBytes {
		return cliError("%s is %d bytes, over this agent's %d-byte limit for a bundle", file, st.Size(), maxBundleArtifactBytes)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return cliError("cannot read the bundle: %v", err)
	}
	sum := hex.EncodeToString(hasher.Sum(nil))
	if stamp := readBundleStamp(); stamp != nil && strings.EqualFold(stamp.SourceSha256, sum) && bundleTreePresent() {
		fmt.Printf("Support bundle %s is already installed at %s.\n", stamp.Version, BundleRoot())
		return 0
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return cliError("cannot read the bundle: %v", err)
	}

	if statementPath == "" && heldReleaseLogKeys(b.bakedLogKeys, b.keyDir).holds() {
		return cliError("this machine installs only a bundle its release statement records: give --statement=FILE, the RELEASE_STATEMENT beside the bundle")
	}
	statement := func() ([]byte, error) { return os.ReadFile(statementPath) }
	version, err := b.installFrom(f, sum, statement)
	if errors.Is(err, errBundleRetry) {
		return cliError("the bundle was not installed: %s", strings.TrimPrefix(err.Error(), errBundleRetry.Error()+": "))
	}
	if err != nil {
		return cliError("the bundle was refused, and nothing was installed: %v", err)
	}
	fmt.Printf("Support bundle %s installed at %s.\n", version, BundleRoot())
	return 0
}

// liveJobMarkerPid is the pid on the job marker's first line while a
// joinery-agent runs as that pid, or 0: no marker, an unreadable one, one a
// killed process left, or one whose pid another program now has. The test is
// install_agent.sh's (agent_job_in_progress), so the two readers agree.
func liveJobMarkerPid() int {
	raw, err := os.ReadFile(jobMarkerPath)
	if err != nil {
		return 0
	}
	first, _, _ := strings.Cut(string(raw), "\n")
	pid, err := strconv.Atoi(strings.TrimSpace(first))
	if err != nil || pid <= 0 {
		return 0
	}
	if err := syscall.Kill(pid, 0); err != nil && !errors.Is(err, syscall.EPERM) {
		return 0
	}
	comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil || strings.TrimSpace(string(comm)) != "joinery-agent" {
		return 0
	}
	return pid
}
