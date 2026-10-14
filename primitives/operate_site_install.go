package primitives

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// site_install: install one dormant copy of a site as a container on this
// host (specs/site_container_engine.md D9). A site that moves to another host
// is copied there from its backups: this word makes the empty, quiet site the
// copy restores into, the way the bare-metal install does for a copy on a
// machine of its own.
//
// A SCRIPT WORD RUN FROM A RELEASE. install.sh comes from the published core
// archive of the release named (the source's), fetched through the management
// node and verified before anything in it runs (ScriptSpec.Release,
// release_archive.go): this host has no site tree, and its support bundle
// carries install.sh only as a helper, without the site it installs. And the
// site is that tree and nothing else (--release-tree-only): install.sh lays no
// core archive over it and fetches no theme, plugin or bundle, so no code the
// management node serves unsigned runs in the copy, not even on the page its
// owner types the recovery key into (reviewer2 WP5 R1). The copy's restore
// then brings the source's own code, themes and plugins from its backups.
//
// The copy is born quiet (install.sh, start_dormant_container): its own state
// is in its container before its first process, its host records it quiet,
// and the engine's hook gives it the table that keeps every account but its
// root off the network. It serves its owner's look alone, sends nothing and
// runs no scheduled task until it takes over its source's node id.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Make this host build one more site container, quiet, from a release the
// publisher signed: a few hundred megabytes of disk, the memory its limit
// allows, a port. install.sh checks it fits the host's limits; the operator
// sees it on the host's list and removes it. Accepted.
//
// What it cannot do:
//
//   - Replace or rebuild a site that is here. install.sh refuses a copy whose
//     name this host already has: a container, a run spec or any volume of it.
//   - Install from anything but a signed release: the tree must verify, both
//     ways, against the key compiled into this binary, and against the public
//     log where this machine holds its keys, and the site is built from that
//     tree alone.
//   - Point the new site at another management node. It joins the one this
//     machine is enrolled with (ExecEnv.PlaneURL); nothing in the job names one.
//   - Make a live site. Every install here is a dormant copy: --dormant and
//     its source's node and key are composed here, never optional.
func init() {
	Register(Primitive{
		Name:        "site_install",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Install a dormant copy of a site as a container on this host, from its source's release (verified before it runs): quiet from its first process until it takes over its source's node.",
		Params: []ParamSpec{
			{Name: "name", Type: ParamString, Required: true, MaxLen: 50, Pattern: siteInstallName},
			{Name: "domain", Type: ParamString, Required: true, MaxLen: 253, Pattern: siteInstallDomain},
			{Name: "port", Type: ParamInt, Required: true, Min: 1024, Max: 65000},
			{Name: "release", Type: ParamString, Required: true, MaxLen: 20, Pattern: siteInstallRelease},
			{Name: "copy_of", Type: ParamInt, Required: true, Min: 1, Max: 999999999999999999},
			{Name: "copy_of_key", Type: ParamString, Required: true, MaxLen: 44, Pattern: siteInstallKey},
			{Name: "memory", Type: ParamString, MaxLen: 8, Pattern: siteInstallMemory},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  siteInstallScript,
			Release:     func(_ context.Context, _ *ExecEnv, p Params) (string, error) { return p.String("release"), nil },
			ArgsFrom:    siteInstallArgv,
		},
		// The site's image is built here: minutes, more on a busy host.
		Timeout: 75 * time.Minute,
	})
}

const siteInstallScript = "maintenance_scripts/install_tools/install.sh"

var (
	// install.sh's own site-name rule.
	siteInstallName    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,49}$`)
	siteInstallDomain  = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	siteInstallRelease = regexp.MustCompile(`^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$`)
	// The source's agent public key, as install.sh's --copy-of-key reads it.
	siteInstallKey    = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
	siteInstallMemory = regexp.MustCompile(`^[1-9][0-9]{0,5}[mg]$`)
	siteInstallPlane  = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$`)
)

func siteInstallArgv(_ context.Context, env *ExecEnv, p Params) ([]string, error) {
	if env == nil || env.SiteRoot != "" {
		return nil, refusedf("site_install: a site is installed by its host, and this machine is a site")
	}
	if env.PlaneURL == nil {
		return nil, refusedf("site_install: this agent cannot read the management node it is enrolled with")
	}
	plane, err := env.PlaneURL()
	if err != nil {
		return nil, refusedf("site_install: %v", err)
	}
	if !siteInstallPlane.MatchString(plane) {
		return nil, refusedf("site_install: this machine's management node (%s) is not an https address a site can join", plane)
	}
	plane = strings.TrimSuffix(plane, "/")
	argv := []string{
		"-y", "-q", "site", "--docker",
		p.String("name"), "-", p.String("domain"), strconv.FormatInt(p.Int("port"), 10),
		"--enable-agent", "--management-node=" + plane, "--upgrade-server=" + plane,
		"--dormant", "--copy-of=" + strconv.FormatInt(p.Int("copy_of"), 10), "--copy-of-key=" + p.String("copy_of_key"),
		"--release-tree-only",
	}
	if m := p.String("memory"); m != "" {
		argv = append(argv, "--memory="+m)
	}
	return argv, nil
}
