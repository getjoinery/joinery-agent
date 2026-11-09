package primitives

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// site_create: install one new, live site as a container on this host — a
// sold Starter site (specs/starter_tier.md, Launch scope step 3). Its twin,
// site_install, makes a dormant copy that a restore fills; this one makes a
// site that starts serving its owner at once, with the admin account its
// buyer is shown.
//
// A SCRIPT WORD RUN FROM A RELEASE, as site_install is: install.sh comes from
// the published core archive of the release named, fetched through the
// management node and verified before anything in it runs (ScriptSpec.Release,
// release_archive.go). The site is then installed as a site on its own server
// is (install_node): the core overlay, theme and plugin bundle are downloaded
// from the management node this machine is enrolled with, which is the site's
// upgrade server for the rest of its life, and are NOT checked against a
// signed manifest before the site's image is built. Unlike a dormant copy
// (--release-tree-only), a live site needs its theme and plugins, so the new
// site's code is what that management node serves.
//
// THE ADMIN PASSWORD TRAVELS ON STDIN. It is the account's first password,
// which the management node shows its buyer once and the site asks them to
// change at first sign-in (install.sh --admin-password-stdin). argv is
// visible to every process on the box, and this word hands a script no
// environment, so stdin is the only way it may reach install.sh. The
// management node opens it from its sealed copy into the signed job it hands
// out, and stores it in no job record.
//
// ALWAYS A NEW SITE (--new-site-only, composed here, never optional). On a
// shared host a name already in use is another customer's site, and -y would
// stop and rebuild it over its volumes. install.sh refuses a name this host
// already has (its container, run spec or any volume), a domain another site
// here serves, and a port in use rather than quietly taking another the
// management node never hears of. A run that fails removes what it made. A
// run killed outright (this word's time limit) cannot, so install.sh marks
// each install unfinished from the moment its name is proved free until it
// ends (/etc/joinery/new-site/NAME), and the next run of the same name clears
// what carries that mark before it starts.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Make this host build one more live site container, joined to that same
// management node, running code that node chose: the core overlay and the
// bundle above are downloaded from it and not checked against a signed
// manifest. That IS something it could not do before: the sites already on
// this host verify what they are served (upgrades are signature-checked, and
// recreate_site builds only from the host's own run spec and signed tree), so
// this word is the one way unsigned code of the management node's choosing
// comes to run here. What holds it is the container: its walls, its
// memory, processor and disk limits, its own port, no reach into its
// neighbours' files (the site container engine's id blocks). Accepted for
// launch (owner, 2026-11-09), to be closed after it by checking the overlay
// against the release's signed manifest before the image is built
// (specs/starter_tier.md, reviewer2 A3). The operator sees the site on the
// host's list and removes it.
//
// What it cannot do:
//
//   - Replace or rebuild a site that is here: --new-site-only is always
//     passed, and install.sh refuses a name this host already has. The one
//     thing of that name it removes is an install of this word that never
//     finished: a finished site carries no unfinished mark, and any other
//     install of the name drops it.
//   - Run install.sh itself from anything but a signed release: the tree
//     verifies, both ways, against the key compiled into this binary and the
//     public log where this machine holds its keys.
//   - Point the new site at another management node. It joins the one this
//     machine is enrolled with (ExecEnv.PlaneURL); nothing in the job names one.
//   - Make a site with no limits: memory, processors and disk are each
//     required and bounded to their shapes here, and install.sh refuses a
//     disk allowance on a host that cannot enforce one. Their size is the
//     management node's to choose.
//   - Put the password anywhere but install.sh's stdin: it is never in argv,
//     and stdin is never logged.
func init() {
	Register(Primitive{
		Name:        "site_create",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Install a new live site as a container on this host, from a release (verified before it runs), with its admin account's first password on stdin.",
		Params: []ParamSpec{
			{Name: "name", Type: ParamString, Required: true, MaxLen: 50, Pattern: siteInstallName},
			{Name: "domain", Type: ParamString, Required: true, MaxLen: 253, Pattern: siteInstallDomain},
			{Name: "port", Type: ParamInt, Required: true, Min: 1024, Max: 65000},
			{Name: "release", Type: ParamString, Required: true, MaxLen: 20, Pattern: siteInstallRelease},
			{Name: "admin_email", Type: ParamString, Required: true, MaxLen: 254, Pattern: siteCreateEmail},
			{Name: "admin_password", Type: ParamString, Required: true, MaxLen: 128, Pattern: siteCreatePassword},
			{Name: "memory", Type: ParamString, Required: true, MaxLen: 8, Pattern: siteInstallMemory},
			{Name: "cpus", Type: ParamString, Required: true, MaxLen: 5, Pattern: siteCreateCpus},
			{Name: "disk", Type: ParamString, Required: true, MaxLen: 8, Pattern: siteCreateDisk},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  siteInstallScript,
			Release:     func(_ context.Context, _ *ExecEnv, p Params) (string, error) { return p.String("release"), nil },
			ArgsFrom:    siteCreateArgv,
			StdinFrom:   siteCreateStdin,
		},
		// The site's image is built here: minutes, more on a busy host.
		Timeout: 75 * time.Minute,
	})
}

var (
	// One address: a local part at a hostname, nothing that could be a second
	// argument or a header.
	siteCreateEmail = regexp.MustCompile(`^[A-Za-z0-9._+-]+@([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$`)
	// Printable, one line, long enough to be a password the plane minted.
	siteCreatePassword = regexp.MustCompile(`^[\x21-\x7e]{12,128}$`)
	// A core count: 1, 0.5, 1.5, 2.
	siteCreateCpus = regexp.MustCompile(`^[0-9]{1,2}(\.[0-9]{1,2})?$`)
	// A disk allowance in install.sh's syntax: 5G, 512M.
	siteCreateDisk = regexp.MustCompile(`^[1-9][0-9]{0,5}[MG]$`)
)

func siteCreateArgv(_ context.Context, env *ExecEnv, p Params) ([]string, error) {
	if env == nil || env.SiteRoot != "" {
		return nil, refusedf("site_create: a site is installed by its host, and this machine is a site")
	}
	if env.PlaneURL == nil {
		return nil, refusedf("site_create: this agent cannot read the management node it is enrolled with")
	}
	plane, err := env.PlaneURL()
	if err != nil {
		return nil, refusedf("site_create: %v", err)
	}
	if !siteInstallPlane.MatchString(plane) {
		return nil, refusedf("site_create: this machine's management node (%s) is not an https address a site can join", plane)
	}
	plane = strings.TrimSuffix(plane, "/")
	argv := []string{
		"-y", "-q", "site", "--docker",
		p.String("name"), "-", p.String("domain"), strconv.FormatInt(p.Int("port"), 10),
		"--enable-agent", "--management-node=" + plane, "--upgrade-server=" + plane,
		"--admin-email=" + p.String("admin_email"), "--admin-password-stdin", "--new-site-only",
		"--memory=" + p.String("memory"), "--cpus=" + p.String("cpus"), "--disk=" + p.String("disk"),
	}
	return argv, nil
}

// The one line install.sh --admin-password-stdin reads.
func siteCreateStdin(p Params) (string, error) {
	return p.String("admin_password") + "\n", nil
}
