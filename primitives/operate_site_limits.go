package primitives

import (
	"regexp"
	"time"
)

// site_limits: change one of this Docker host's sites' memory, CPU ceiling
// and disk allowance without rebuilding it
// (specs/multi_tenant_docker_hosts.md WP6).
//
// Why it exists: a site may need a bigger allowance, or an abuser a smaller
// one, and a rebuild is minutes of downtime and a full image build. Memory and
// CPU change on the running container; the disk allowance on the host's disk
// pool. The run spec records each, so a rebuild keeps them.
//
// A SCRIPT WORD: maintenance_scripts/sysadmin_tools/site_limits.sh, verified
// against the signed release manifest (on a Docker host, the support
// bundle's), with four argv elements: the site name, then memory, cpus and
// disk, each a figure, none, or keep.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Squeeze one of the host's sites: a memory limit low enough that it barely
// runs, a CPU ceiling of 0.01, a disk allowance below what it holds (it then
// refuses uploads and stored mail until room is made; nothing is deleted). A
// memory change restarts the site. All of it is undone by the same word.
// hold_container can already take a site down outright. Accepted.
//
// What it cannot do:
//
//   - Name anything but a site container install.sh made with a run spec:
//     `name` matches the site pattern here, and the script refuses any other.
//   - Give a site more than the host has: the script refuses a CPU ceiling
//     above the host's CPUs, a memory size Docker would not take, and a disk
//     allowance on a host with no disk pool. It cannot lift a memory limit or
//     CPU ceiling on a running container at all.
//   - Touch the site's data. It runs docker update, docker restart, and the
//     disk pool's quota commands, and writes the run spec.
func init() {
	Register(Primitive{
		Name:        "site_limits",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Change one of this host's sites' memory, CPU ceiling and disk allowance without rebuilding it: each a figure, none, or keep.",
		Params: []ParamSpec{
			{Name: "name", Type: ParamString, Required: true, MaxLen: 50, Pattern: holdContainerName},
			{Name: "memory", Type: ParamString, Required: true, MaxLen: 16, Pattern: siteLimitsMemory},
			{Name: "cpus", Type: ParamString, Required: true, MaxLen: 16, Pattern: siteLimitsCpus},
			{Name: "disk", Type: ParamString, Required: true, MaxLen: 16, Pattern: siteLimitsDisk},
		},

		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  siteLimitsScript,
			Args:        []string{"{name}", "{memory}", "{cpus}", "{disk}"},
			StdinFrom:   nil,
		},

		// docker update, the quota commands, and a container restart that
		// waits for the site to stop.
		Timeout: 5 * time.Minute,
	})
}

const siteLimitsScript = "maintenance_scripts/sysadmin_tools/site_limits.sh"

var (
	siteLimitsMemory = regexp.MustCompile(`^([0-9]{1,6}[bkmg]?|none|keep)$`)
	siteLimitsCpus   = regexp.MustCompile(`^([0-9]{1,3}(\.[0-9]{1,3})?|\.[0-9]{1,3}|none|keep)$`)
	siteLimitsDisk   = regexp.MustCompile(`^([0-9]{1,6}[mgt]|none|keep)$`)
)
