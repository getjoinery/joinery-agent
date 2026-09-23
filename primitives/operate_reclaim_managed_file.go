package primitives

import "time"

// reclaim_managed_file {file}: put one host file back to the platform's own
// definition — move it aside to a dated copy, run the installer that owns
// it, and return the transcript.
//
// specs/agent_recipes_and_vocabulary.md, "Host files: what may be read and
// what may be reset". The general form of the fail2ban_reset_config named in
// implemented/agent_tier1_recipes.md. What runs is
// maintenance_scripts/sysadmin_tools/reclaim_managed_file.sh, verified
// against the signed release manifest, with one argv element.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Put one of the files below back to what the release says it should be,
// undoing an owner's hand edit to it — which is kept beside it, dated, and
// named in the transcript. That is a configuration change that keeps a
// backup: operate, not destructive (rule 9, owner 2026-09-23).
//
// What it cannot do:
//
//   - Name a file. `file` is an enum of the resettable list, and the script
//     re-validates against its own copy. Only files a re-runnable installer
//     writes are on it; apache2.conf (owner, option A), the certbot vhost,
//     every mail file, the security settings, the apt files and docker's
//     daemon.json never are.
//   - Delete anything. The script moves, and puts the copy back when the
//     owning installer does not write the file on this machine.
//   - Run anything but the file's owning installer, through the host runner's
//     --only under the runner lock.
func init() {
	Register(Primitive{
		Name:        "reclaim_managed_file",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Put one host file from a compiled list back to the platform's definition: move it aside to a dated copy and run the installer that owns it.",
		Params: []ParamSpec{
			{Name: "file", Type: ParamEnum, Required: true, Values: reclaimFiles},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  reclaimManagedFileScript,
			Args:        []string{"{file}"},
			StdinFrom:   nil,
		},
		Timeout: 15 * time.Minute,
	})
}

// reclaimFiles is the resettable list: a subset of file_head's readable names,
// and a MIRROR of the case table in reclaim_managed_file.sh and of
// RECLAIM_FILES on the plane.
var reclaimFiles = []string{
	"fail2ban_jail_local",
	"fail2ban_joinery_sshd",
	"fail2ban_joinery_apache",
	"apache_remoteip",
	"apache_mpm_event",
	"journald_size_limit",
	"php_fpm_ini",
	"apache_site",
	"cron_agent",
	"logrotate_site",
	"cron_site",
}

const reclaimManagedFileScript = "maintenance_scripts/sysadmin_tools/reclaim_managed_file.sh"
