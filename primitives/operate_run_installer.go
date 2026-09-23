package primitives

// run_installer {name}: run ONE installer through the host runner, under the
// runner lock, and return the transcript.
//
// specs/agent_recipes_and_vocabulary.md § First words. An operate word that
// means "make this aspect of the host correct" is an installer run by name:
// install day, the host timer and a repair run the same code (requirement 5).
// host_converge is this word with its one installer compiled in;
// run_plugin_installers runs them all.
//
// The name is one of two shapes, and the ArgsFrom below turns it into the
// runner's own flag, never a path:
//
//   - a core installer: one of the five names in the runner's
//     CORE_INSTALLERS, an enum here (runInstallerCore) and refused by the
//     runner itself outside its own list. On a machine with no site only the
//     runner's HOST_INSTALLERS are accepted, under --machine, and the runner
//     refuses the rest there too.
//   - plugin:NAME, a plugin's declared host_installer, which the runner runs
//     with --only-plugin=NAME only when that plugin is active on this node and
//     declares one, out of the plugin's own directory, under the same trust
//     check every plugin installer passes. Never on a machine with no site: a
//     machine has no plugins.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word? Run
// an installer the host timer already runs every day, sooner. Every one is
// idempotent by contract and writes what the release says the host should be.
// Dispatched in a loop it costs CPU and holds the runner lock, which the timer
// waits out. Accepted.
//
// What it cannot do:
//
//   - Name a file. `name` is a compiled pattern whose core half is five
//     literal names; the plugin half is a plugin identifier, which the runner
//     resolves through the plugin's own plugin.json and refuses when the path
//     escapes the plugin directory.
//   - Choose arguments, a tree or an environment. ArgsFrom composes the one
//     flag from the validated name and the machine's own posture.

import (
	"context"
	"regexp"
	"strings"
	"time"
)

func init() {
	Register(Primitive{
		Name:        "run_installer",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Run one installer by name (a core installer, or plugin:NAME for an active plugin's host installer) through the host runner, and return the transcript.",
		Params: []ParamSpec{
			{Name: "name", Type: ParamString, Required: true, MaxLen: 64, Pattern: runInstallerName},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  pluginInstallersRunner,
			ArgsFrom:    runInstallerArgv,
			StdinFrom:   nil,
		},
		Timeout: 15 * time.Minute,
	})
}

// runInstallerCore mirrors CORE_INSTALLERS in _plugin_installers_start.sh, and
// runInstallerHost its HOST_INSTALLERS. The runner refuses outside its own
// lists whatever these say; these refuse first so the plane is told here.
var (
	runInstallerCore = []string{
		"install_agent.sh",
		"install_parser_jail.sh",
		"install_host_converger.sh",
		"render_vhost.sh",
		"host_housekeeping.sh",
		"site_housekeeping.sh",
	}
	runInstallerHost = []string{
		"host_housekeeping.sh",
		"install_host_converger.sh",
	}
	runInstallerName = regexp.MustCompile(`^(install_agent\.sh|install_parser_jail\.sh|install_host_converger\.sh|render_vhost\.sh|host_housekeeping\.sh|site_housekeeping\.sh|plugin:[a-z][a-z0-9_]{1,49})$`)
)

func runInstallerArgv(_ context.Context, env *ExecEnv, p Params) ([]string, error) {
	name := p.String("name")
	siteless := env != nil && env.SiteRoot == ""
	if plugin, ok := strings.CutPrefix(name, "plugin:"); ok {
		if siteless {
			return nil, refusedf("run_installer: %s names a plugin installer, and a machine with no site has no plugins", name)
		}
		return []string{"--only-plugin=" + plugin}, nil
	}
	if siteless {
		for _, h := range runInstallerHost {
			if h == name {
				return []string{hostConvergeMachine, "--only=" + name}, nil
			}
		}
		return nil, refusedf("run_installer: %s is not a host installer; a machine with no site runs only %s",
			name, strings.Join(runInstallerHost, ", "))
	}
	return []string{"--only=" + name}, nil
}
