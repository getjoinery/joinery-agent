package main

import (
	"errors"
	"os"
	"os/exec"
)

// The engine this host's sites run on, named the way
// maintenance_scripts/install_tools/_site_engine.sh names it
// (specs/site_container_engine.md D7): the site container engine, our own
// Podman build, where anything is at its current path (install_site_engine.sh
// makes it a link), and Docker anywhere else. A link counts as itself,
// whatever it points at; anything else there, or an engine with no usable
// podman binary, is a refusal, never Docker, which a host with the site
// container engine does not run. Variables so a test can point them at a
// fixture.
//
// siteEngineRule is the helper's Version this rule matches; the plane's
// agent_engine_rule_test fails when the helper moves on and this does not.
const siteEngineRule = "1.3"

var (
	siteEngineCurrent = "/usr/local/lib/joinery-site-engine/current"
	siteEnginePodman  = "/usr/local/bin/podman"
)

// siteEngine is the engine's name (podman or docker) and the binary to run.
func siteEngine() (name, bin string, err error) {
	if fi, lerr := os.Lstat(siteEngineCurrent); lerr == nil {
		if fi.Mode()&os.ModeSymlink == 0 {
			return "", "", errors.New(siteEngineCurrent + " is not a link (install_tools/install_site_engine.sh converge)")
		}
		st, serr := os.Stat(siteEnginePodman)
		if serr != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
			return "", "", errors.New("this host's sites run on the site container engine, and " + siteEnginePodman +
				" is missing or not executable (install_tools/install_site_engine.sh converge)")
		}
		return "podman", siteEnginePodman, nil
	}
	docker, lerr := exec.LookPath("docker")
	if lerr != nil {
		return "", "", errors.New("docker is not on this host's path")
	}
	return "docker", docker, nil
}

// engineStorageFormat is the engine's info template for the folder it keeps
// its data in: Docker's root directory, or the site container engine's
// storage (its graphroot), whose volumes are laid out the same way
// (volumes/<name>/_data).
func engineStorageFormat(name string) string {
	if name == "podman" {
		return "{{.Store.GraphRoot}}"
	}
	return "{{.DockerRootDir}}"
}
