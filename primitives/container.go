package primitives

import "os"

// containerMarkers are the files a container engine writes into every
// container it starts: Docker's /.dockerenv, and /run/.containerenv for the
// site container engine (Podman, specs/site_container_engine.md D7). Either
// one means this process runs inside a container. A variable so a test
// can point it at a fixture.
var containerMarkers = []string{"/.dockerenv", "/run/.containerenv"}

// RunsInContainer answers whether this process runs inside a container, by
// either engine's marker: on a Joinery host, a site's.
func RunsInContainer() bool {
	for _, m := range containerMarkers {
		if _, err := os.Stat(m); err == nil {
			return true
		}
	}
	return false
}
