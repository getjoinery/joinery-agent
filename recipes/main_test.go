package recipes

import (
	"os"

	"joinery-agent/primitives"
	"testing"
)

// TestMain points the site state root at an empty folder, so no test passes
// or fails by what the machine running it holds in /etc/joinery/sites. A test
// about site state sets its own.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "agent-site-state-")
	if err != nil {
		panic(err)
	}
	primitives.SiteStateDir = dir
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
