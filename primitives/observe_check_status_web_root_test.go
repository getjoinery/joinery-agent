package primitives

import (
	"context"
	"testing"
)

// check_status names the site's web root, so the plane can fill a node record
// made without one. A machine with no site names none.
func TestCheckStatusReportsTheWebRoot(t *testing.T) {
	root := t.TempDir()
	result, err := runCheckStatus(context.Background(), &ExecEnv{WebRoot: root}, Params{})
	if err != nil {
		t.Fatal(err)
	}
	if result["web_root"] != root {
		t.Fatalf("web_root = %v, want %s", result["web_root"], root)
	}

	siteless, err := runCheckStatus(context.Background(), &ExecEnv{}, Params{})
	if err != nil {
		t.Fatal(err)
	}
	if _, has := siteless["web_root"]; has {
		t.Fatalf("a siteless machine reported a web root: %v", siteless["web_root"])
	}
}
