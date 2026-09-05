package primitives

import (
	"strings"
	"testing"
)

// publish_upgrade runs the one script in the vocabulary that signs code every
// node in the fleet will run as root. What matters is that the plane can say
// only two things to it — a version and the notes — and that both arrive in
// the order the publisher reads them.

func publishUpgradeParams(t *testing.T, raw map[string]interface{}) (Params, error) {
	t.Helper()
	p, ok := Lookup("publish_upgrade")
	if !ok {
		t.Fatal("publish_upgrade should be registered")
	}
	return Validate(p.Params, raw)
}

func validPublishParams() map[string]interface{} {
	return map[string]interface{}{
		"version": "0.8.371",
		"notes":   "Fix empty site backups, detect them, and let the dashboard approve a join",
	}
}

func TestAWellFormedPublishIsAccepted(t *testing.T) {
	if _, err := publishUpgradeParams(t, validPublishParams()); err != nil {
		t.Fatalf("a well-formed publish should validate: %v", err)
	}
}

func TestAPublishNamesItsVersionExactly(t *testing.T) {
	// The publisher reads its first argument as a version only when it looks
	// like one. The vocabulary requires the full three-part number so argv
	// never has to be guessed at.
	for _, bad := range []string{"", "0.8", "v0.8.371", "0.8.371-rc1", "0.8.371 ", "latest", "0.8.371;id"} {
		params := validPublishParams()
		params["version"] = bad
		if _, err := publishUpgradeParams(t, params); err == nil {
			t.Errorf("version %q should be refused", bad)
		}
	}
	params := validPublishParams()
	delete(params, "version")
	if _, err := publishUpgradeParams(t, params); err == nil {
		t.Error("a publish with no version must be refused, not auto-numbered on the node")
	}
}

func TestAPublishNeedsNotesAndBoundsThem(t *testing.T) {
	params := validPublishParams()
	delete(params, "notes")
	if _, err := publishUpgradeParams(t, params); err == nil {
		t.Error("a publish with no release notes must be refused")
	}

	params = validPublishParams()
	params["notes"] = strings.Repeat("x", publishNotesMaxLen+1)
	if _, err := publishUpgradeParams(t, params); err == nil {
		t.Error("release notes past the ceiling must be refused")
	}
}

func TestNothingElseReachesThePublisher(t *testing.T) {
	// There is no parameter through which the plane could name a source
	// checkout, a signing key, an output directory or a flag.
	for _, field := range []string{"source_path", "signing_key", "output_dir", "flags", "web_root"} {
		params := validPublishParams()
		params[field] = "anything"
		if _, err := publishUpgradeParams(t, params); err == nil {
			t.Errorf("a job carrying %q must be refused as out-of-vocabulary", field)
		}
	}
}

func TestThePublisherIsCalledVersionFirstThenNotes(t *testing.T) {
	// publish_upgrade.php: argv[1] is the version when it looks like one,
	// argv[2] the notes. Both are always present, so the order is the contract.
	p, _ := Lookup("publish_upgrade")
	params, err := publishUpgradeParams(t, validPublishParams())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	argv, err := resolveArgs(p.Script.Args, params)
	if err != nil {
		t.Fatalf("resolve argv: %v", err)
	}
	want := []string{"0.8.371", validPublishParams()["notes"].(string)}
	if len(argv) != len(want) || argv[0] != want[0] || argv[1] != want[1] {
		t.Fatalf("argv = %q, want %q", argv, want)
	}
	if p.Script.ScriptPath != publishScript || !strings.HasSuffix(p.Script.ScriptPath, "plugins/server_manager/includes/publish_upgrade.php") {
		t.Fatalf("the primitive must run the plugin's publisher, got %q", p.Script.ScriptPath)
	}
	if p.Script.Interpreter != "/usr/bin/php" {
		t.Fatalf("interpreter = %q", p.Script.Interpreter)
	}
}
