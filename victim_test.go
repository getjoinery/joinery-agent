package main

// The decommission ceremony's host side: how a victim is located from
// host-owned files, and how the approval scope keeps a decommission answer
// from ever being a restore answer.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"joinery-agent/primitives"
)

// TestDecommissionScopeIsItsOwnDomain pins the domain separation: the
// decommission scope shares NOTHING nameable with the restore scope — not the
// setting rows (its consent copy renders on the victim's own panel, not the
// restore panel), not the HKDF context, not the plaintext tag. A collision in
// any of these would let one ceremony's answer satisfy the other.
func TestDecommissionScopeIsItsOwnDomain(t *testing.T) {
	if decommissionScope.requestSetting == restoreScope.requestSetting ||
		decommissionScope.answerSetting == restoreScope.answerSetting {
		t.Fatal("decommission and restore share a settings row — one panel would render the other's consent")
	}
	if decommissionScope.infoPrefix == restoreScope.infoPrefix {
		t.Fatal("decommission and restore share an HKDF context — their challenges could be answers to each other")
	}
	if decommissionScope.plaintextTag == restoreScope.plaintextTag {
		t.Fatal("decommission and restore share a plaintext tag — the compared bytes no longer separate them")
	}
	// The PHP side (ApprovalChallenge::SCOPES) compiles the same three strings; the
	// values are pinned here so a rename on either side fails a test.
	if decommissionScope.requestSetting != "decommission_approval_request" ||
		decommissionScope.answerSetting != "decommission_approval_answer" ||
		decommissionScope.infoPrefix != "joinery-decommission-approval:" {
		t.Fatalf("decommission scope strings changed — the victim's PHP panel compiles these exact names: %+v", decommissionScope)
	}
}

// TestAScopedGateStagesIntoItsOwnRows proves a decommission-scoped gate writes
// the decommission rows and its request carries the decommission context — the
// victim's panel finds it where the victim's code looks, and never on the
// restore panel.
func TestAScopedGateStagesIntoItsOwnRows(t *testing.T) {
	store, _ := provenKeyStore(t)
	gate := newScopedApproval(store, decommissionScope)

	staged := make(chan approvalRequest, 1)
	store.onWrite = func(name, value string) {
		if name == decommissionScope.requestSetting && value != "" {
			var req approvalRequest
			if err := json.Unmarshal([]byte(value), &req); err != nil {
				t.Errorf("staged request is not readable JSON: %v", err)
				return
			}
			select {
			case staged <- req:
			default:
			}
			// Decline immediately so the test does not wait out the window.
			answer, _ := json.Marshal(approvalAnswer{JobID: 7, Declined: true})
			store.Write(decommissionScope.answerSetting, string(answer))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := gate.Require(ctx, 7, primitives.ApprovalStatement{
		Primitive: "decommission_site",
		Summary:   "This will permanently DESTROY the site scratchsite.",
	})
	if err == nil || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("a declined decommission should refuse naming the decline, got %v", err)
	}

	select {
	case req := <-staged:
		if req.Info != decommissionScope.infoPrefix {
			t.Errorf("the staged request carries context %q, want the decommission context", req.Info)
		}
		if req.Primitive != "decommission_site" {
			t.Errorf("the staged request names %q", req.Primitive)
		}
	default:
		t.Fatal("nothing was staged into the decommission request row")
	}

	if v, _ := store.Read(restoreScope.requestSetting); v != "" {
		t.Error("a decommission ceremony wrote into the RESTORE request row")
	}
}

// TestHostPostureGatesTheCeremony: only a machine with no site of its own gets
// a victim ceremony. A machine with a site must refuse to destroy a
// co-resident one.
func TestHostPostureGatesTheCeremony(t *testing.T) {
	if victimCeremonyFor(&Config{Siteless: false}) != nil {
		t.Fatal("a machine WITH a site was handed the victim ceremony")
	}
	if victimCeremonyFor(nil) != nil {
		t.Fatal("a nil config was handed the victim ceremony")
	}
	if victimCeremonyFor(&Config{Siteless: true}) == nil {
		t.Fatal("a host-posture machine was refused the victim ceremony")
	}
}

// TestTheVhostNamesTheVictimsPort: the published web port is read from the
// host-owned vhost, exactly as install.sh writes it from its proxy template.
func TestTheVhostNamesTheVictimsPort(t *testing.T) {
	vhost := `<VirtualHost *:80>
    ServerName scratchsite.example.com
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8083/
    ProxyPassReverse / http://127.0.0.1:8083/
</VirtualHost>`
	m := proxyPassPort.FindStringSubmatch(vhost)
	if m == nil || m[1] != "8083" {
		t.Fatalf("the ProxyPass port was not found: %v", m)
	}
}

// TestAMissingVhostIsARefusalNamingTheSite: a site this host does not front is
// refused before anything else is touched.
func TestAMissingVhostIsARefusal(t *testing.T) {
	_, err := victimWebPort("no-such-site-xyzzy")
	if err == nil || !primitives.Refused(err) {
		t.Fatalf("a missing vhost should refuse, got %v", err)
	}
	if !strings.Contains(err.Error(), "no-such-site-xyzzy") {
		t.Errorf("the refusal should name the site: %v", err)
	}
}

// TestVictimConfigComesFromTheConfigVolumePath: the parse is the agent's own
// narrow config regex, aimed at the volume's host-side path — proven here over
// a fixture with the exact line shape Globalvars_site.php uses.
func TestVictimConfigParsesTheVolumeConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "Globalvars_site.php")
	content := `<?php
$this->settings['dbusername'] = 'scratch_user';
$this->settings['dbname'] = 'scratchsite';
$this->settings['dbpassword'] = 'p w%27d';
$this->settings['webDir'] = 'scratchsite.example.com';
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	settings, err := parseGlobalvars(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if settings["dbname"] != "scratchsite" || settings["dbusername"] != "scratch_user" {
		t.Fatalf("config parse missed the DB identity: %+v", settings)
	}
}

// TestVictimConfigIsUnderDockersOwnRoot: the config volume is found under the
// root the daemon names, so a host with user-namespace remapping (volumes one
// directory deeper) is read the same as any other, and a root Docker cannot
// name, or names oddly, is a refusal rather than a guess.
func TestVictimConfigIsUnderDockersOwnRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "docker", "100000.100000")
	dir := filepath.Join(root, "volumes", "remapped_config", "_data")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	content := "<?php\n$this->settings['dbusername'] = 'u';\n$this->settings['dbname'] = 'remapped';\n$this->settings['dbpassword'] = 'p';\n"
	if err := os.WriteFile(filepath.Join(dir, "Globalvars_site.php"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := dockerRootDir
	defer func() { dockerRootDir = saved }()

	dockerRootDir = func() (string, error) { return root, nil }
	cfg, err := victimConfig("remapped")
	if err != nil || cfg["dbname"] != "remapped" {
		t.Fatalf("the config under a remapped root was not read: %v %+v", err, cfg)
	}

	dockerRootDir = func() (string, error) { return "", errors.New("daemon down") }
	_, err = victimConfig("remapped")
	var refusal *primitives.RefusalError
	if !errors.As(err, &refusal) || !strings.Contains(err.Error(), "did not say where it keeps") {
		t.Fatalf("an unanswered root must be a refusal, got %v", err)
	}

	for _, bad := range []string{"", "var/lib/docker", "/var/lib/../etc", "/var/lib/docker/"} {
		if _, err := checkDockerRoot(bad); err == nil {
			t.Fatalf("root %q must be refused", bad)
		}
	}
	if got, err := checkDockerRoot("/var/lib/docker/100000.100000"); err != nil || got != "/var/lib/docker/100000.100000" {
		t.Fatalf("a clean remapped root must pass: %q %v", got, err)
	}
}

// TestDockerRootSaysWhyDockerDidNotAnswer: when the docker CLI fails, the
// refusal carries what Docker said, not only an exit status.
func TestDockerRootSaysWhyDockerDidNotAnswer(t *testing.T) {
	dir := t.TempDir()
	stub := "#!/bin/sh\necho 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	_, err := dockerRootDir()
	if err == nil || !strings.Contains(err.Error(), "Cannot connect to the Docker daemon") {
		t.Fatalf("the refusal must carry Docker's own words, got %v", err)
	}
}

// TestVictimStringsAreInertDisplayData: container-controlled bytes reaching a
// statement are stripped of control characters and capped — a victim cannot
// smuggle terminal escapes or a novel into the operator's screen or the log.
func TestVictimStringsAreInertDisplayData(t *testing.T) {
	if got := displaySafe("evil\x1b[2Jname\r\n", 100); got != "evil[2Jname" {
		t.Errorf("control bytes survived: %q", got)
	}
	if got := displaySafe(strings.Repeat("a", 500), 100); len(got) > 100 {
		t.Errorf("length cap did not hold: %d bytes", len(got))
	}
}

// TestADSNValueCannotInjectKeys: a victim's password is quoted into the DSN,
// so a value with a space or quote is a password, not a second DSN key.
func TestADSNValueCannotInjectKeys(t *testing.T) {
	if got := quoteDSNValue(`x' sslmode='require`); got != `'x\' sslmode=\'require'` {
		t.Errorf("quoting is wrong: %s", got)
	}
}
