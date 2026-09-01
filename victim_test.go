package main

// The decommission ceremony's host side: how a victim is located from
// host-owned files, and how the approval scope keeps a decommission answer
// from ever being a restore answer.

import (
	"context"
	"encoding/json"
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
	// The PHP side (DecommissionApproval) compiles the same three strings; the
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
