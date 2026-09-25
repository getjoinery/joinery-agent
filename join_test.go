package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// THE FINGERPRINT CONTRACT, pinned. The management node computes the same
// value in AgentJoinRequest::fingerprint() and its own suite pins this exact
// vector (agent_channel_test.php) — the two panels showing the same
// fingerprint for the same key is the entire security of the join, so a drift
// on either side must fail a suite before it strands an enrollment at
// mismatched fingerprints.
//
// Vector: the 32 bytes 0x00..0x1f → first 16 hex chars of their SHA-256.
func TestFingerprintContractIsPinned(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	const want = "630dcd2966c43366"
	if got := Fingerprint(raw); got != want {
		t.Fatalf("Fingerprint(0x00..0x1f) = %q, want %q — this breaks the cross-side contract; "+
			"fix the drift, never the pin", got, want)
	}
}

// A restart mid-join must keep the same keypair — the fingerprint on the node
// panel is what a human is comparing on the management node, and a fresh key
// on every restart would make that comparison a moving target.
func TestStagedIdentitySurvivesReload(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_IDENTITY_PATH", filepath.Join(dir, "node_identity.json"))

	pub, priv, err := GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	staged := &stagedIdentity{
		PlaneURL: "https://mn.example", PublicKey: pub, PrivateKey: priv,
		RequestedTime: "2026-08-26 00:00:00",
	}
	if err := staged.save(); err != nil {
		t.Fatal(err)
	}

	loaded := loadStagedIdentity()
	if loaded == nil {
		t.Fatal("staged identity did not load back")
	}
	if loaded.PublicKey != pub || loaded.PrivateKey != priv {
		t.Fatal("staged identity reloaded with a different keypair")
	}
	if loaded.PlaneURL != staged.PlaneURL || loaded.RequestedTime != staged.RequestedTime {
		t.Fatal("staged identity lost the ask it belongs to")
	}

	// The staged file holds a private key: it must be unreadable beyond root.
	info, err := os.Stat(stagedIdentityPath())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("staged identity file mode %04o is readable beyond its owner", perm)
	}

	discardStagedIdentity()
	if loadStagedIdentity() != nil {
		t.Fatal("discard left the staged identity behind")
	}
}

// A site-driven join claims the site's name; only a siteless machine falls
// back to the OS hostname.
func TestClaimedNameIsTheSiteNameWhenThereIsASite(t *testing.T) {
	if got := claimedNameFor("/var/www/html/keyless9"); got != "keyless9" {
		t.Fatalf("site root /var/www/html/keyless9 should claim keyless9, got %q", got)
	}
	if got := claimedNameFor("/var/www/html/keyless9/"); got != "keyless9" {
		t.Fatalf("a trailing slash must not change the name, got %q", got)
	}
	host, _ := os.Hostname()
	if got := claimedNameFor(""); got != host {
		t.Fatalf("a siteless machine claims its hostname %q, got %q", host, got)
	}
	if got := claimedNameFor("/"); got != host {
		t.Fatalf("a site root of / names nothing and falls back to the hostname, got %q", got)
	}
}

// A join names the site's web root, so the plane makes a node that hosts a
// site; a siteless machine names none. Without it the plane made a node with
// no backup and no recovery-key report.
func TestTheJoinNamesTheWebRoot(t *testing.T) {
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = nil
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		planeReply(w, map[string]interface{}{"status": "pending", "fingerprint": "x"})
	}))
	defer srv.Close()

	pub, priv, err := GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	staged := &stagedIdentity{PlaneURL: srv.URL, PublicKey: pub, PrivateKey: priv}
	ask := func(cfg *Config, sendJoin bool) map[string]interface{} {
		w := &JoinWatcher{cfg: cfg, agentVersion: "test"}
		if _, err := w.callJoin(context.Background(), srv.URL, staged, "site1", sendJoin); err != nil {
			t.Fatal(err)
		}
		return got
	}

	site := &Config{SiteRoot: "/var/www/html/site1", WebRoot: "/var/www/html/site1/public_html"}
	if body := ask(site, true); body["web_root"] != "/var/www/html/site1/public_html" {
		t.Fatalf("a site's join carries web_root = %v", body["web_root"])
	}
	if body := ask(site, false); body["web_root"] != nil {
		t.Fatalf("the status poll carries only the key, got web_root = %v", body["web_root"])
	}
	if body := ask(&Config{Siteless: true}, true); body["web_root"] != nil {
		t.Fatalf("a siteless machine's join carries web_root = %v", body["web_root"])
	}
}
