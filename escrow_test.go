package main

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// The escrow contract, from this side (the plane's half is
// plugins/server_manager/tests/data_root_escrow_test.php): the message an
// unlock identity signs, byte for byte; the report key, derived from the
// volume key; and a request carrying both, as the holder reads it.

func TestEscrowSigningMessageIsPinned(t *testing.T) {
	got := escrowSigningMessage("POST", "/api/v1/agent/escrow/unlock", "ID", "1700000000", "NONCE", "HASH")
	want := "joinery-unlock-v1\nPOST\n/api/v1/agent/escrow/unlock\nID\n1700000000\nNONCE\nHASH"
	if got != want {
		t.Fatalf("got %q, want %q (EscrowEndpoint::signing_message)", got, want)
	}
}

func TestEscrowReportKeyIsTheVolumeKeys(t *testing.T) {
	vk := volumeKey()
	m := hmac.New(sha256.New, vk)
	m.Write([]byte("joinery-escrow-report-v1"))
	if hex.EncodeToString(escrowReportKey(vk)) != hex.EncodeToString(m.Sum(nil)) {
		t.Fatal("the report key is not HMAC-SHA256(volume key, joinery-escrow-report-v1)")
	}
	other := append([]byte{}, vk...)
	other[0] ^= 1
	if hex.EncodeToString(escrowReportKey(other)) == hex.EncodeToString(escrowReportKey(vk)) {
		t.Fatal("another volume key gives the same report key")
	}
}

func TestEscrowRequestIsSignedAndMACed(t *testing.T) {
	id, err := loadUnlockIdentity(filepath.Join(t.TempDir(), "unlock_identity"), true)
	if err != nil {
		t.Fatal(err)
	}
	again, err := loadUnlockIdentity(filepath.Join(t.TempDir(), "x"), false)
	if err == nil || again != nil {
		t.Fatal("a missing identity was not refused without mint")
	}
	reportKey := escrowReportKey(volumeKey())
	var seen *http.Request
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
		body, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{"api_version":"1.0","data":{"status":"recorded"}}`))
	}))
	defer srv.Close()
	if _, err := escrowRequestMAC(context.Background(), srv.Client(), srv.URL, id, "report", map[string]interface{}{"state": "unlocked"}, reportKey); err != nil {
		t.Fatal(err)
	}
	if seen.URL.Path != "/api/v1/agent/escrow/report" {
		t.Fatalf("path %s", seen.URL.Path)
	}
	sum := sha256.Sum256(body)
	msg := escrowSigningMessage("POST", seen.URL.Path, seen.Header.Get("X-Joinery-Unlock-Identity"),
		seen.Header.Get("X-Joinery-Unlock-Timestamp"), seen.Header.Get("X-Joinery-Unlock-Nonce"), hex.EncodeToString(sum[:]))
	sig, _ := base64.StdEncoding.DecodeString(seen.Header.Get("X-Joinery-Unlock-Signature"))
	pub, _ := base64.StdEncoding.DecodeString(seen.Header.Get("X-Joinery-Unlock-Identity"))
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(msg), sig) {
		t.Fatal("the holder could not verify the request's signature")
	}
	m := hmac.New(sha256.New, reportKey)
	m.Write(body)
	if seen.Header.Get("X-Joinery-Unlock-Report-Mac") != base64.StdEncoding.EncodeToString(m.Sum(nil)) {
		t.Fatal("the report key's MAC is not over the body")
	}
}

func TestUnlockIdentityPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unlock_identity")
	a, err := loadUnlockIdentity(path, true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadUnlockIdentity(path, true)
	if err != nil || a.PublicB64() != b.PublicB64() {
		t.Fatalf("a second load minted another identity: %v", err)
	}
	if len(a.Fingerprint()) != 16 {
		t.Fatal("the fingerprint is not the 16-hex form both panels show")
	}
}

// O7, T-E11: the escrow fetch offers the post-quantum key exchange. The
// module's go line (1.24 or later) is what turns X25519MLKEM768 on by
// default; this catches a go line moved back.
func TestEscrowClientOffersPostQuantumKeyExchange(t *testing.T) {
	var offered []tls.CurveID
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		offered = hello.SupportedCurves
		return nil, nil
	}}
	srv.StartTLS()
	defer srv.Close()
	client := newEscrowClient()
	client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, c := range offered {
		if c == tls.X25519MLKEM768 {
			return
		}
	}
	t.Fatalf("the escrow client offers %v, without X25519MLKEM768", offered)
}

// A person approving an enrolment by sight must recognise the machine: an
// image's own hostname says nothing (B21).
func TestEscrowMachineNameSkipsImageHostnames(t *testing.T) {
	for _, h := range []string{"", "localhost", "LOCALHOST", "localhost.localdomain", "ubuntu", "debian"} {
		if meaningfulHostname(h) {
			t.Errorf("%q should not name a machine", h)
		}
	}
	for _, h := range []string{"mgr-a", "li1234-56.members.linode.com", "getjoinery"} {
		if !meaningfulHostname(h) {
			t.Errorf("%q names a machine", h)
		}
	}
	if n := escrowMachineName(); n == "" || n == "localhost" {
		t.Errorf("escrowMachineName() = %q", n)
	}
}

// A data root is enrolled only when encrypted and with no run under way: a
// change of key's mapping may hold either key (B67).
func TestEnrolRefusedWhileARunIsUnderWay(t *testing.T) {
	plain := dataRootConfig{Backing: "file", Source: "/srv/joinery.img"}
	if enrolRefusal(plain) == nil {
		t.Fatal("a plain data root was not refused")
	}
	enc := dataRootConfig{Backing: "luks-file", Source: "/srv/joinery.img", Sidecar: "/srv/joinery.img.recovery"}
	if err := enrolRefusal(enc); err != nil {
		t.Fatalf("an encrypted data root with no run was refused: %v", err)
	}
	for _, mode := range []string{"encrypt", "decrypt", "reencrypt"} {
		c := enc
		c.Reencrypt = mode
		err := enrolRefusal(c)
		if err == nil || !strings.Contains(err.Error(), mode+"ion is running") {
			t.Fatalf("%s under way: %v", mode, err)
		}
	}
}
