package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"joinery-agent/primitives"
)

// The agent key lent to the copy words (specs/site_copy.md WP4) signs only in
// its own domain, never in the request domain the management node verifies.
func TestTheLentKeyNeverSignsARequest(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k := nodeKey{id: &NodeIdentity{private: priv}}

	request := SigningMessage("POST", "/x", 7, "t", "n", "b")
	if _, err := k.SignDomain(requestSigningDomain, []byte(request)); err == nil {
		t.Fatal("signed under the request domain")
	}
	if _, err := k.SignDomain(primitives.CopyExportDomain, []byte(request)); err == nil {
		t.Fatal("signed a request message under another domain's name")
	}
	if _, err := k.SignDomain("a\nb", []byte("a\nb\nx")); err == nil {
		t.Fatal("signed under a domain with a newline in it")
	}
	msg := []byte(primitives.CopyExportDomain + "\nbody")
	sig, err := k.SignDomain(primitives.CopyExportDomain, msg)
	if err != nil || !ed25519.Verify(priv.Public().(ed25519.PublicKey), msg, sig) {
		t.Fatalf("did not sign its own domain: %v", err)
	}

	blob, err := primitives.OpenSealedToAgentKey(priv, []byte("short"))
	if err == nil || blob != nil {
		t.Fatal("opened a short seal")
	}
}

// The export scope is its own: its rows and context differ from every other
// scope's, so an answer for one act can never release another.
func TestTheExportScopeIsItsOwn(t *testing.T) {
	for _, other := range []approvalScope{restoreScope, decommissionScope} {
		if exportScope.requestSetting == other.requestSetting || exportScope.answerSetting == other.answerSetting ||
			exportScope.infoPrefix == other.infoPrefix || exportScope.plaintextTag == other.plaintextTag {
			t.Errorf("the export scope shares a row or context with %s", other.act)
		}
	}
	if NewExportApproval(nil).scoped().act != "copy export" {
		t.Error("NewExportApproval does not build the export scope")
	}
}
