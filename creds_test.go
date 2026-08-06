package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Golden vectors produced by the PHP includes/SecretBox.php wire format, so
// these assert cross-language parity, not Go self-consistency. testKey is a
// throwaway key generated for the fixtures — not a real secret.
const (
	testKey        = "7kS/o0STt/vRtkaGccyfbXhUe/DDwoJqgHElGftouto="
	sodiumBlob     = "v1.sodium.Dm-AOBmVR4ebhN2mfKzsSE48iRCVFFUB.T4vGODmCtrTpZli55-aJjxcqt5s_nwFLgQ7biTBDEafD7_-2goRalzMFTvBhNAAuepubeIm8DyqTAcJFV-8GW4XF6iGA7dAwbpfVekxDkMxWlpWiCyaSa9XsEmzvEfA"
	sodiumPlain    = `{"access_key":"AKIA_PUB","secret_key":"sk_topsecret_42","region":"us-west-002"}`
	aesgcmBlob     = "v1.aesgcm.C_ia9DuQyogtzvIF.dvHAvtI4AsrYkFwQsEd26zbeE1wNbc3XcMMjy4zdXZpMohE"
	aesgcmPlain    = "hello-aesgcm-secret"
)

func mustKey(t *testing.T) *[32]byte {
	t.Helper()
	k, err := decodeSecretBoxKey(testKey)
	if err != nil {
		t.Fatalf("decodeSecretBoxKey: %v", err)
	}
	return k
}

func TestSecretBoxDecryptSodium(t *testing.T) {
	got, err := secretBoxDecrypt(sodiumBlob, mustKey(t))
	if err != nil {
		t.Fatalf("decrypt sodium: %v", err)
	}
	if got != sodiumPlain {
		t.Fatalf("sodium plaintext mismatch:\n got %q\nwant %q", got, sodiumPlain)
	}
}

func TestSecretBoxDecryptAESGCM(t *testing.T) {
	got, err := secretBoxDecrypt(aesgcmBlob, mustKey(t))
	if err != nil {
		t.Fatalf("decrypt aesgcm: %v", err)
	}
	if got != aesgcmPlain {
		t.Fatalf("aesgcm plaintext mismatch: got %q want %q", got, aesgcmPlain)
	}
}

func TestSecretBoxDecryptWrongKeyFails(t *testing.T) {
	other, _ := decodeSecretBoxKey(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if _, err := secretBoxDecrypt(sodiumBlob, other); err == nil {
		t.Fatal("expected decrypt to fail with the wrong key")
	}
}

func TestResolveTargetCredsSealed(t *testing.T) {
	sealed := `{"enc":"` + sodiumBlob + `"}`
	got, err := resolveTargetCredsJSON(sealed, mustKey(t))
	if err != nil {
		t.Fatalf("resolve sealed: %v", err)
	}
	if got != sodiumPlain {
		t.Fatalf("sealed resolve mismatch:\n got %q\nwant %q", got, sodiumPlain)
	}
}

func TestResolveTargetCredsLegacyPlaintext(t *testing.T) {
	// A pre-encryption plaintext credential object passes through untouched,
	// even with no key configured.
	legacy := `{"access_key":"PUB","secret_key":"legacy"}`
	got, err := resolveTargetCredsJSON(legacy, nil)
	if err != nil {
		t.Fatalf("resolve legacy: %v", err)
	}
	if got != legacy {
		t.Fatalf("legacy passthrough mismatch: got %q want %q", got, legacy)
	}
}

func TestResolveSealedWithoutKeyFails(t *testing.T) {
	sealed := `{"enc":"` + sodiumBlob + `"}`
	if _, err := resolveTargetCredsJSON(sealed, nil); err == nil {
		t.Fatal("expected sealed resolve to fail without a key")
	}
}

func TestSubstituteCredPlaceholders(t *testing.T) {
	cmd := "php -- upload <<'EOF'\n$creds = json_decode(base64_decode('__SM_CREDS_7__'), true);\n$bucket = 'b';\nEOF"

	load := func(id int64) (string, error) {
		if id != 7 {
			t.Fatalf("unexpected target id %d", id)
		}
		return `{"enc":"` + sodiumBlob + `"}`, nil
	}

	noNode := func(int64) (string, error) {
		t.Fatal("node loader must not be called for a main-slot token")
		return "", nil
	}
	out, err := substituteCredPlaceholders(cmd, mustKey(t), load, noNode)
	if err != nil {
		t.Fatalf("substitute: %v", err)
	}
	if strings.Contains(out, "__SM_CREDS_7__") {
		t.Fatal("placeholder token was not replaced")
	}
	if strings.Contains(out, "sk_topsecret_42") {
		t.Fatal("plaintext secret must not appear literally in the command (it is base64 of the JSON)")
	}

	// The replacement is base64(json(creds)); decode it back and confirm.
	start := strings.Index(out, "base64_decode('") + len("base64_decode('")
	end := strings.Index(out[start:], "'")
	b64 := out[start : start+end]
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("substituted value is not valid base64: %v", err)
	}
	var creds map[string]string
	if err := json.Unmarshal(decoded, &creds); err != nil {
		t.Fatalf("decoded value is not creds JSON: %v", err)
	}
	if creds["secret_key"] != "sk_topsecret_42" {
		t.Fatalf("resolved secret_key mismatch: got %q", creds["secret_key"])
	}
}

func TestSubstituteNoPlaceholderIsNoop(t *testing.T) {
	cmd := "echo hello"
	never := func(int64) (string, error) {
		t.Fatal("loader must not be called when there is no placeholder")
		return "", nil
	}
	out, err := substituteCredPlaceholders(cmd, mustKey(t), never, never)
	if err != nil || out != cmd {
		t.Fatalf("no-op expected, got out=%q err=%v", out, err)
	}
}

func TestSubstituteNodeCredPlaceholder(t *testing.T) {
	// A node token resolves from the NODE slot only. The main loader must not
	// be touched — resolving the wrong slot would hand a node the
	// delete-capable key the whole split exists to keep away from it.
	cmd := `$creds = json_decode(base64_decode('__SM_NODE_CREDS_7__'), true);`

	noMain := func(int64) (string, error) {
		t.Fatal("main loader must not be called for a node-slot token")
		return "", nil
	}
	loadNode := func(id int64) (string, error) {
		if id != 7 {
			t.Fatalf("unexpected target id %d", id)
		}
		return `{"enc":"` + sodiumBlob + `"}`, nil
	}

	out, err := substituteCredPlaceholders(cmd, mustKey(t), noMain, loadNode)
	if err != nil {
		t.Fatalf("substitute node token: %v", err)
	}
	if strings.Contains(out, "__SM_NODE_CREDS_7__") || strings.Contains(out, "__SM_CREDS_7__") {
		t.Fatalf("node token was not fully replaced: %q", out)
	}

	start := strings.Index(out, "base64_decode('") + len("base64_decode('")
	end := strings.Index(out[start:], "'")
	decoded, err := base64.StdEncoding.DecodeString(out[start : start+end])
	if err != nil {
		t.Fatalf("substituted value is not valid base64: %v", err)
	}
	var creds map[string]string
	if err := json.Unmarshal(decoded, &creds); err != nil {
		t.Fatalf("decoded value is not creds JSON: %v", err)
	}
	if creds["secret_key"] != "sk_topsecret_42" {
		t.Fatalf("resolved secret_key mismatch: got %q", creds["secret_key"])
	}
}

func TestSubstituteNodeCredEmptySlotFails(t *testing.T) {
	// The builder only emits a node token while the slot is filled, so an
	// empty slot at run time means it was cleared after the job was built.
	// The step must fail — never fall back to the main credential.
	cmd := `x __SM_NODE_CREDS_3__ y`
	noMain := func(int64) (string, error) {
		t.Fatal("main loader must not be called as a fallback")
		return "", nil
	}
	loadNode := func(int64) (string, error) {
		return "", fmt.Errorf("backup target #3 has no node credentials configured")
	}
	if _, err := substituteCredPlaceholders(cmd, mustKey(t), noMain, loadNode); err == nil {
		t.Fatal("expected an empty node slot to fail the step")
	}
}

func TestSubstituteBothTokensResolveTheirOwnSlots(t *testing.T) {
	cmd := `main='__SM_CREDS_7__' node='__SM_NODE_CREDS_7__'`
	loadMain := func(int64) (string, error) { return `{"access_key":"MAIN"}`, nil }
	loadNode := func(int64) (string, error) { return `{"access_key":"NODE"}`, nil }

	out, err := substituteCredPlaceholders(cmd, mustKey(t), loadMain, loadNode)
	if err != nil {
		t.Fatalf("substitute both: %v", err)
	}
	wantMain := base64.StdEncoding.EncodeToString([]byte(`{"access_key":"MAIN"}`))
	wantNode := base64.StdEncoding.EncodeToString([]byte(`{"access_key":"NODE"}`))
	if !strings.Contains(out, "main='"+wantMain+"'") {
		t.Fatalf("main token resolved wrongly: %q", out)
	}
	if !strings.Contains(out, "node='"+wantNode+"'") {
		t.Fatalf("node token resolved wrongly: %q", out)
	}
}
