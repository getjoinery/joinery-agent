package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"joinery-agent/xwing"
)

// The encrypted data root's key material (dataroot.go): the break-glass copy
// is the backup envelope's format, version 2 (X-Wing), so the owner's
// backup_envelope.php opens what this seals and this opens what PHP seals; a
// version-1 copy (an old X25519 recovery key) still opens and nothing new is
// sealed to one; the recipient file is refused when its fingerprint is not its
// key's; and the slots are read from the header's own metadata.

func testKeypair(t *testing.T) (secretB64 string, pub []byte) {
	t.Helper()
	seed, err := xwing.NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	p, err := xwing.PublicKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(seed), p
}

func writeRecipient(t *testing.T, dir string, pub []byte, fpr string) string {
	t.Helper()
	path := filepath.Join(dir, "recovery_recipient")
	body := "# test\npublic_key=" + base64.StdEncoding.EncodeToString(pub) + "\nfingerprint=" + fpr + "\n"
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func volumeKey() []byte {
	k := make([]byte, volumeKeyBytes)
	for i := range k {
		k[i] = byte(i * 7)
	}
	return k
}

func TestDataRootSealOpensWithTheRecoveryKey(t *testing.T) {
	dir := t.TempDir()
	secret, pub := testKeypair(t)
	recipient := writeRecipient(t, dir, pub, keyFingerprint(pub))
	rpub, fpr, err := readRecipient(recipient)
	if err != nil || fpr != keyFingerprint(pub) || !bytes.Equal(rpub, pub) {
		t.Fatalf("readRecipient: %v %s", err, fpr)
	}
	out, err := sealVolumeKey(volumeKey(), rpub, time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var env sidecarEnvelope
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatal(err)
	}
	if env.Version != 2 || env.Artifact != "data-root" || len(env.Recipients) != 1 || env.Recipients[0].Alg != "xwing" ||
		env.Recipients[0].Kind != "recovery" || env.Recipients[0].Fingerprint != fpr || env.Created != "2026-10-11T00:00:00Z" {
		t.Fatalf("the envelope is not the backup envelope's version 2 shape: %+v", env)
	}
	sidecar := filepath.Join(dir, "joinery.img.recovery")
	os.WriteFile(sidecar, out, 0600)

	key, err := openSidecar(sidecar, secret)
	if err != nil || !bytes.Equal(key, volumeKey()) {
		t.Fatalf("the recovery key does not open its own seal: %v", err)
	}
	// As pasted into a console: spaces and a newline around it.
	if key, err := openSidecar(sidecar, "  "+secret+"\n"); err != nil || !bytes.Equal(key, volumeKey()) {
		t.Fatalf("a pasted key with whitespace: %v", err)
	}
}

// A copy sealed before the X-Wing upgrade, to an old X25519 key, still opens
// with that key, in either form libsodium keeps it; nothing new is sealed to it.
func TestDataRootVersionOneStillOpens(t *testing.T) {
	dir := t.TempDir()
	p, s, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.SealAnonymous(nil, volumeKey(), p, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env := sidecarEnvelope{Version: 1, Artifact: "data-root", Cipher: "luks2-volume-key", Created: "2026-10-11T00:00:00Z",
		Recipients: []sidecarRecipient{{Kind: "recovery", Fingerprint: keyFingerprint(p[:]), Sealed: base64.StdEncoding.EncodeToString(sealed)}}}
	body, _ := json.Marshal(env)
	sidecar := filepath.Join(dir, "old.recovery")
	os.WriteFile(sidecar, body, 0600)
	if key, err := openSidecar(sidecar, base64.StdEncoding.EncodeToString(s[:])); err != nil || !bytes.Equal(key, volumeKey()) {
		t.Fatalf("an old copy does not open with its key: %v", err)
	}
	pair := base64.StdEncoding.EncodeToString(append(append([]byte{}, s[:]...), p[:]...))
	if key, err := openSidecar(sidecar, pair); err != nil || !bytes.Equal(key, volumeKey()) {
		t.Fatalf("the keypair form: %v", err)
	}
	if _, err := sealVolumeKey(volumeKey(), p[:], time.Now()); err == nil || !strings.Contains(err.Error(), "old X25519") {
		t.Fatalf("a volume key was sealed to an old key: %v", err)
	}
	if _, _, err := readRecipient(writeRecipient(t, dir, p[:], keyFingerprint(p[:]))); err != nil {
		t.Fatalf("an old recipient file is no longer read: %v", err)
	}
}

func TestDataRootSealRefusals(t *testing.T) {
	dir := t.TempDir()
	_, pub := testKeypair(t)
	other, _ := testKeypair(t)
	out, _ := sealVolumeKey(volumeKey(), pub, time.Now())
	sidecar := filepath.Join(dir, "sidecar")
	os.WriteFile(sidecar, out, 0600)

	if _, err := openSidecar(sidecar, other); err == nil || !strings.Contains(err.Error(), "does not open") {
		t.Fatalf("another recovery key opened it: %v", err)
	}
	if _, err := openSidecar(sidecar, base64.StdEncoding.EncodeToString(pub)); err == nil || !strings.Contains(err.Error(), "PUBLIC half") {
		t.Fatalf("the public half is not named as such: %v", err)
	}
	if _, err := openSidecar(sidecar, "hunter2"); err == nil || !strings.Contains(err.Error(), "not a recovery key") {
		t.Fatalf("a passphrase is not refused as one: %v", err)
	}
	if _, err := sealVolumeKey(volumeKey()[:32], pub, time.Now()); err == nil {
		t.Fatal("a 32-byte key was sealed as a volume key")
	}
	if _, _, err := readRecipient(writeRecipient(t, dir, pub, strings.Repeat("0", 64))); err == nil {
		t.Fatal("a recipient whose fingerprint is not its key's was accepted")
	}
}

// Copies sealed by the platform's PHP, in the backup envelope's format, open
// here: version 2 (SealedBox::sealV2, X-Wing) and version 1 (libsodium).
func TestDataRootOpensWhatPHPSealed(t *testing.T) {
	kv, err := readKeyValueFile("testdata/data_root_test_key.txt")
	if err != nil {
		t.Fatal(err)
	}
	for file, secret := range map[string]string{
		"testdata/data_root_sidecar_php_v2.json": kv["secret_v2"],
		"testdata/data_root_sidecar_php.json":    kv["secret"],
	} {
		key, err := openSidecar(file, secret)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for i, b := range key {
			if b != byte(i) {
				t.Fatalf("%s: byte %d is %d", file, i, b)
			}
		}
	}
}

func TestParseLuksSlots(t *testing.T) {
	meta := []byte(`{
	  "keyslots": {
	    "0": {"type": "luks2", "kdf": {"type": "pbkdf2", "hash": "sha256", "iterations": 2000000, "salt": "x"}},
	    "1": {"type": "luks2", "kdf": {"type": "pbkdf2", "hash": "sha512", "iterations": 1000, "salt": "x"}},
	    "10": {"type": "luks2", "kdf": {"type": "argon2id", "time": 4, "memory": 1048576, "cpus": 4, "salt": "x"}}
	  },
	  "tokens": {"0": {"type": "systemd-tpm2", "keyslots": ["1"]}},
	  "segments": {}, "digests": {}, "config": {}
	}`)
	slots, err := parseLuksSlots(meta)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range slots {
		got = append(got, strings.Join([]string{s.KDF, s.Hash, s.Iterations, s.Token}, " "))
	}
	want := "pbkdf2 sha256 2000000 -|pbkdf2 sha512 1000 systemd-tpm2|argon2id - 4 -"
	if strings.Join(got, "|") != want || slots[2].ID != 10 {
		t.Fatalf("got %q, want %q", strings.Join(got, "|"), want)
	}
	if s, _ := parseLuksSlots([]byte(`{"keyslots": {}, "tokens": {}}`)); len(s) != 0 {
		t.Fatal("a header with no slots lists some")
	}
	part, _ := parseLuksSlots([]byte(`{"keyslots": {"0": {"type": "luks2", "kdf": {"type": "pbkdf2", "hash": "sha256", "iterations": 2000000}},
		"1": {"type": "reencrypt", "mode": "encrypt"}}, "tokens": {}}`))
	if len(part) != 1 || part[0].ID != 0 {
		t.Fatalf("an encryption's own bookkeeping slot is listed as a key slot: %+v", part)
	}
}

func TestDataRootConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data_root")
	os.WriteFile(path, []byte("# x\nbacking=luks-file\nsource=/srv/joinery.img\nsidecar=/srv/joinery.img.recovery\n"), 0644)
	c, err := readDataRootConfig(path)
	if err != nil || !c.encrypted() || c.Source != "/srv/joinery.img" || c.Sidecar != "/srv/joinery.img.recovery" || c.device() != "/srv/joinery.img" {
		t.Fatalf("%+v %v", c, err)
	}
	os.WriteFile(path, []byte("backing=file\nsource=/srv/joinery.img\n"), 0644)
	if c, _ := readDataRootConfig(path); c.encrypted() {
		t.Fatal("a plain data root reads as encrypted")
	}
}

// A re-encryption under a new volume key takes the other key slots away and
// leaves their tokens; a chip sealed again leaves the old token. Those are
// the stale ones; a token with a live slot is not.
func TestStaleTokens(t *testing.T) {
	meta := []byte(`{
	  "keyslots": {"0": {"type": "luks2"}},
	  "tokens": {
	    "0": {"type": "systemd-tpm2", "keyslots": []},
	    "1": {"type": "systemd-tpm2", "keyslots": ["3"]},
	    "2": {"type": "systemd-tpm2", "keyslots": ["0"]}
	  }
	}`)
	ids, err := parseStaleTokens(meta)
	if err != nil || strings.Join(ids, ",") != "0,1" {
		t.Fatalf("got %v %v, want 0,1", ids, err)
	}
	if ids, _ := parseStaleTokens([]byte(`{"keyslots": {"0": {}}, "tokens": {}}`)); len(ids) != 0 {
		t.Fatalf("a header with no tokens has stale ones: %v", ids)
	}
}
