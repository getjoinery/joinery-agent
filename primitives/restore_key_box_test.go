package primitives

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// keyBoxChain stages a chain another server made, as stage_chain leaves one:
// its manifest, recorded in this machine's ledger as handed over, sealed to
// that server's key and to the site's recovery key, and no chain.key.
type keyBoxChain struct {
	env             *ExecEnv
	work            string
	recoveryPriv    []byte
	recoveryPub     []byte
	dataKey         string
	ephemeral       []byte
	withRecoveryBox bool
}

func newKeyBoxChain(t *testing.T, withRecoveryBox bool) *keyBoxChain {
	t.Helper()
	const id = "chain-20260807_231507"
	c := &keyBoxChain{env: restoreEnv(t), withRecoveryBox: withRecoveryBox}
	c.work = filepath.Join(c.env.SiteRoot, "backups", chainWorkspacePrefix+id)
	if err := os.MkdirAll(c.work, 0o700); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c.recoveryPriv, c.recoveryPub = priv[:], pub[:]
	otherServer, _, _ := box.GenerateKey(rand.Reader)
	c.dataKey = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	forRecovery, _ := box.SealAnonymous(nil, []byte(c.dataKey), pub, rand.Reader)
	forServer, _ := box.SealAnonymous(nil, []byte(c.dataKey), otherServer, rand.Reader)
	c.ephemeral = forRecovery[:32]
	fp := sha256.Sum256(pub[:])
	recipients := []map[string]string{{"kind": "site", "fingerprint": strings.Repeat("0", 64),
		"sealed": base64.StdEncoding.EncodeToString(forServer)}}
	if withRecoveryBox {
		recipients = append(recipients, map[string]string{"kind": "recovery", "fingerprint": hex.EncodeToString(fp[:]),
			"sealed": base64.StdEncoding.EncodeToString(forRecovery)})
	}
	manifest, _ := json.Marshal(map[string]interface{}{"chain_id": id, "envelope": map[string]interface{}{"recipients": recipients}})
	if err := os.WriteFile(filepath.Join(c.work, chainManifestFile), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(manifest)
	ledger, _ := json.Marshal(map[string]ledgerEntry{id + "/" + chainManifestFile: {SHA256: hex.EncodeToString(sum[:]),
		Bytes: int64(len(manifest)), UploadedTime: "2026-08-07 23:30:00", Source: "handed_over"}})
	if err := os.WriteFile(ledgerPath(c.env, ProfileManager), ledger, 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

// share is the operator's browser: the X25519 of a recovery key with the
// box's ephemeral key.
func (c *keyBoxChain) share(t *testing.T, priv []byte) []byte {
	t.Helper()
	s, err := curve25519.X25519(priv, c.ephemeral)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (c *keyBoxChain) describe(t *testing.T) (ApprovalStatement, error) {
	t.Helper()
	p := restorePrimitive(t, "restore_chain")
	params, err := Validate(p.Params, validRestoreParams("restore_chain"))
	if err != nil {
		t.Fatal(err)
	}
	return describeRestoreChain(context.Background(), c.env, params)
}

func TestAChainAnotherServerMadeIsApprovedWithItsKeyOpened(t *testing.T) {
	c := newKeyBoxChain(t, true)
	st, err := c.describe(t)
	if err != nil {
		t.Fatalf("a staged chain with a recovery box should be put to the operator: %v", err)
	}
	if st.KeyBox == nil {
		t.Fatal("the statement carries no key box, so the approval could not open the chain's key")
	}
	fp := sha256.Sum256(c.recoveryPub)
	if st.KeyBox.RecoveryFingerprint != hex.EncodeToString(fp[:]) ||
		st.KeyBox.EphemeralPublic != base64.StdEncoding.EncodeToString(c.ephemeral) {
		t.Errorf("the key box names %+v", st.KeyBox)
	}
	facts := map[string]string{}
	for _, f := range st.Facts {
		facts[f.Label] = f.Value
	}
	if !strings.Contains(facts["Backup key"], "recovery key") || !strings.Contains(facts["Backup key"], hex.EncodeToString(fp[:])[:16]) {
		t.Errorf("the operator is not told the backup opens with their recovery key: %q", facts["Backup key"])
	}
	if !strings.Contains(facts["Made by"], "before it moved here") {
		t.Errorf("the operator is not told another server made it: %q", facts["Made by"])
	}
	body, _ := json.Marshal(st)
	var bound struct {
		KeyBox map[string]interface{} `json:"key_box"`
	}
	_ = json.Unmarshal(body, &bound)
	if len(bound.KeyBox) != 2 || bound.KeyBox["ephemeral_public"] != st.KeyBox.EphemeralPublic ||
		bound.KeyBox["recovery_fingerprint"] != st.KeyBox.RecoveryFingerprint {
		t.Errorf("the statement the challenge is bound to should carry the box and nothing else of it: %s", body)
	}

	// Before the approval the restore has no key, and refuses.
	if _, err := chainArgs(t, c.env, validRestoreParams("restore_chain")); !Refused(err) {
		t.Fatalf("restored with no key: %v", err)
	}
	if err := st.KeyBox.Open(c.share(t, c.recoveryPriv), c.recoveryPub); err != nil {
		t.Fatalf("the recovery key's value did not open the box: %v", err)
	}
	key, err := os.ReadFile(filepath.Join(c.work, chainKeyFile))
	if err != nil || string(key) != c.dataKey {
		t.Fatalf("chain.key is %q (%v), want the chain's data key", key, err)
	}
	if info, _ := os.Stat(filepath.Join(c.work, chainKeyFile)); info == nil || info.Mode().Perm() != 0o600 {
		t.Error("chain.key is not 0600")
	}
	if _, err := chainArgs(t, c.env, validRestoreParams("restore_chain")); err != nil {
		t.Errorf("with the key opened, the restore composes: %v", err)
	}
}

func TestAKeyBoxOpensOnlyWithTheKeyItIsSealedTo(t *testing.T) {
	c := newKeyBoxChain(t, true)
	st, err := c.describe(t)
	if err != nil || st.KeyBox == nil {
		t.Fatalf("no key box: %v", err)
	}
	otherPub, otherPriv, _ := box.GenerateKey(rand.Reader)
	if err := st.KeyBox.Open(c.share(t, otherPriv[:]), otherPub[:]); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("another recovery key was taken: %v", err)
	}
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	if err := st.KeyBox.Open(random, c.recoveryPub); err == nil {
		t.Error("a value that is not the recovery key's opened the box")
	}
	if _, err := os.Stat(filepath.Join(c.work, chainKeyFile)); !os.IsNotExist(err) {
		t.Error("a refused answer left a key behind")
	}
}

func TestAChainStagedWithItsOwnKeyAsksForNone(t *testing.T) {
	c := newKeyBoxChain(t, true)
	if err := os.WriteFile(filepath.Join(c.work, chainKeyFile), []byte(c.dataKey), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := c.describe(t)
	if err != nil || st.KeyBox != nil {
		t.Errorf("a chain whose key this machine recovered asked for a key box: %+v %v", st.KeyBox, err)
	}
	for _, f := range st.Facts {
		if f.Label == "Backup key" {
			t.Errorf("a chain this machine opened says it needs the recovery key: %q", f.Value)
		}
	}
}

func TestAChainWithNoKeyAndNoRecoveryBoxIsRefused(t *testing.T) {
	c := newKeyBoxChain(t, false)
	if _, err := c.describe(t); !Refused(err) || !strings.Contains(err.Error(), "recovery key") {
		t.Errorf("a chain nothing here can open was put to the operator: %v", err)
	}
}
