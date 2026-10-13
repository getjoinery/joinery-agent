package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// The encrypted data root's key material
// (specs/hosted_data_promise_disk_encryption.md D1, D2, D2a).
//
// joinery_data_root.sh makes and grows the volume; what it cannot do in a
// shell is the sealed-box arithmetic, so it asks this binary, which is on the
// root disk of every encrypted machine and needs nothing from the data root.
//
// THE BREAK-GLASS COPY is the volume key sealed to a recovery public key with
// libsodium's crypto_box_seal, written in the same envelope a backup's data
// key uses (BackupEnvelope.php, version 1). So the owner opens it with the
// tool they already have, `backup_envelope.php open --sidecar ...
// --private recovery.key`, and this binary opens it with the same recovery
// key pasted at the console (unlock.go).
//
// THE RECIPIENT is a file of its own, /etc/joinery/data-root/recovery_recipient:
// the public key and its fingerprint, the sha256 of its raw bytes, which is
// what the Backups page and the node page show. Only a key the site or the
// operator has proven is ever written there, by the install or the converger;
// this binary only refuses one whose fingerprint does not match it.

const (
	dataRootConfPath     = "/etc/joinery/data_root"
	dataRootMapping      = "joinery-data"
	dataRootMapperPath   = "/dev/mapper/" + dataRootMapping
	dataRootOpenedByPath = "/run/joinery/data-root.opened-by"
	// The TPM2 chip did not open the volume at this boot.
	dataRootTPM2FailedPath = "/run/joinery/data-root.tpm2-failed"
	sidecarVersion         = 1
	sidecarArtifact        = "data-root"
	sidecarCipher          = "luks2-volume-key"
	// A LUKS2 volume key of the standard configuration: 512 bits.
	volumeKeyBytes = 64
)

type sidecarEnvelope struct {
	Version    int                `json:"version"`
	Artifact   string             `json:"artifact"`
	Cipher     string             `json:"cipher"`
	Created    string             `json:"created"`
	Recipients []sidecarRecipient `json:"recipients"`
}

type sidecarRecipient struct {
	Kind        string `json:"kind"`
	Fingerprint string `json:"fingerprint"`
	Sealed      string `json:"sealed"`
}

// dataRootConfig is /etc/joinery/data_root, which joinery_data_root.sh writes.
type dataRootConfig struct {
	Backing string // file, device, luks-file, luks-device
	Source  string
	UUID    string
	Sidecar string
	// An encryption or its undo running (D5, D8): which, the key slot that
	// drives it, that slot's secret sealed to the recovery key, and for a
	// decryption the header it was exported to, which the device opens with.
	Reencrypt      string
	DrivingSlot    int
	DrivingSidecar string
	DecryptHeader  string
}

// headerArgs is what a cryptsetup call on the volume needs for its header.
func (c dataRootConfig) headerArgs() []string {
	if c.Reencrypt == "decrypt" && c.DecryptHeader != "" {
		return []string{"--header", c.DecryptHeader}
	}
	return nil
}

func (c dataRootConfig) encrypted() bool { return strings.HasPrefix(c.Backing, "luks-") }

// device is what holds the LUKS header: the device by its UUID, which a
// reboot cannot rename, or the source as recorded.
func (c dataRootConfig) device() string {
	if c.Backing == "luks-device" && c.UUID != "" {
		p := "/dev/disk/by-uuid/" + c.UUID
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return c.Source
}

func readKeyValueFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			if _, seen := out[k]; !seen {
				out[k] = v
			}
		}
	}
	return out, sc.Err()
}

func readDataRootConfig(path string) (dataRootConfig, error) {
	kv, err := readKeyValueFile(path)
	if err != nil {
		return dataRootConfig{}, err
	}
	c := dataRootConfig{Backing: kv["backing"], Source: kv["source"], UUID: kv["uuid"], Sidecar: kv["sidecar"],
		Reencrypt: kv["reencrypt"], DrivingSidecar: kv["driving_sidecar"], DecryptHeader: kv["decrypt_header"]}
	c.DrivingSlot = -1
	if n, err := strconv.Atoi(kv["driving_slot"]); err == nil {
		c.DrivingSlot = n
	}
	return c, nil
}

// readRecipient returns the raw recovery public key and its fingerprint from
// the recipient file, refusing one whose fingerprint does not match it.
func readRecipient(path string) ([]byte, string, error) {
	kv, err := readKeyValueFile(path)
	if err != nil {
		return nil, "", err
	}
	pub, err := base64.StdEncoding.DecodeString(kv["public_key"])
	if err != nil || len(pub) != 32 {
		return nil, "", fmt.Errorf("%s holds no recovery public key (one base64 line of 32 bytes)", path)
	}
	fpr := keyFingerprint(pub)
	if kv["fingerprint"] != fpr {
		return nil, "", fmt.Errorf("%s: the fingerprint it records is not its key's (%s)", path, fpr)
	}
	return pub, fpr, nil
}

// keyFingerprint is the platform's: the sha256, in hex, of the raw public key.
func keyFingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// sealVolumeKey seals key to the recovery public key as a version-1 envelope.
func sealVolumeKey(key, recipientPub []byte, now time.Time) ([]byte, error) {
	return sealKeyMaterial(key, recipientPub, now, sidecarArtifact, sidecarCipher)
}

// sealSlotSecret seals a driving key slot's secret (64 characters of hex) as
// the pending copy of an encryption or re-encryption (D5, D8).
func sealSlotSecret(secret, recipientPub []byte, now time.Time) ([]byte, error) {
	return sealKeyMaterial(secret, recipientPub, now, "data-root-driving-slot", "luks2-slot-passphrase")
}

func sealKeyMaterial(key, recipientPub []byte, now time.Time, artifact, cipher string) ([]byte, error) {
	if len(key) != volumeKeyBytes {
		return nil, fmt.Errorf("what is sealed here is %d bytes; this is %d", volumeKeyBytes, len(key))
	}
	var pub [32]byte
	copy(pub[:], recipientPub)
	sealed, err := box.SealAnonymous(nil, key, &pub, rand.Reader)
	if err != nil {
		return nil, err
	}
	env := sidecarEnvelope{
		Version:  sidecarVersion,
		Artifact: artifact,
		Cipher:   cipher,
		Created:  now.UTC().Format("2006-01-02T15:04:05Z"),
		Recipients: []sidecarRecipient{{
			Kind:        "recovery",
			Fingerprint: keyFingerprint(recipientPub),
			Sealed:      base64.StdEncoding.EncodeToString(sealed),
		}},
	}
	out, err := json.MarshalIndent(env, "", "    ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// recoveryKeypair reads a recovery key as it is kept: the base64 secret key
// (44 characters), or the base64 keypair libsodium writes (secret then
// public), with any whitespace a paste brings.
func recoveryKeypair(pasted string) (priv, pub [32]byte, err error) {
	raw, derr := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(pasted), ""))
	if derr != nil || (len(raw) != 32 && len(raw) != 64) {
		return priv, pub, errors.New("that is not a recovery key: it is one line of 44 base64 characters")
	}
	copy(priv[:], raw[:32])
	zero(raw)
	p, derr := curve25519.X25519(priv[:], curve25519.Basepoint)
	if derr != nil {
		return priv, pub, errors.New("that is not a recovery key")
	}
	copy(pub[:], p)
	return priv, pub, nil
}

// openSidecar returns the volume key from the envelope at path, opened with
// the pasted recovery key. A public key pasted by mistake is named as such,
// since its fix is the opposite of a wrong private key's.
func openSidecar(path, pasted string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("the break-glass copy cannot be read: %v", err)
	}
	var env sidecarEnvelope
	if err := json.Unmarshal(data, &env); err != nil || env.Version != sidecarVersion || len(env.Recipients) == 0 {
		return nil, fmt.Errorf("%s is not a break-glass copy this agent reads", path)
	}
	priv, pub, err := recoveryKeypair(pasted)
	if err != nil {
		return nil, err
	}
	defer zero(priv[:])
	if raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(pasted)); derr == nil && len(raw) == 32 {
		for _, r := range env.Recipients {
			if r.Fingerprint == keyFingerprint(raw) {
				return nil, errors.New("that is the recovery key's PUBLIC half; paste the private key you saved")
			}
		}
	}
	for _, r := range env.Recipients {
		sealed, derr := base64.StdEncoding.DecodeString(r.Sealed)
		if derr != nil {
			continue
		}
		if key, ok := box.OpenAnonymous(nil, sealed, &pub, &priv); ok {
			if len(key) != volumeKeyBytes {
				zero(key)
				return nil, fmt.Errorf("%s holds a key of %d bytes, not a volume key", path, len(key))
			}
			return key, nil
		}
	}
	return nil, errors.New("that key does not open this data root's break-glass copy")
}

// luksSlot is one key slot of a LUKS2 header, as status and check need it.
type luksSlot struct {
	ID         int
	KDF        string
	Hash       string
	Iterations string
	Token      string
}

// parseLuksSlots reads `cryptsetup luksDump --dump-json-metadata`: every key
// slot's derivation, and the token (systemd-tpm2) that owns it, if any.
func parseLuksSlots(meta []byte) ([]luksSlot, error) {
	var doc struct {
		Keyslots map[string]struct {
			Type string `json:"type"`
			KDF  struct {
				Type       string `json:"type"`
				Hash       string `json:"hash"`
				Iterations int    `json:"iterations"`
				Time       int    `json:"time"`
			} `json:"kdf"`
		} `json:"keyslots"`
		Tokens map[string]struct {
			Type     string   `json:"type"`
			Keyslots []string `json:"keyslots"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(meta, &doc); err != nil {
		return nil, fmt.Errorf("the LUKS2 metadata is not readable: %v", err)
	}
	owner := map[string]string{}
	for _, t := range doc.Tokens {
		for _, ks := range t.Keyslots {
			owner[ks] = t.Type
		}
	}
	var out []luksSlot
	for id, ks := range doc.Keyslots {
		n, err := strconv.Atoi(id)
		if err != nil {
			continue
		}
		// LUKS2 keeps an encryption's progress in a keyslot of its own
		// (type reencrypt): bookkeeping, not a key.
		if ks.Type != "" && ks.Type != "luks2" {
			continue
		}
		s := luksSlot{ID: n, KDF: ks.KDF.Type, Hash: ks.KDF.Hash, Token: owner[id]}
		switch {
		case ks.KDF.Iterations > 0:
			s.Iterations = strconv.Itoa(ks.KDF.Iterations)
		case ks.KDF.Time > 0:
			s.Iterations = strconv.Itoa(ks.KDF.Time)
		}
		for _, p := range []*string{&s.Hash, &s.Iterations, &s.Token, &s.KDF} {
			if *p == "" {
				*p = "-"
			}
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// staleLuksTokens: the ids of the tokens whose key slots are all gone.
func staleLuksTokens(dev string) ([]string, error) {
	meta, err := exec.Command("cryptsetup", "luksDump", "--dump-json-metadata", dev).Output()
	if err != nil {
		return nil, fmt.Errorf("cryptsetup luksDump %s: %v", dev, err)
	}
	return parseStaleTokens(meta)
}

func parseStaleTokens(meta []byte) ([]string, error) {
	var doc struct {
		Keyslots map[string]json.RawMessage `json:"keyslots"`
		Tokens   map[string]struct {
			Keyslots []string `json:"keyslots"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(meta, &doc); err != nil {
		return nil, fmt.Errorf("the header's metadata: %v", err)
	}
	var out []string
	for id, t := range doc.Tokens {
		live := false
		for _, k := range t.Keyslots {
			if _, ok := doc.Keyslots[k]; ok {
				live = true
			}
		}
		if !live {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

func luksSlotsOf(dev string, header ...string) ([]luksSlot, error) {
	args := append([]string{"luksDump", "--dump-json-metadata"}, header...)
	meta, err := exec.Command("cryptsetup", append(args, dev)...).Output()
	if err != nil {
		return nil, fmt.Errorf("cryptsetup luksDump %s: %v", dev, err)
	}
	return parseLuksSlots(meta)
}

// cliDataRoot is `joinery-agent data-root ...`, joinery_data_root.sh's helper.
func cliDataRoot(args []string) int {
	if len(args) == 0 {
		return cliError("data-root: seal --recipient FILE [--slot] | unseal --sidecar FILE | reseal --recipient FILE | check-recipient FILE | slots DEVICE | add-slot DEVICE | prune-tokens DEVICE | identity | enrol --holder URL [--wait SECONDS] [--name NAME] | report STATE | preflight | report-key | escrow-rekey --old-report-key-file FILE")
	}
	flag := func(name string) string {
		for i, a := range args[1:] {
			if a == "--"+name && i+2 < len(args) {
				return args[i+2]
			}
			if v, ok := strings.CutPrefix(a, "--"+name+"="); ok {
				return v
			}
		}
		return ""
	}
	switch args[0] {
	case "check-recipient":
		if len(args) < 2 {
			return cliError("data-root check-recipient FILE")
		}
		_, fpr, err := readRecipient(args[1])
		if err != nil {
			return cliError("%v", err)
		}
		fmt.Println(fpr)
		return 0

	case "seal":
		// The key arrives on stdin, so it is never an argument; the envelope
		// goes to stdout, which the script writes beside the volume.
		pub, _, err := readRecipient(flag("recipient"))
		if err != nil {
			return cliError("%v", err)
		}
		key, err := io.ReadAll(io.LimitReader(os.Stdin, volumeKeyBytes+1))
		if err != nil {
			return cliError("reading the volume key: %v", err)
		}
		defer zero(key)
		seal := sealVolumeKey
		for _, a := range args[1:] {
			if a == "--slot" {
				seal = sealSlotSecret
			}
		}
		out, err := seal(key, pub, time.Now())
		if err != nil {
			return cliError("%v", err)
		}
		os.Stdout.Write(out)
		return 0

	case "reseal":
		// D8: the break-glass copy sealed again, to the recipient now in the
		// recipient file, from the volume key in the open mapping; the old
		// copy replaced atomically. The volume key does not change: a leaked
		// key's re-encryption is the other half of D8.
		conf, err := readDataRootConfig(dataRootConfPath)
		if err != nil {
			return cliError("data-root reseal: %v", err)
		}
		if !conf.encrypted() || conf.Sidecar == "" {
			return cliError("data-root reseal: this machine's data root is not encrypted")
		}
		if conf.Reencrypt != "" {
			return cliError("data-root reseal: its %sion is running; the copy is sealed again once it is done", conf.Reencrypt)
		}
		pub, fpr, err := readRecipient(flag("recipient"))
		if err != nil {
			return cliError("data-root reseal: %v", err)
		}
		vk, err := volumeKeyFromMapping()
		if err != nil {
			return cliError("data-root reseal: %v", err)
		}
		defer zero(vk)
		out, err := sealVolumeKey(vk, pub, time.Now())
		if err != nil {
			return cliError("data-root reseal: %v", err)
		}
		tmp := conf.Sidecar + ".tmp"
		if err := os.WriteFile(tmp, out, 0600); err != nil {
			return cliError("data-root reseal: %v", err)
		}
		if err := os.Rename(tmp, conf.Sidecar); err != nil {
			return cliError("data-root reseal: %v", err)
		}
		fmt.Printf("sealed to %s\n", fpr)
		return 0

	case "prune-tokens":
		// TPM2 tokens whose key slot is gone: a re-encryption under a new
		// volume key takes every other slot away but leaves their tokens,
		// and a chip sealed again leaves the old one. Removed, so the header
		// carries only tokens that open something.
		if len(args) < 2 {
			return cliError("data-root prune-tokens DEVICE")
		}
		ids, err := staleLuksTokens(args[1])
		if err != nil {
			return cliError("data-root prune-tokens: %v", err)
		}
		for _, id := range ids {
			if err := cryptsetupRun("token", "remove", "--token-id", id, args[1]); err != nil {
				return cliError("data-root prune-tokens: token %s: %v", id, err)
			}
			fmt.Printf("removed token %s, whose key slot is gone\n", id)
		}
		return 0

	case "report-key":
		// The escrow report key of the volume key in the open mapping, base64,
		// for a re-encryption under a new volume key to keep until it is done
		// (joinery_data_root.sh rekey, on the data root): the old key is what
		// proves the change to the holder (escrow-rekey). Not to a terminal.
		if fi, err := os.Stdout.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			return cliError("data-root report-key writes a key; send it to a file, not the screen")
		}
		rk, err := escrowReportKeyFromMapping()
		if err != nil {
			return cliError("data-root report-key: %v", err)
		}
		defer zero(rk)
		fmt.Println(base64.StdEncoding.EncodeToString(rk))
		return 0

	case "escrow-rekey":
		// After a re-encryption under a new volume key (D8): the escrow slot
		// it took away is made again with a new secret, the change proven to
		// the holder with the old volume key's report key, read from FILE.
		path := flag("old-report-key-file")
		if path == "" {
			return cliError("data-root escrow-rekey --old-report-key-file FILE")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return cliError("data-root escrow-rekey: %v", err)
		}
		old, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		zero(raw)
		if err != nil || len(old) != 32 {
			return cliError("data-root escrow-rekey: %s does not hold a report key", path)
		}
		defer zero(old)
		slot, err := escrowRekey(context.Background(), old)
		if err != nil {
			return cliError("data-root escrow-rekey: %v", err)
		}
		if slot < 0 {
			fmt.Println("no escrow holder: nothing to change")
			return 0
		}
		fmt.Printf("escrow slot %d, with a new secret from the holder\n", slot)
		return 0

	case "add-slot":
		// A key slot in the standard configuration holding the secret on
		// stdin, authorised by the volume key read from the open mapping;
		// both reach cryptsetup through pipes. Prints the slot's number.
		if len(args) < 2 {
			return cliError("data-root add-slot DEVICE")
		}
		secret, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		if err != nil || len(secret) < 32 {
			return cliError("data-root add-slot: the slot's secret comes on stdin, 32 bytes or more")
		}
		defer zero(secret)
		vk, err := volumeKeyFromMapping()
		if err != nil {
			return cliError("data-root add-slot: %v", err)
		}
		defer zero(vk)
		slot, err := luksAddSlot(args[1], vk, secret)
		if err != nil {
			return cliError("data-root add-slot: %v", err)
		}
		fmt.Println(slot)
		return 0

	case "unseal":
		// By hand, in a recovery: the recovery key on stdin, the raw volume
		// key to stdout, which must not be a terminal.
		if fi, err := os.Stdout.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			return cliError("data-root unseal writes the raw volume key; send it to a file in /run or a pipe, not the screen")
		}
		pasted, err := bufio.NewReader(io.LimitReader(os.Stdin, 4096)).ReadString('\n')
		if err != nil && err != io.EOF {
			return cliError("reading the recovery key: %v", err)
		}
		key, err := openSidecar(flag("sidecar"), pasted)
		if err != nil {
			return cliError("%v", err)
		}
		defer zero(key)
		os.Stdout.Write(key)
		return 0

	case "identity":
		// The unlock identity (D3), made if there is none: create --encrypted
		// runs this, and it prints the fingerprint a holder's page shows.
		id, err := loadUnlockIdentity(unlockIdentityPath, true)
		if err != nil {
			return cliError("the unlock identity: %v", err)
		}
		fmt.Printf("public_key=%s\nfingerprint=%s\n", id.PublicB64(), id.Fingerprint())
		return 0

	case "enrol":
		// By hand, for a holder that is not this machine's management node
		// (C-3): the request waits for approval on the holder's dashboard.
		holder := flag("holder")
		wait := 10 * time.Minute
		if v := flag("wait"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				wait = time.Duration(n) * time.Second
			}
		}
		// --name: what the holder's page calls it; by default its site's
		// domain, its node and its hostname (escrowMachineName).
		slot, err := escrowEnrol(context.Background(), holder, flag("name"), wait, func(f string, a ...interface{}) {
			fmt.Printf(f+"\n", a...)
		})
		if err != nil {
			return cliError("data-root enrol: %v", err)
		}
		fmt.Printf("enrolled with %s: key slot %d opens the data root from there\n", holder, slot)
		return 0

	case "report":
		if len(args) < 2 {
			return cliError("data-root report unlocked|shutdown|addresses")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := escrowReport(ctx, args[1]); err != nil {
			return cliError("data-root report: %v", err)
		}
		return 0

	case "preflight":
		// Before a planned reboot (D4): exit 0 when the boot that follows
		// would open hands-off.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := escrowPreflight(ctx); err != nil {
			return cliError("data-root preflight: %v", err)
		}
		fmt.Println("ready: a reboot now opens hands-off")
		return 0

	case "slots":
		if len(args) < 2 {
			return cliError("data-root slots DEVICE")
		}
		slots, err := luksSlotsOf(args[1])
		if err != nil {
			return cliError("%v", err)
		}
		for _, s := range slots {
			fmt.Printf("slot=%d kdf=%s hash=%s iterations=%s token=%s\n", s.ID, s.KDF, s.Hash, s.Iterations, s.Token)
		}
		return 0
	}
	return cliError("data-root: unknown command %q", args[0])
}
