package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"joinery-agent/primitives"
)

// The escrow slot, the machine's side (specs/hosted_data_promise_disk_encryption.md
// D3, WP2).
//
// THE UNLOCK IDENTITY is an Ed25519 keypair of its own, minted by
// `joinery_data_root.sh create --encrypted` on the root disk and used for
// nothing else. Not the agent's node key: that one is minted afresh at every
// join and forgotten at every leave, and it names one plane, while the escrow
// holder may be another (D3, C-3) and must still know this machine after a
// re-pair. The holder keys its escrow table by this identity alone.
//
// THE HOLDER is named by URL, never an address, so a holder that moves
// machines is still found. Every request is signed with the unlock identity
// over the method, the path, the identity, a timestamp, a nonce and the body's
// hash, under a domain of its own, so no other signature this machine makes
// can stand in for one.
//
// ENROLMENT comes after the join (D3): the holder mints the secret and hands it
// over once, over TLS, in answer to a signed request; the machine adds it as a
// key slot, authorised by the volume key read from the open mapping, and tells
// the holder which slot. The secret never rides a job row, a command line or a
// log.
//
// AT BOOT the unlock asks the holder for the secret (one answer per boot; the
// holder checks the address it comes from) and opens the volume with it.

const (
	unlockIdentityPath  = "/etc/joinery/data-root/unlock_identity"
	escrowHolderPath    = "/etc/joinery/data-root/holder"
	escrowSigningDomain = "joinery-unlock-v1"
	// escrowAPIPath is where every holder answers, below its URL.
	escrowAPIPath = "/api/v1/agent/escrow/"
	// The node key's signature on an enrolment with its own plane: this
	// unlock identity is this node's (D3). A domain of its own, so it is no
	// request signature and no other.
	escrowEnrolDomain = "joinery-escrow-enrol-v1"
	// The standard key slot (D1, joinery_data_root.sh LUKS_SLOT): every slot
	// this platform makes. The shell gate pins the two to one number.
	luksSlotPBKDF      = "pbkdf2"
	luksSlotHash       = "sha256"
	luksSlotIterations = "2000000"
	// How long the unlock waits for the holder before the console and the
	// page are offered as well (O2). It keeps asking the holder meanwhile.
	escrowFirstWait = 60 * time.Second
	escrowRetry     = 10 * time.Second
	escrowMaxBody   = 64 * 1024
)

type unlockIdentity struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// loadUnlockIdentity reads the identity; with mint, makes it when there is none.
func loadUnlockIdentity(path string, mint bool) (*unlockIdentity, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		kv := map[string]string{}
		for _, line := range strings.Split(string(data), "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && !strings.HasPrefix(k, "#") {
				kv[k] = v
			}
		}
		seed, derr := base64.StdEncoding.DecodeString(kv["private_seed"])
		if derr != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s holds no unlock identity", path)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		zero(seed)
		return &unlockIdentity{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
	}
	if !errors.Is(err, os.ErrNotExist) || !mint {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	body := "# Written by joinery-agent (specs/hosted_data_promise_disk_encryption.md D3): this machine's unlock\n" +
		"# identity. It signs the requests that ask the escrow holder for the data root's key.\n" +
		"public_key=" + base64.StdEncoding.EncodeToString(pub) + "\n" +
		"private_seed=" + base64.StdEncoding.EncodeToString(priv.Seed()) + "\n"
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return &unlockIdentity{priv: priv, pub: pub}, nil
}

func (u *unlockIdentity) PublicB64() string   { return base64.StdEncoding.EncodeToString(u.pub) }
func (u *unlockIdentity) Fingerprint() string { return Fingerprint(u.pub) }

func escrowSigningMessage(method, path, identity, timestamp, nonce, bodySha256 string) string {
	return strings.Join([]string{escrowSigningDomain, strings.ToUpper(method), path, identity, timestamp, nonce, bodySha256}, "\n")
}

// escrowHolder is /etc/joinery/data-root/holder: whom to ask, and the slot.
type escrowHolder struct {
	URL      string
	Slot     int
	Enrolled string
}

func readEscrowHolder(path string) (*escrowHolder, error) {
	kv, err := readKeyValueFile(path)
	if err != nil {
		return nil, err
	}
	h := &escrowHolder{URL: kv["url"], Enrolled: kv["enrolled"]}
	h.Slot, _ = strconv.Atoi(kv["slot"])
	if h.URL == "" || kv["slot"] == "" {
		return nil, fmt.Errorf("%s names no holder and slot", path)
	}
	return h, nil
}

func writeEscrowHolder(path string, h *escrowHolder) error {
	body := "# Written by joinery-agent (specs/hosted_data_promise_disk_encryption.md D3): the escrow holder\n" +
		"# this machine asks for its data root's key at boot, and the key slot that key opens.\n" +
		"url=" + h.URL + "\nslot=" + strconv.Itoa(h.Slot) + "\nenrolled=" + h.Enrolled + "\n"
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// escrowRequest posts one signed request to the holder and returns the data
// of its answer. A refusal comes back as a *planeStatusError with its status.
func escrowRequest(ctx context.Context, client *http.Client, holderURL string, id *unlockIdentity, action string, payload map[string]interface{}) (json.RawMessage, error) {
	return escrowRequestMAC(ctx, client, holderURL, id, action, payload, nil)
}

// escrowRequestMAC is escrowRequest with the report key's HMAC over the body,
// for what changes the holder's record (confirm, report): proof the volume
// is open here, which a copy of the root disk cannot give.
func escrowRequestMAC(ctx context.Context, client *http.Client, holderURL string, id *unlockIdentity, action string, payload map[string]interface{}, reportKey []byte) (json.RawMessage, error) {
	if payload == nil {
		payload = map[string]interface{}{}
	}
	payload["action"] = action
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	path := escrowAPIPath + action
	url := strings.TrimRight(holderURL, "/") + path
	sum := sha256.Sum256(body)
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(id.priv, []byte(escrowSigningMessage(http.MethodPost, path, id.PublicB64(), timestamp, nonce, hex.EncodeToString(sum[:]))))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Joinery-Unlock-Identity", id.PublicB64())
	req.Header.Set("X-Joinery-Unlock-Timestamp", timestamp)
	req.Header.Set("X-Joinery-Unlock-Nonce", nonce)
	req.Header.Set("X-Joinery-Unlock-Signature", base64.StdEncoding.EncodeToString(sig))
	if reportKey != nil {
		m := hmac.New(sha256.New, reportKey)
		m.Write(body)
		req.Header.Set("X-Joinery-Unlock-Report-Mac", base64.StdEncoding.EncodeToString(m.Sum(nil)))
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return readEnvelopeUpTo(resp, url, escrowMaxBody)
}

func newEscrowClient() *http.Client { return newPlaneClient(false) }

func bootID() string {
	b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b))
}

// volumeKeyFromMapping reads the open volume's key from its table (D8): the
// volume is opened with --disable-keyring so the key is there, and root can
// read it. It goes from here to cryptsetup through a pipe.
func volumeKeyFromMapping() ([]byte, error) {
	out, err := exec.Command("dmsetup", "table", "--showkeys", dataRootMapping).Output()
	if err != nil {
		return nil, fmt.Errorf("dmsetup table %s: %v", dataRootMapping, err)
	}
	defer zero(out)
	f := strings.Fields(string(out))
	if len(f) < 5 || f[2] != "crypt" {
		return nil, errors.New("the data root's mapping is not a dm-crypt table")
	}
	if strings.HasPrefix(f[4], ":") {
		return nil, errors.New("the data root's key is in the kernel keyring, not its table: it was opened without --disable-keyring")
	}
	key, err := hex.DecodeString(f[4])
	if err != nil || len(key) != volumeKeyBytes {
		return nil, errors.New("the data root's table holds no 512-bit key")
	}
	return key, nil
}

// escrowReportKey is what proves to the holder that a report comes from this
// machine with its data root open: an HMAC key derived from the volume key,
// handed over at enrolment. A copy of the root disk carries the unlock
// identity but not this.
func escrowReportKey(volumeKey []byte) []byte {
	m := hmac.New(sha256.New, volumeKey)
	m.Write([]byte("joinery-escrow-report-v1"))
	return m.Sum(nil)
}

func escrowReportKeyFromMapping() ([]byte, error) {
	vk, err := volumeKeyFromMapping()
	if err != nil {
		return nil, err
	}
	defer zero(vk)
	return escrowReportKey(vk), nil
}

// luksAddSlot adds a key slot holding secret, in the standard configuration,
// authorised by the volume key; both reach cryptsetup through pipes. It
// returns the new slot's number.
func luksAddSlot(dev string, volumeKey, secret []byte) (int, error) {
	before, err := luksSlotsOf(dev)
	if err != nil {
		return 0, err
	}
	vkR, vkW, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	skR, skW, err := os.Pipe()
	if err != nil {
		vkR.Close()
		vkW.Close()
		return 0, err
	}
	cmd := exec.Command("cryptsetup", "luksAddKey", "--batch-mode",
		"--pbkdf", luksSlotPBKDF, "--hash", luksSlotHash, "--pbkdf-force-iterations", luksSlotIterations,
		// The key size must be named: a volume with no slot yet (every one
		// before its first enrolment) gives cryptsetup nowhere to read it from.
		"--key-size", "512", "--volume-key-file", "/dev/fd/3", dev, "/dev/fd/4")
	cmd.ExtraFiles = []*os.File{vkR, skR}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		for _, f := range []*os.File{vkR, vkW, skR, skW} {
			f.Close()
		}
		return 0, err
	}
	vkR.Close()
	skR.Close()
	vkW.Write(volumeKey)
	vkW.Close()
	skW.Write(secret)
	skW.Close()
	if err := cmd.Wait(); err != nil {
		return 0, fmt.Errorf("cryptsetup luksAddKey: %v %s", err, strings.TrimSpace(stderr.String()))
	}
	after, err := luksSlotsOf(dev)
	if err != nil {
		return 0, err
	}
	had := map[int]bool{}
	for _, s := range before {
		had[s.ID] = true
	}
	for _, s := range after {
		if !had[s.ID] {
			return s.ID, nil
		}
	}
	return 0, errors.New("cryptsetup added a key slot, but no new one is listed")
}

// sidecarBox is the break-glass copy as the holder records it (D2b): the
// envelope itself, so the holder can show a change and open it in a browser.
func sidecarBox(conf dataRootConfig) string {
	b, err := os.ReadFile(conf.Sidecar)
	if err != nil {
		return ""
	}
	return string(b)
}

type escrowEnrolAnswer struct {
	Status      string `json:"status"` // pending, enrolled, refused
	Secret      string `json:"secret"`
	Fingerprint string `json:"fingerprint"`
	Reason      string `json:"reason"`
}

// escrowEnrol enrols this machine with the holder at holderURL. With its own
// management node, its node key vouches for the identity and no approval is
// needed; with any other holder the request waits for a person to approve it
// on the holder's dashboard after comparing fingerprints (C-3). wait bounds how
// long this call polls for that approval.
func escrowEnrol(ctx context.Context, holderURL string, wait time.Duration, say func(string, ...interface{})) (int, error) {
	conf, err := readDataRootConfig(dataRootConfPath)
	if err != nil {
		return 0, err
	}
	if !conf.encrypted() {
		return 0, errors.New("this machine's data root is not encrypted")
	}
	if !mapperOpen() {
		return 0, errors.New("the data root is not open, so its key cannot authorise a new slot")
	}
	if !strings.HasPrefix(holderURL, "https://") {
		return 0, fmt.Errorf("the escrow holder %q is not an https URL", holderURL)
	}
	id, err := loadUnlockIdentity(unlockIdentityPath, true)
	if err != nil {
		return 0, fmt.Errorf("the unlock identity: %v", err)
	}
	host, _ := os.Hostname()
	vk, err := volumeKeyFromMapping()
	if err != nil {
		return 0, err
	}
	defer zero(vk)
	reportKey := escrowReportKey(vk)
	// Its own addresses, both families (D3): a dual-stack machine may ask
	// over either. The holder adds the one the request comes from.
	payload := map[string]interface{}{
		"addresses": machineAddresses(), "box": sidecarBox(conf), "hostname": host,
		"holder": strings.TrimRight(holderURL, "/"), "report_key": base64.StdEncoding.EncodeToString(reportKey),
	}
	// Enrolling with its own management node, the machine signs the identity
	// with its node key too, which is what lets the holder hand the secret to
	// this identity without a person approving it; with any other holder the
	// request waits for that approval (C-3).
	if nid, err := LoadIdentity(IdentityPath()); err == nil && nid != nil && sameHolder(nid.PlaneURL, holderURL) {
		ts := strconv.FormatInt(time.Now().UTC().Unix(), 10)
		msg := escrowEnrolDomain + "\n" + id.PublicB64() + "\n" + strings.TrimRight(holderURL, "/") + "\n" + ts
		if sig, err := (nodeKey{id: nid}).SignDomain(escrowEnrolDomain, []byte(msg)); err == nil {
			payload["node_id"] = nid.NodeID
			payload["node_time"] = ts
			payload["node_signature"] = base64.StdEncoding.EncodeToString(sig)
		}
	}
	client := newEscrowClient()
	deadline := time.Now().Add(wait)
	var answer escrowEnrolAnswer
	saidPending := false
	for {
		raw, err := escrowRequest(ctx, client, holderURL, id, "enrol", payload)
		if err != nil {
			return 0, err
		}
		answer = escrowEnrolAnswer{}
		if err := json.Unmarshal(raw, &answer); err != nil {
			return 0, fmt.Errorf("the holder's answer: %v", err)
		}
		if answer.Status != "pending" {
			break
		}
		if !saidPending {
			say("enrolment asked of %s; approve it there once its fingerprint reads %s", holderURL, id.Fingerprint())
			saidPending = true
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("pending at %s: approve the request whose fingerprint is %s, then run this again", holderURL, id.Fingerprint())
		}
		sleepCtx(ctx, 5*time.Second)
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
	}
	if answer.Status != "enrolled" || answer.Secret == "" {
		return 0, fmt.Errorf("the holder refused the enrolment: %s", answer.Reason)
	}
	secret, err := base64.StdEncoding.DecodeString(answer.Secret)
	if err != nil || len(secret) < 32 {
		return 0, errors.New("the holder's secret is not one this machine can use")
	}
	defer zero(secret)
	dev, err := attachDataRoot(conf)
	if err != nil {
		return 0, err
	}
	// A slot from an earlier enrolment with this holder goes once the new
	// one is in: one escrow slot per machine.
	old, _ := readEscrowHolder(escrowHolderPath)
	slot, err := luksAddSlot(dev, vk, secret)
	if err != nil {
		return 0, err
	}
	if _, err := escrowRequestMAC(ctx, client, holderURL, id, "confirm", map[string]interface{}{"slot": slot}, reportKey); err != nil {
		return 0, fmt.Errorf("slot %d holds the escrow key, but the holder did not record it: %v", slot, err)
	}
	if err := writeEscrowHolder(escrowHolderPath, &escrowHolder{URL: holderURL, Slot: slot, Enrolled: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		return 0, err
	}
	if old != nil && old.Slot != slot {
		if err := cryptsetupRun("luksKillSlot", "--batch-mode", dev, strconv.Itoa(old.Slot)); err != nil {
			say("the earlier escrow slot %d did not go: %v", old.Slot, err)
		}
	}
	return slot, nil
}

// escrowRekey makes the escrow slot again after a re-encryption under a new
// volume key took it away (D8): the change is proven with the old volume
// key's report key, the holder mints a new secret for the new slot, and the
// slot is confirmed with the new report key. -1 when this machine has no
// escrow holder.
func escrowRekey(ctx context.Context, oldReportKey []byte) (int, error) {
	h, err := readEscrowHolder(escrowHolderPath)
	if err != nil {
		if os.IsNotExist(err) {
			return -1, nil
		}
		return 0, err
	}
	conf, err := readDataRootConfig(dataRootConfPath)
	if err != nil {
		return 0, err
	}
	id, err := loadUnlockIdentity(unlockIdentityPath, false)
	if err != nil {
		return 0, fmt.Errorf("the unlock identity: %v", err)
	}
	vk, err := volumeKeyFromMapping()
	if err != nil {
		return 0, err
	}
	defer zero(vk)
	reportKey := escrowReportKey(vk)
	client := newEscrowClient()
	raw, err := escrowRequestMAC(ctx, client, h.URL, id, "rekey", map[string]interface{}{
		"report_key": base64.StdEncoding.EncodeToString(reportKey), "box": sidecarBox(conf), "addresses": machineAddresses(),
	}, oldReportKey)
	if err != nil {
		return 0, err
	}
	var answer escrowEnrolAnswer
	if err := json.Unmarshal(raw, &answer); err != nil {
		return 0, fmt.Errorf("the holder's answer: %v", err)
	}
	if answer.Status != "enrolled" || answer.Secret == "" {
		return 0, fmt.Errorf("the holder refused the changed key: %s", answer.Reason)
	}
	secret, err := base64.StdEncoding.DecodeString(answer.Secret)
	if err != nil || len(secret) < 32 {
		return 0, errors.New("the holder's secret is not one this machine can use")
	}
	defer zero(secret)
	dev, err := attachDataRoot(conf)
	if err != nil {
		return 0, err
	}
	slot, err := luksAddSlot(dev, vk, secret)
	if err != nil {
		return 0, err
	}
	if _, err := escrowRequestMAC(ctx, client, h.URL, id, "confirm", map[string]interface{}{"slot": slot}, reportKey); err != nil {
		return 0, fmt.Errorf("slot %d holds the new escrow key, but the holder did not record it: %v", slot, err)
	}
	if err := writeEscrowHolder(escrowHolderPath, &escrowHolder{URL: h.URL, Slot: slot, Enrolled: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		return 0, err
	}
	return slot, nil
}

// escrowReport tells the holder something about this machine, signed:
// unlocked, shutdown, or its addresses and sidecar box.
func escrowReport(ctx context.Context, state string) error {
	h, err := readEscrowHolder(escrowHolderPath)
	if err != nil {
		return err
	}
	id, err := loadUnlockIdentity(unlockIdentityPath, false)
	if err != nil {
		return err
	}
	reportKey, err := escrowReportKeyFromMapping()
	if err != nil {
		return err
	}
	payload := map[string]interface{}{"state": state, "boot_id": bootID(), "addresses": machineAddresses()}
	if conf, err := readDataRootConfig(dataRootConfPath); err == nil {
		payload["box"] = sidecarBox(conf)
	}
	_, err = escrowRequestMAC(ctx, newEscrowClient(), h.URL, id, "report", payload, reportKey)
	return err
}

type escrowUnlockAnswer struct {
	Secret string `json:"secret"`
	Slot   int    `json:"slot"`
	// A person's answer from the holder's unlock page (D2b): the value that
	// opens the break-glass box, worked out in their browser there.
	Shared string `json:"shared"`
}

// escrow is the unlock's ask of the holder (D3): until it answers, every
// escrowRetry; a refusal is said once and asked again, since a holder that
// comes back, or a 15-minute wait that ends, unlocks it with no person.
func (u *dataRootUnlocker) escrow(ctx context.Context, h *escrowHolder, id *unlockIdentity) {
	client := newEscrowClient()
	last := ""
	for ctx.Err() == nil {
		raw, err := escrowRequest(ctx, client, h.URL, id, "unlock", map[string]interface{}{"boot_id": bootID()})
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			var a escrowUnlockAnswer
			if jerr := json.Unmarshal(raw, &a); jerr == nil && a.Shared != "" {
				err = u.openWithShared(a.Shared, "the recovery key, from the escrow holder's page")
				if err == nil {
					return
				}
			} else if jerr == nil && a.Secret != "" {
				secret, derr := base64.StdEncoding.DecodeString(a.Secret)
				if derr == nil {
					slot := h.Slot
					if a.Slot > 0 {
						slot = a.Slot
					}
					oerr := u.openWithSlot(secret, slot, "the escrow holder, "+h.URL)
					zero(secret)
					if oerr == nil {
						return
					}
					err = oerr
				}
			} else {
				err = errors.New("the holder's answer held no key")
			}
		}
		// Said once per kind of answer: a holder that cannot be reached fails
		// at a different address each time behind a proxy, and the journal is
		// not a dashboard.
		kind := err.Error()
		var ue *url.Error
		if errors.As(err, &ue) {
			kind = "unreachable"
		}
		if kind != last {
			unlockSay("the escrow holder %s did not unlock it: %s", h.URL, err.Error())
			last = kind
		}
		sleepCtx(ctx, escrowRetry)
	}
}

// openWithSlot opens the volume with a key slot's secret, once.
func (u *dataRootUnlocker) openWithSlot(secret []byte, slot int, how string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !mapperOpen() {
		// A change of volume key part-way has two slots behind the driving
		// secret, the old key's and the new key's, and cryptsetup opens it
		// only when it may try both: no --key-slot (-1).
		keySlot := slot
		if u.conf.Reencrypt == "reencrypt" && slot == u.conf.DrivingSlot {
			keySlot = -1
		}
		if err := cryptsetupOpenKeySlot(u.dev, u.conf.headerArgs(), secret, keySlot); err != nil {
			return err
		}
	}
	// The slot that drives an encryption part-way: its secret goes back to
	// /run so the run resumes (D5 step 5).
	if u.conf.Reencrypt != "" && slot == u.conf.DrivingSlot {
		keepDrivingKey(secret)
	}
	u.once.Do(func() { u.done <- how })
	return nil
}

func cryptsetupOpenKeySlot(dev string, header []string, secret []byte, slot int) error {
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	args := append([]string{"open", "--disable-keyring"}, header...)
	if slot >= 0 {
		args = append(args, "--key-slot", strconv.Itoa(slot))
	}
	args = append(args, "--key-file", "/dev/fd/3", dev, dataRootMapping)
	cmd := exec.Command("cryptsetup", args...)
	cmd.ExtraFiles = []*os.File{r}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		r.Close()
		w.Close()
		return err
	}
	r.Close()
	_, werr := w.Write(secret)
	w.Close()
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("cryptsetup open: %v %s", err, strings.TrimSpace(stderr.String()))
	}
	return werr
}

func sameHolder(a, b string) bool {
	return strings.EqualFold(strings.TrimRight(a, "/"), strings.TrimRight(b, "/"))
}

// dataRootEnrolForPlane is data_root_enrol's hook: enrol with the plane this
// agent answers to.
func dataRootEnrolForPlane(ctx context.Context) (map[string]interface{}, error) {
	nid, err := LoadIdentity(IdentityPath())
	if err != nil || nid == nil {
		return nil, errors.New("this machine is not connected to a management node")
	}
	var said []string
	slot, err := escrowEnrol(ctx, nid.PlaneURL, 30*time.Second, func(f string, a ...interface{}) {
		said = append(said, fmt.Sprintf(f, a...))
	})
	if err != nil {
		return nil, err
	}
	id, _ := loadUnlockIdentity(unlockIdentityPath, false)
	out := map[string]interface{}{"slot": slot, "holder": nid.PlaneURL}
	if id != nil {
		out["unlock_fingerprint"] = id.Fingerprint()
	}
	return out, nil
}

// openWithShared opens the break-glass box with the browser's 32-byte value
// (the unlock page's, here or at the holder) and the volume with its key.
func (u *dataRootUnlocker) openWithShared(sharedB64, how string) error {
	shared, err := base64.StdEncoding.DecodeString(sharedB64)
	if err != nil || len(shared) != 32 {
		return errors.New("the value given does not open this machine's break-glass box")
	}
	defer zero(shared)
	page, err := newUnlockPage(u)
	if err != nil {
		return err
	}
	key, err := primitives.OpenRecoverySealed(page.sealed, shared, page.recipientPub)
	if err != nil {
		return errors.New("the value given does not open this machine's break-glass box")
	}
	defer zero(key)
	return u.openWith(key, how)
}

// escrowPreflight says whether a planned reboot would open hands-off (D4): a
// TPM2 slot opens it on its own, otherwise the holder must answer that it
// would answer the boot. Asked a minute before the reboot, with the report key.
func escrowPreflight(ctx context.Context) error {
	conf, err := readDataRootConfig(dataRootConfPath)
	if err != nil {
		return err
	}
	if !conf.encrypted() {
		return errors.New("this machine's data root is not encrypted")
	}
	if slots, err := luksSlotsOf(conf.device(), conf.headerArgs()...); err == nil {
		for _, s := range slots {
			if s.Token == "systemd-tpm2" {
				return nil
			}
		}
	}
	h, err := readEscrowHolder(escrowHolderPath)
	if err != nil {
		return errors.New("it has no escrow holder: after a reboot it opens only by its recovery key")
	}
	id, err := loadUnlockIdentity(unlockIdentityPath, false)
	if err != nil {
		return err
	}
	reportKey, err := escrowReportKeyFromMapping()
	if err != nil {
		return err
	}
	_, err = escrowRequestMAC(ctx, newEscrowClient(), h.URL, id, "preflight", map[string]interface{}{"boot_id": bootID()}, reportKey)
	if err != nil {
		return fmt.Errorf("the escrow holder %s: %v", h.URL, err)
	}
	return nil
}
