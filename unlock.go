package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The one-shot unlock mode (specs/hosted_data_promise_disk_encryption.md D1b,
// D2a, D3, D4): `joinery-agent unlock`, run by joinery-data-unlock.service
// once the network is up, opens the encrypted data root and exits; the mount
// and every service whose data lives there are waiting on it.
//
// WHAT OPENS IT, in order: the TPM2 chip, where the volume has a slot for one;
// then the escrow holder (D3, escrow.go), asked every ten seconds for as long
// as it takes; and, from the start where there is no holder, or after a
// minute where it has not answered (O2), the recovery key as well: pasted at
// the console (systemd's password agent, so it works on Lish or a serial
// console before anyone has logged in). Whichever comes first opens it. The
// unlock page (D2b) joins the recovery key.
//
// IT WAITS FOR AS LONG AS IT MUST. The unit has no start timeout: a machine
// waiting for a person is waiting, not failed, and when the volume opens the
// mount and the consumers start on their own, with no reboot.
//
// THE KEY STAYS IN MEMORY. The volume key reaches cryptsetup through a pipe,
// never a file or an argument, and every open is --disable-keyring, so the
// key sits in the mapping's table, where grow and a re-seal read it, and not
// in the kernel keyring.

const unlockAskID = "joinery-data-unlock"

func unlockSay(format string, args ...interface{}) {
	fmt.Printf("joinery-agent unlock: "+format+"\n", args...)
}

func cliUnlock(args []string) int {
	closing := false
	for _, a := range args {
		switch a {
		case "--close":
			closing = true
		default:
			return cliError("unlock: unknown option %q (unlock [--close])", a)
		}
	}
	conf, err := readDataRootConfig(dataRootConfPath)
	if err != nil {
		return cliError("unlock: %s cannot be read: %v", dataRootConfPath, err)
	}
	if !conf.encrypted() {
		return cliError("unlock: this machine's data root is not encrypted (%s says %q)", dataRootConfPath, conf.Backing)
	}
	if closing {
		return unlockClose(conf)
	}
	if mapperOpen() {
		unlockSay("the data root is already open")
		return 0
	}
	dev, err := attachDataRoot(conf)
	if err != nil {
		return cliError("unlock: %v", err)
	}
	// A decryption that finished before its switch to the plain data root
	// did: the data is plain XFS, there is nothing to open, and the script
	// finishes the switch (joinery_data_root.sh decrypt_finish).
	if conf.Reencrypt == "decrypt" {
		if out, _ := exec.Command("blkid", "-p", "-s", "TYPE", "-o", "value", dev).Output(); strings.TrimSpace(string(out)) == "xfs" {
			unlockSay("its decryption has finished and the data is plain: finishing the switch to the plain data root")
			_ = exec.Command("systemd-run", "--no-block", "--collect", "--unit=joinery-data-decrypt-finish",
				"/bin/bash", "/usr/local/sbin/joinery-data-root", "encrypt-resume").Run()
			return 1
		}
	}
	host, _ := os.Hostname()
	u := &dataRootUnlocker{conf: conf, dev: dev, host: host, done: make(chan string, 1)}
	how := u.run(context.Background())
	recordOpenedBy(how)
	unlockSay("the data root is open (%s)", how)
	// The holder answers this identity again only once it hears the machine
	// is unlocked or shut down, or 15 minutes on (D3).
	if _, err := readEscrowHolder(escrowHolderPath); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if err := escrowReport(ctx, "unlocked"); err != nil {
			unlockSay("the escrow holder was not told it is unlocked (%v); it answers the next boot after 15 minutes", err)
		}
		cancel()
	}
	return 0
}

type dataRootUnlocker struct {
	conf dataRootConfig
	dev  string
	host string
	mu   sync.Mutex
	once sync.Once
	done chan string
}

// How often the TPM2 chip is asked before the escrow and the recovery key,
// and how long between asks. Vars for the tests.
var (
	tpm2Tries     = 5
	tpm2RetryWait = 2 * time.Second
)

// run returns once the volume is open, naming what opened it.
func (u *dataRootUnlocker) run(ctx context.Context) string {
	if u.conf.Reencrypt != "" {
		unlockSay("its %sion is part-way: it opens through the key slot that drives it, and the run resumes once open", u.conf.Reencrypt)
	}
	if u.hasTPM2() {
		args := append([]string{"open", "--disable-keyring", "--token-only", "--token-type", "systemd-tpm2"}, u.conf.headerArgs()...)
		// The chip refuses an unseal while another process at boot extends
		// a PCR between its policy check and the unseal (TPM_RC_PCR_CHANGED,
		// 0x128): found on the test machine at one boot in three. Tried
		// again before anything else is asked.
		var err error
		for try := 1; try <= tpm2Tries; try++ {
			if err = cryptsetupRun(append(args, u.dev, dataRootMapping)...); err == nil {
				return "the TPM2 chip"
			}
			if try < tpm2Tries {
				unlockSay("the TPM2 chip refused at try %d of %d; asking it again", try, tpm2Tries)
				time.Sleep(tpm2RetryWait)
			}
		}
		{
			unlockSay("the TPM2 chip did not open it, asked %d times (%v); asking for the recovery key", tpm2Tries, err)
			// Once something else opens it, the data root's tick seals the
			// chip's slot again to this boot's measurements
			// (joinery_data_root.sh luks_tpm2_reseal_if_due).
			_ = os.MkdirAll(filepath.Dir(dataRootTPM2FailedPath), 0755)
			_ = os.WriteFile(dataRootTPM2FailedPath, []byte(time.Now().UTC().Format("2006-01-02 15:04:05 UTC")+"\n"), 0644)
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	h, err := readEscrowHolder(escrowHolderPath)
	var id *unlockIdentity
	if err == nil {
		id, err = loadUnlockIdentity(unlockIdentityPath, false)
	}
	if err != nil {
		unlockSay("the data root of %s is locked; waiting for its recovery key", u.host)
		u.breakGlass(ctx)
		return u.wait(cancel)
	}
	unlockSay("the data root of %s is locked; asking its escrow holder, %s", u.host, h.URL)
	go u.escrow(ctx, h, id)
	go func() {
		sleepCtx(ctx, escrowFirstWait)
		if ctx.Err() == nil {
			unlockSay("the escrow holder has not answered in a minute; the recovery key is asked for as well")
			u.breakGlass(ctx)
		}
	}()
	return u.wait(cancel)
}

// wait returns what opened the volume, once something has, after the other
// ways have stopped: the console prompt is withdrawn, and the page's answer to
// the browser that unlocked it is sent before its ports are let go.
func (u *dataRootUnlocker) wait(cancel context.CancelFunc) string {
	how := <-u.done
	cancel()
	time.Sleep(1500 * time.Millisecond)
	return how
}

// breakGlass offers the recovery key both ways at once (D2a, D2b): the
// console prompt, and the unlock page on ports 80 and 443.
func (u *dataRootUnlocker) breakGlass(ctx context.Context) {
	go u.console(ctx)
	page, err := newUnlockPage(u)
	if err != nil {
		unlockSay("no unlock page: %v; the console still asks", err)
		return
	}
	go page.serve(ctx)
}

func (u *dataRootUnlocker) hasTPM2() bool {
	slots, err := luksSlotsOf(u.dev, u.conf.headerArgs()...)
	if err != nil {
		return false
	}
	for _, s := range slots {
		if s.Token == "systemd-tpm2" {
			return true
		}
	}
	return false
}

// openWith opens the volume with what the break-glass copy held: the volume
// key, or, while an encryption or its undo is part-way, the driving slot's
// secret, since a device part-way opens only through a key slot (D5). Once:
// whichever way gets there first opens it, and every later one finds it open.
func (u *dataRootUnlocker) openWith(material []byte, how string) error {
	if u.conf.Reencrypt != "" {
		return u.openWithSlot(material, u.conf.DrivingSlot, how)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if !mapperOpen() {
		if err := cryptsetupOpenVolumeKey(u.dev, material); err != nil {
			return err
		}
	}
	u.once.Do(func() { u.done <- how })
	return nil
}

// breakGlassSidecar is the copy the recovery key opens now: the volume key's,
// or while an encryption or its undo is part-way, the driving slot's.
func (c dataRootConfig) breakGlassSidecar() string {
	if c.Reencrypt != "" && c.DrivingSidecar != "" {
		return c.DrivingSidecar
	}
	return c.Sidecar
}

// keepDrivingKey puts the driving slot's secret back where the run reads it
// (joinery_data_root.sh encrypt-resume), in /run, so it resumes.
func keepDrivingKey(secret []byte) {
	dir := "/run/joinery/data-root-encrypt"
	_ = os.MkdirAll(dir, 0700)
	_ = os.WriteFile(filepath.Join(dir, "slot.key"), secret, 0600)
}

// console asks for the recovery key until one opens the volume. A key that
// does not open the break-glass copy is asked for again, saying why.
func (u *dataRootUnlocker) console(ctx context.Context) {
	ask := fmt.Sprintf("Recovery key for %s (its data is locked):", u.host)
	for ctx.Err() == nil {
		pasted, err := askPassword(ctx, ask)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			unlockSay("the console prompt failed (%v); asking again in 10 seconds", err)
			sleepCtx(ctx, 10*time.Second)
			continue
		}
		key, err := openSidecar(u.conf.breakGlassSidecar(), pasted)
		if err != nil {
			unlockSay("a recovery key was given at the console and refused: %v", err)
			ask = fmt.Sprintf("%s. Recovery key for %s:", upperFirst(err.Error()), u.host)
			continue
		}
		err = u.openWith(key, "the recovery key, at the console")
		zero(key)
		if err != nil {
			unlockSay("the recovery key opened the break-glass copy, but the volume did not open: %v", err)
			ask = fmt.Sprintf("The key is right, but the volume did not open (%v). Recovery key for %s:", err, u.host)
			continue
		}
		return
	}
}

// askPassword asks through systemd's password agents (the console's among
// them), with no timeout, masking what is typed.
func askPassword(ctx context.Context, prompt string) (string, error) {
	cmd := exec.CommandContext(ctx, "systemd-ask-password", "--timeout=0", "--echo=masked", "--id="+unlockAskID, prompt)
	// A prompt no longer needed is withdrawn the way systemd-ask-password
	// cleans up after itself, not left on the console.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.Output()
	return strings.TrimRight(string(out), "\r\n"), err
}

// cryptsetupOpenVolumeKey opens the mapping with the volume key, which
// reaches cryptsetup through a pipe (fd 3), never a file or an argument.
func cryptsetupOpenVolumeKey(dev string, volumeKey []byte) error {
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd := exec.Command("cryptsetup", "open", "--disable-keyring", "--key-size", "512",
		"--volume-key-file", "/dev/fd/3", dev, dataRootMapping)
	cmd.ExtraFiles = []*os.File{r}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		r.Close()
		w.Close()
		return err
	}
	r.Close()
	_, werr := w.Write(volumeKey)
	w.Close()
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("cryptsetup open: %v %s", err, strings.TrimSpace(stderr.String()))
	}
	return werr
}

func cryptsetupRun(args ...string) error {
	var stderr bytes.Buffer
	cmd := exec.Command("cryptsetup", args...)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return errors.New(msg)
		}
		return err
	}
	return nil
}

func mapperOpen() bool {
	_, err := os.Stat(dataRootMapperPath)
	return err == nil
}

// attachDataRoot returns what holds the volume: a device, or the image's loop
// device, set up here with direct I/O where the root disk allows it, and no
// discard, which would hand the image's space back to the root disk.
func attachDataRoot(conf dataRootConfig) (string, error) {
	if conf.Backing == "luks-device" {
		return conf.device(), nil
	}
	if out, err := exec.Command("losetup", "-n", "-O", "NAME", "-j", conf.Source).Output(); err == nil {
		if dev := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0]); dev != "" {
			return dev, nil
		}
	}
	out, err := exec.Command("losetup", "--direct-io=on", "--find", "--show", conf.Source).Output()
	if err != nil {
		out, err = exec.Command("losetup", "--find", "--show", conf.Source).Output()
		if err != nil {
			return "", fmt.Errorf("%s could not be attached to a loop device: %v", conf.Source, err)
		}
		unlockSay("the root disk refuses direct I/O; the loop device reads through the page cache")
	}
	dev := strings.TrimSpace(string(out))
	_ = os.WriteFile(filepath.Join("/sys/block", filepath.Base(dev), "queue/discard_max_bytes"), []byte("0"), 0644)
	return dev, nil
}

// unlockClose is the unit's stop: the mapping closed and the image's loop
// device let go, once the mount above them has gone.
func unlockClose(conf dataRootConfig) int {
	if _, err := readEscrowHolder(escrowHolderPath); err == nil && mapperOpen() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := escrowReport(ctx, "shutdown"); err != nil {
			unlockSay("the escrow holder was not told of the shutdown (%v)", err)
		}
		cancel()
	}
	if mapperOpen() {
		if err := cryptsetupRun("close", dataRootMapping); err != nil {
			return cliError("unlock --close: the data root's mapping did not close: %v", err)
		}
	}
	if conf.Backing == "luks-file" {
		out, _ := exec.Command("losetup", "-n", "-O", "NAME", "-j", conf.Source).Output()
		for _, dev := range strings.Fields(string(out)) {
			if err := exec.Command("losetup", "-d", dev).Run(); err != nil {
				unlockSay("%s did not detach: %v", dev, err)
			}
		}
	}
	return 0
}

// recordOpenedBy leaves what opened the volume where status reads it, for
// this boot only.
func recordOpenedBy(how string) {
	_ = os.MkdirAll(filepath.Dir(dataRootOpenedByPath), 0755)
	_ = os.WriteFile(dataRootOpenedByPath, []byte(how+", at "+time.Now().UTC().Format("2006-01-02 15:04:05 UTC")+"\n"), 0644)
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
