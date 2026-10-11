package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"strings"
	"time"
)

// EscrowReportWatcher keeps the escrow holder's record of this machine true
// (specs/hosted_data_promise_disk_encryption.md D3, D2b): the addresses it may
// ask from, both families, and the break-glass copy's box. The machine says
// so itself, signed with its unlock identity, because the holder may not be
// its plane and would otherwise never hear of an IP swap or a re-seal.
//
// It reports when what it would say has changed since it last said it, and
// once a day regardless, so a holder restored from an older backup catches up.
type EscrowReportWatcher struct {
	interval time.Duration
	state    string // the state file: a hash of what was last reported
}

const (
	escrowReportInterval = 5 * time.Minute
	escrowReportStale    = 24 * time.Hour
	escrowReportState    = "/run/joinery/escrow-report.state"
)

func (w *EscrowReportWatcher) Run(ctx context.Context) {
	interval, state := w.interval, w.state
	if interval <= 0 {
		interval = escrowReportInterval
	}
	if state == "" {
		state = escrowReportState
	}
	lastErr := ""
	for {
		if err := w.once(ctx, state); err != nil && err.Error() != lastErr {
			log.Printf("escrow: the holder was not told of this machine's addresses: %v", err)
			lastErr = err.Error()
		} else if err == nil {
			lastErr = ""
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func (w *EscrowReportWatcher) once(ctx context.Context, statePath string) error {
	h, err := readEscrowHolder(escrowHolderPath)
	if err != nil || !mapperOpen() {
		return nil // not enrolled, or locked: the unlock reports for itself
	}
	conf, _ := readDataRootConfig(dataRootConfPath)
	sum := sha256.Sum256([]byte(h.URL + "\n" + strings.Join(machineAddresses(), ",") + "\n" + sidecarBox(conf)))
	now := hex.EncodeToString(sum[:])
	if prev, err := os.ReadFile(statePath); err == nil {
		fi, _ := os.Stat(statePath)
		if strings.TrimSpace(string(prev)) == now && fi != nil && time.Since(fi.ModTime()) < escrowReportStale {
			return nil
		}
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := escrowReport(rctx, "addresses"); err != nil {
		return err
	}
	_ = os.MkdirAll("/run/joinery", 0755)
	return os.WriteFile(statePath, []byte(now+"\n"), 0644)
}
