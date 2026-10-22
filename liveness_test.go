package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The liveness watch says "alive" only while the agent is (agent restart audit
// H1). These pin what counts as hung, and that silence is the whole signal.

type livenessRig struct {
	l        *liveness
	now      time.Time
	working  bool
	overdue  []string
	notified []string
	alive    int
}

func newLivenessRig() *livenessRig {
	r := &livenessRig{now: time.Date(2026, 10, 22, 3, 0, 0, 0, time.UTC)}
	r.l = &liveness{
		loops:   map[string]*loopBeat{},
		now:     func() time.Time { return r.now },
		working: func(time.Time) bool { return r.working },
		overdue: func(time.Time, time.Duration) []string { return r.overdue },
		notify:  func(s string) error { r.notified = append(r.notified, s); return nil },
		alive:   func(time.Time) error { r.alive++; return nil },
	}
	return r
}

func (r *livenessRig) watchdogBeats() int {
	n := 0
	for _, s := range r.notified {
		if s == "WATCHDOG=1" {
			n++
		}
	}
	return n
}

func TestLivenessAliveWhileLoopsComeRound(t *testing.T) {
	r := newLivenessRig()
	r.l.watch("poll", pollQuietLimit)
	for i := 0; i < 10; i++ {
		r.now = r.now.Add(5 * time.Minute)
		r.l.beat("poll")
		r.l.tick()
	}
	if r.watchdogBeats() != 10 || r.alive != 10 {
		t.Fatalf("a loop coming round every 5 minutes is alive at every tick: notified %v, alive file %d", r.notified, r.alive)
	}
}

func TestLivenessQuietLoopStopsTheBeat(t *testing.T) {
	r := newLivenessRig()
	r.l.watch("poll", pollQuietLimit)
	r.now = r.now.Add(pollQuietLimit - time.Second)
	r.l.tick()
	if r.watchdogBeats() != 1 {
		t.Fatalf("inside the limit the agent is alive")
	}
	r.now = r.now.Add(2 * time.Second)
	r.l.tick()
	r.l.tick()
	if r.watchdogBeats() != 1 || r.alive != 1 {
		t.Fatalf("a poll quiet past its limit must stop both signals: notified %v, alive file %d", r.notified, r.alive)
	}
	if !strings.Contains(r.l.stated, "the poll loop has not come round") {
		t.Errorf("the reason names the loop: %q", r.l.stated)
	}
	r.l.beat("poll")
	r.l.tick()
	if r.watchdogBeats() != 2 || r.l.stated != "" {
		t.Errorf("a loop that comes round again is alive again")
	}
}

func TestLivenessWordWithinDeadlineHoldsTheLockLegitimately(t *testing.T) {
	r := newLivenessRig()
	r.l.watch("poll", pollQuietLimit)
	r.working = true
	r.now = r.now.Add(4 * time.Hour) // a restore's whole budget, no poll meanwhile
	r.l.tick()
	if r.watchdogBeats() != 1 {
		t.Fatalf("a word inside its deadline is work, not a hang")
	}
	r.working = false
	r.l.tick()
	if r.watchdogBeats() != 1 {
		t.Fatalf("once it is done the poll must come round again within its limit")
	}
}

func TestLivenessOverdueWordIsAHangEvenWhileOthersWork(t *testing.T) {
	r := newLivenessRig()
	r.working = true
	r.overdue = []string{"backup_site (deadline 2026-10-22T01:00:00Z)"}
	r.l.tick()
	if r.watchdogBeats() != 0 || r.alive != 0 {
		t.Fatalf("a word far past its deadline is the hang: notified %v", r.notified)
	}
	if !strings.Contains(r.l.stated, "backup_site") {
		t.Errorf("the reason names the word: %q", r.l.stated)
	}
}

func TestLivenessNothingWatchedIsAlive(t *testing.T) {
	// An agent still waiting for its config has no loops yet; it is alive.
	r := newLivenessRig()
	r.now = r.now.Add(24 * time.Hour)
	r.l.tick()
	if r.watchdogBeats() != 1 {
		t.Fatalf("no watched loop and no word: alive")
	}
}

func TestLivenessBeatOnUnwatchedLoopIsHarmless(t *testing.T) {
	r := newLivenessRig()
	r.l.beat("poll") // a RemoteSource in a test, never Run
	if len(r.l.loops) != 0 {
		t.Fatalf("a beat must not start watching a loop")
	}
}

func TestLivenessRunStatesTheTimeoutFirst(t *testing.T) {
	r := newLivenessRig()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.l.Run(ctx)
	if len(r.notified) < 2 || r.notified[0] != "WATCHDOG_USEC=180000000" || r.notified[1] != "WATCHDOG=1" {
		t.Fatalf("Run states the watchdog timeout, then says alive at once: %v", r.notified)
	}
}

func TestSdNotifyWritesToTheSocket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notify.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Skipf("no unix datagram sockets here: %v", err)
	}
	defer conn.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	if err := sdNotify("WATCHDOG=1"); err != nil {
		t.Fatalf("sdNotify: %v", err)
	}
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := conn.ReadFromUnix(buf)
	if err != nil || string(buf[:n]) != "WATCHDOG=1" {
		t.Fatalf("the socket got %q (%v)", buf[:n], err)
	}

	t.Setenv("NOTIFY_SOCKET", "")
	if err := sdNotify("WATCHDOG=1"); err != nil {
		t.Errorf("no socket is no supervisor, not an error: %v", err)
	}
}

func TestWriteAliveFile(t *testing.T) {
	old := AliveFile
	AliveFile = filepath.Join(t.TempDir(), "run", "alive")
	defer func() { AliveFile = old }()
	if err := writeAliveFile(time.Unix(1792600000, 0)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(AliveFile)
	if err != nil || strings.TrimSpace(string(b)) != "1792600000" {
		t.Fatalf("the file holds the unix time: %q %v", b, err)
	}
}

func TestUnitAllowsNotifications(t *testing.T) {
	// Without NotifyAccess a Type=simple unit drops every message, and the
	// watch would protect nothing on a systemd host.
	if !strings.Contains(string(embeddedUnit), "\nNotifyAccess=main\n") {
		t.Fatal("install/joinery-agent.service must carry NotifyAccess=main")
	}
	if strings.Contains(string(embeddedUnit), "\nWatchdogSec=") {
		t.Fatal("the agent states its own watchdog timeout; a WatchdogSec in the unit would kill an older agent that sends nothing")
	}
}
