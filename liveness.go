package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"joinery-agent/primitives"
)

// The liveness watch: a hung agent is restarted, not only a dead one (agent
// restart audit H1).
//
// A crashed agent always came back: systemd's Restart=always, or the cron
// keepalive in a container. An agent that was still running but no longer doing
// anything — its poll loop stuck, a word that never returned after its deadline
// — was restarted by nothing, and its management node only opened an incident
// after two hours of silence.
//
// So the agent tells its supervisor, every half minute, that it is alive, and
// only while it is:
//
//   - systemd: a WATCHDOG=1 notification. The agent states the watchdog's
//     timeout itself (WATCHDOG_USEC), rather than the unit carrying WatchdogSec,
//     so a unit converged ahead of its binary never starts killing an older
//     agent that sends nothing. The unit only allows the messages
//     (NotifyAccess=main). When they stop, systemd aborts it and Restart=always
//     starts it again.
//   - everywhere: the time, written to primitives.AliveFile. The container keepalive
//     (install_agent.sh's joinery-agent-supervise) restarts an agent whose file
//     has gone stale.
//
// What counts as hung:
//
//   - A watched loop (the poll that claims work, the self-update check) has not
//     come round for its limit, while no word is running within its deadline. A
//     word inside its deadline holds the job lock legitimately, for up to the
//     four hours a restore may take, and the poll waits for it.
//   - A word still running livenessOverdueGrace past its own deadline.
//
// Nothing here exits the process. A watch that could not say "alive" any more
// says why, once, with every goroutine's stack, and leaves the restart to the
// supervisor: the one part of this that a hung process cannot get wrong.

const (
	livenessCheckInterval = 30 * time.Second
	// What systemd is told: the time after the last "alive" before it acts.
	livenessWatchdogTimeout = 3 * time.Minute
	// How far past its own deadline a word may run before it is a hang. The
	// word's context has expired by then; a script is killed at the deadline,
	// and only something that ignores that is still here.
	livenessOverdueGrace = 10 * time.Minute
	// A poll comes round within maxPollInterval or maxRemoteBackoff (5 min)
	// plus two plane requests (remoteHTTPTimeout each); the self-update check
	// every minute. Twenty minutes is well clear of both.
	pollQuietLimit   = 20 * time.Minute
	updateQuietLimit = 20 * time.Minute
)

type loopBeat struct {
	last  time.Time
	limit time.Duration
}

type liveness struct {
	mu      sync.Mutex
	loops   map[string]*loopBeat
	stated  string // the problem last logged; "" while healthy
	now     func() time.Time
	working func(time.Time) bool
	overdue func(time.Time, time.Duration) []string
	notify  func(string) error
	alive   func(time.Time) error
}

func newLiveness() *liveness {
	return &liveness{
		loops:   map[string]*loopBeat{},
		now:     time.Now,
		working: primitives.RunningWithinDeadline,
		overdue: primitives.OverdueRuns,
		notify:  sdNotify,
		alive:   writeAliveFile,
	}
}

// agentLiveness is the running process's watch. A loop that is not watched
// (in tests, or a CLI invocation) beats into nothing.
var agentLiveness = newLiveness()

// watch starts counting a loop, as of now.
func (l *liveness) watch(name string, limit time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.loops[name] = &loopBeat{last: l.now(), limit: limit}
}

// beat records that a watched loop came round.
func (l *liveness) beat(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok := l.loops[name]; ok {
		b.last = l.now()
	}
}

// problem is why this agent is not alive right now, or "".
func (l *liveness) problem(now time.Time) string {
	if late := l.overdue(now, livenessOverdueGrace); len(late) > 0 {
		return "still running past its deadline: " + strings.Join(late, ", ")
	}
	if l.working(now) {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	names := make([]string, 0, len(l.loops))
	for name := range l.loops {
		names = append(names, name)
	}
	sort.Strings(names)
	var quiet []string
	for _, name := range names {
		b := l.loops[name]
		if gap := now.Sub(b.last); gap > b.limit {
			quiet = append(quiet, fmt.Sprintf("the %s loop has not come round for %s", name, gap.Round(time.Second)))
		}
	}
	return strings.Join(quiet, "; ")
}

// tick says "alive" when the agent is, and says why once when it is not.
func (l *liveness) tick() {
	now := l.now()
	p := l.problem(now)
	if p == "" {
		if l.stated != "" {
			log.Printf("liveness: recovered (%s); telling the supervisor this agent is alive again", l.stated)
			l.stated = ""
		}
		_ = l.notify("WATCHDOG=1")
		if err := l.alive(now); err != nil {
			// Not a reason to stop: systemd still hears from us. Said every
			// tick would be noise; once per process is enough.
			aliveWriteFailedOnce.Do(func() { log.Printf("liveness: could not write %s: %v", primitives.AliveFile, err) })
		}
		return
	}
	if p != l.stated {
		log.Printf("liveness: NOT ALIVE — %s. No longer telling the supervisor this agent is alive; it restarts the agent within %s. Every goroutine's stack follows.",
			p, livenessWatchdogTimeout)
		buf := make([]byte, 1<<20)
		log.Printf("liveness: goroutines:\n%s", buf[:runtime.Stack(buf, true)])
		l.stated = p
	}
}

var aliveWriteFailedOnce sync.Once

// Run states the watchdog's timeout to systemd, then checks every
// livenessCheckInterval until the context ends.
func (l *liveness) Run(ctx context.Context) {
	_ = l.notify("WATCHDOG_USEC=" + strconv.FormatInt(livenessWatchdogTimeout.Microseconds(), 10))
	l.tick()
	t := time.NewTicker(livenessCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.tick()
		}
	}
}

// sdNotify sends one sd_notify(3) message. No socket, no message: the agent
// is not under systemd, or its unit does not allow notifications.
// notifySocket is systemd's notification address, taken from the environment
// once, before anything runs, and then removed from it (sd_notify(3)'s
// unset_environment). Left in the environment, every child the agent starts
// inherits it, and a systemctl among them reports its own exit status there,
// which systemd refuses and logs (NotifyAccess=main), about twice a minute on
// every machine (copy-final, B41).
var notifySocket = takeNotifySocket()

func takeNotifySocket() string {
	socket := os.Getenv("NOTIFY_SOCKET")
	os.Unsetenv("NOTIFY_SOCKET")
	return socket
}

func sdNotify(state string) error {
	socket := notifySocket
	if socket == "" {
		return nil
	}
	if strings.HasPrefix(socket, "@") {
		socket = "\x00" + socket[1:] // an abstract socket
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}

func writeAliveFile(now time.Time) error {
	if err := os.MkdirAll(filepath.Dir(primitives.AliveFile), 0755); err != nil {
		return err
	}
	return os.WriteFile(primitives.AliveFile, []byte(strconv.FormatInt(now.Unix(), 10)+"\n"), 0644)
}
