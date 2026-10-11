package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The agent's outbox: a job's result is kept on disk until the management
// node has taken it.
//
// THE PROBLEM. A result used to be posted once, and a post that failed was
// logged and dropped. The job then sat 'running' on the management node for
// its whole claim budget, and the budget's end handed it out AGAIN. That is
// what happened to getjoinery's data root move (job 536, 2026-10-10): the move
// finished in seconds, its one result post landed on a management node that
// the move's own restart had just broken, and the node's queue was held for
// four hours with a second, unattended move waiting at the end of them.
//
// THE RULE. A result is written here before it is posted, and removed only
// when the management node has answered for good: it took it, or it said it
// never will (any 4xx — the job is not this node's, not running, or the body
// is one it refuses; sending the same bytes again cannot change that). A
// network failure, a 5xx or an answer that is not the management node's JSON
// keeps it. The poll delivers every kept result BEFORE it claims, and claims
// nothing while one is still undelivered — so a claim that says idle is true:
// this process runs no job and owes no result, and the management node can
// fail as lost whatever it still has running for this node.
//
// The directory sits beside the job-running marker, under the root-owned
// directory the installer creates, so it survives a restart and a reboot. It
// is a var so the tests can point it at a temporary directory.
var resultOutboxDir = filepath.Join(agentConfigDir, "outbox")

// On a machine whose data root is encrypted, a result is kept on the data root
// while it is mounted: a job's result can carry what the data root holds, and
// the root disk is plain (specs/hosted_data_promise_disk_encryption.md D10).
// While it is locked, what runs reads nothing of it, and a result is kept where
// it always was. Both are read back. Vars so the tests can point them away.
var (
	dataRootOutboxDir   = "/srv/joinery/agent-outbox"
	outboxDataRootConf  = dataRootConfPath
	outboxDataRootMount = "/srv/joinery"
)

// outboxDir is where a result is kept now.
func outboxDir() string {
	conf, err := readDataRootConfig(outboxDataRootConf)
	if err == nil && conf.encrypted() && isMountPoint(outboxDataRootMount) {
		return dataRootOutboxDir
	}
	return resultOutboxDir
}

// planeStatusError is a management node answer that was not a 200: the HTTP
// status, kept so a caller can tell "never" from "not now".
type planeStatusError struct {
	Status int
	msg    string
}

func (e *planeStatusError) Error() string { return e.msg }

// planeAnsweredForGood reports whether err is the management node refusing for
// good: a 4xx, but for a rate limit or a clock refusal. Everything else — no
// answer, a 5xx, a page that is not its JSON — may go differently next time.
func planeAnsweredForGood(err error) bool {
	var pe *planeStatusError
	if !errors.As(err, &pe) || pe.Status < 400 || pe.Status >= 500 {
		return false
	}
	// Two 4xx answers are about the moment, not the result: a rate limit,
	// and a request signed with a clock too far from the management node's
	// (its own words, matched as dropExtrasIfRefused matches its refusals).
	// Sent again once the clock or the limit has moved, the same bytes land.
	if pe.Status == 429 || (pe.Status == 401 && strings.Contains(pe.msg, "too far from this plane's clock")) {
		return false
	}
	return true
}

func outboxPath(jobID int64) string {
	return outboxPathIn(outboxDir(), jobID)
}

func outboxPathIn(dir string, jobID int64) string {
	return filepath.Join(dir, strconv.FormatInt(jobID, 10)+".json")
}

// keepResult writes a result body to the outbox, atomically. A failure is
// logged and otherwise ignored: the result is still posted, and losing it to
// a failed post is the behaviour this file replaces, not a new one.
func keepResult(jobID int64, body []byte) {
	dir := outboxDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("WARNING: could not keep the result of job #%d for redelivery: %v", jobID, err)
		return
	}
	tmp := outboxPathIn(dir, jobID) + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		log.Printf("WARNING: could not keep the result of job #%d for redelivery: %v", jobID, err)
		_ = os.Remove(tmp)
		return
	}
	if err := os.Rename(tmp, outboxPathIn(dir, jobID)); err != nil {
		log.Printf("WARNING: could not keep the result of job #%d for redelivery: %v", jobID, err)
		_ = os.Remove(tmp)
		return
	}
	// One copy: a result kept in the other place before is this one now.
	for _, other := range outboxDirs() {
		if other != dir {
			_ = os.Remove(outboxPathIn(other, jobID))
		}
	}
}

// outboxDirs is every place a result may be kept.
func outboxDirs() []string {
	return []string{resultOutboxDir, dataRootOutboxDir}
}

// dropResult removes a delivered (or refused-for-good) result.
func dropResult(jobID int64) {
	for _, dir := range outboxDirs() {
		if err := os.Remove(outboxPathIn(dir, jobID)); err != nil && !os.IsNotExist(err) {
			log.Printf("WARNING: could not remove the delivered result of job #%d: %v", jobID, err)
		}
	}
}

// How long a kept result is tried as it was, and then at all. A body the
// management node will not take, behind something that does not say so in its
// words (a firewall in front of it answering one log line with an HTML 403),
// would otherwise stop this agent claiming for good, and only a root shell
// could clear it. After keptShedAfter it is sent as its outcome alone — the
// shedding postResult already does for size — and after keptDropAfter it is
// dropped, loudly. By then the management node has failed the job as lost and
// a person decides what to do about it (reviewer2 F3).
var (
	keptShedAfter = time.Hour
	keptDropAfter = 24 * time.Hour
)

type keptResult struct {
	JobID int64
	Body  []byte
	Kept  time.Time
}

// keptResults lists the outbox, oldest job first. A file that is not a
// result this agent wrote (a name that is not a job id, or one that cannot
// be read) is removed and said, so one bad file can never stop the poll.
func keptResults() []keptResult {
	var out []keptResult
	seen := map[int64]bool{}
	for _, dir := range outboxDirs() {
		for _, k := range keptResultsIn(dir) {
			if !seen[k.JobID] {
				seen[k.JobID] = true
				out = append(out, k)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].JobID < out[j].JobID })
	return out
}

func keptResultsIn(dir string) []keptResult {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []keptResult
	for _, e := range entries {
		name := e.Name()
		path := filepath.Join(dir, name)
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			if strings.HasSuffix(name, ".tmp") {
				_ = os.Remove(path) // a write cut off by a crash
			}
			continue
		}
		id, err := strconv.ParseInt(strings.TrimSuffix(name, ".json"), 10, 64)
		if err != nil || id <= 0 {
			log.Printf("WARNING: removing %s from the result outbox: not a job's result", path)
			_ = os.Remove(path)
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil || len(body) == 0 || len(body) > agentMaxResultBody {
			log.Printf("WARNING: removing the kept result of job #%d: it cannot be read back", id)
			_ = os.Remove(path)
			continue
		}
		kept := time.Now()
		if info, err := e.Info(); err == nil {
			kept = info.ModTime()
		}
		out = append(out, keptResult{JobID: id, Body: body, Kept: kept})
	}
	return out
}

// deliverKeptResults posts every kept result, oldest first. It reports false
// when one could not be delivered now; the caller then claims nothing, so a
// job whose result is still owed is never told to the management node as lost.
func (r *RemoteSource) deliverKeptResults(ctx context.Context) bool {
	for _, k := range keptResults() {
		age := time.Since(k.Kept)
		if age > keptDropAfter {
			log.Printf("ERROR: the result of job #%d could not be delivered for %s; dropped. The management node "+
				"has failed the job as lost: check the node before running it again", k.JobID, age.Round(time.Minute))
			dropResult(k.JobID)
			continue
		}
		if age > keptShedAfter {
			if shed, ok := shedToOutcome(k.Body); ok {
				k.Body = shed
				keepShed(k)
			}
		}
		_, err := r.signedPost(ctx, pathResult, k.Body)
		switch {
		case err == nil:
			log.Printf("delivered the kept result of job #%d", k.JobID)
			dropResult(k.JobID)
		case planeAnsweredForGood(err):
			log.Printf("the management node will not take the kept result of job #%d (%v); dropped", k.JobID, err)
			dropResult(k.JobID)
		default:
			r.noteFailure(fmt.Errorf("delivering the kept result of job #%d: %w", k.JobID, err))
			return false
		}
	}
	return true
}

// shedToOutcome is a kept result body with its data and log taken out: the
// outcome alone, with a note saying why. ok is false when the body is already
// that, or is not one this agent wrote.
func shedToOutcome(body []byte) ([]byte, bool) {
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, false
	}
	if _, has := payload["data"]; !has && payload["log"] == "" {
		return nil, false
	}
	delete(payload, "data")
	payload["log"] = ""
	payload["log_truncated"] = true
	if reason, _ := payload["refusal_reason"].(string); reason == "" {
		payload["refusal_reason"] = "the full result could not be delivered; only the outcome is reported"
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}
	return out, true
}

// keepShed rewrites a kept result as its shed body, keeping the time it was
// first kept so the drop bound still counts from then.
func keepShed(k keptResult) {
	keepResult(k.JobID, k.Body)
	_ = os.Chtimes(outboxPath(k.JobID), k.Kept, k.Kept)
}
