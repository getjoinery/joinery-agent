package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"joinery-agent/primitives"
)

// The node-posture job source: the agent polls its control plane outbound over
// HTTPS, claims one primitive job at a time, executes it under the node's own
// policy, and posts the result back. Polling doubles as the heartbeat — the
// plane's record of the last poll is what makes node liveness centrally visible
// without any inbound reachability (§3.1).

const (
	// agentMaxJobBody is the largest plane→agent response this agent will read.
	// It defends the NODE from its plane. Deliberately smaller than the plane's
	// own inbound cap: a job is a name and a few validated parameters, while a
	// result carries collected output.
	agentMaxJobBody = 64 * 1024

	// agentMaxResultBody is the plane's inbound cap, compiled in here too. The
	// agent checks its own result against it BEFORE posting: a result that
	// arrives too large is refused at the far end and lost, and a lost result
	// is a job that sits claimed until it times out. Trimming here means the
	// outcome is always reported, even when what it has to say is large.
	agentMaxResultBody = 256 * 1024

	// agentMaxLogBytes bounds the log text the agent posts back. What travels is
	// bounded by construction: past this the agent stops keeping bytes and
	// reports the real total separately, so the plane reads how much there was
	// rather than inferring it from how much arrived.
	agentMaxLogBytes = 128 * 1024

	// Poll interval bounds. The plane suggests a value; the node clamps it.
	// Everything from the wire is validated, including numbers that merely tune
	// this agent — a hostile plane must not be able to set 0 (a hot loop against
	// its own endpoint) or an hour (a channel that is dead but looks configured).
	minPollInterval     = 5 * time.Second
	maxPollInterval     = 300 * time.Second
	defaultPollInterval = 15 * time.Second

	// Backoff bounds for an unreachable or unhappy plane.
	maxRemoteBackoff = 5 * time.Minute

	remoteHTTPTimeout = 60 * time.Second
)

// Wire paths. Their own family, not under /api/v1/management/* — that family is
// the opposite direction (plane calls into a node's web tier) and is pinned
// status-only by §3.5.4.
const (
	pathClaim  = "/api/v1/agent/claim"
	pathResult = "/api/v1/agent/result"
)

// RemoteJob is one unit of work as the plane offers it. A primitive name and
// validated parameters — never a command string (§3.1).
type RemoteJob struct {
	JobID     int64                  `json:"job_id"`
	NodeID    int64                  `json:"node_id"`
	Primitive string                 `json:"primitive"`
	Params    map[string]interface{} `json:"params"`
	IssuedAt  string                 `json:"issued_at"`
}

// RemoteSource is the node-posture job source.
type RemoteSource struct {
	identity *NodeIdentity
	policy   *primitives.Policy
	env      *primitives.ExecEnv
	client   *http.Client

	pollInterval time.Duration
	backoff      time.Duration

	// jobLock serialises against the plane-local job source. One agent binary
	// may serve both postures (a control plane paired to itself is exactly how
	// this channel is tested), and two jobs running at once on one machine is
	// not something either source's concurrency guard was built to expect.
	jobLock *sync.Mutex

	// warned suppresses repeat logging of a steady-state complaint.
	warned map[string]bool

	// agentVersion travels on every claim. The plane recorded a node's agent
	// version once, at approval, and then never again — so a fleet that had
	// self-updated three times still read as the version it first paired with,
	// and the dashboard was confidently wrong for exactly the operation during
	// which someone needs it: a rollout. The poll is the one moment the node is
	// provably speaking for itself, so it is where the fact belongs.
	agentVersion string
}

// NewRemoteSource builds the source. Returns nil when this agent has no node
// identity, which is the normal state of a control-plane-only agent.
func NewRemoteSource(id *NodeIdentity, policy *primitives.Policy, env *primitives.ExecEnv, jobLock *sync.Mutex, agentVersion string) *RemoteSource {
	if id == nil {
		return nil
	}
	// The plane SUGGESTS a cadence; the node decides one. Anything the plane
	// sends — including a number that merely tunes this agent — goes through
	// the clamp, so a hostile plane cannot set 0 and get a hot loop against its
	// own endpoint, or set an hour and get a channel that is dead but looks
	// configured.
	interval := defaultPollInterval
	if id.PollSeconds != 0 {
		interval = clampPollInterval(id.PollSeconds)
	}

	return &RemoteSource{
		identity:     id,
		policy:       policy,
		env:          env,
		client:       newPlaneClient(id.TLSInsecure),
		pollInterval: interval,
		jobLock:      jobLock,
		warned:       map[string]bool{},
		agentVersion: agentVersion,
	}
}

func newPlaneClient(tlsInsecure bool) *http.Client {
	return &http.Client{
		Timeout: remoteHTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: tlsInsecure},
			TLSHandshakeTimeout: 15 * time.Second,
		},
	}
}

// clampPollInterval keeps a plane-supplied tuning value inside the range this
// binary was compiled to accept.
func clampPollInterval(seconds int) time.Duration {
	d := time.Duration(seconds) * time.Second
	if d < minPollInterval {
		return minPollInterval
	}
	if d > maxPollInterval {
		return maxPollInterval
	}
	return d
}

// Run polls until the context is cancelled.
func (r *RemoteSource) Run(ctx context.Context) {
	log.Printf("node posture: paired to %s as node #%d (%s); policy %s",
		r.identity.PlaneURL, r.identity.NodeID, r.identity.NodeSlug, r.policy.Describe())
	log.Printf("vocabulary compiled into this agent: %s", strings.Join(primitives.Names(), ", "))

	for {
		wait := r.pollInterval
		if r.backoff > 0 {
			wait = r.backoff
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		job, err := r.claim(ctx)
		if err != nil {
			r.noteFailure(err)
			continue
		}
		r.backoff = 0
		if job == nil {
			continue
		}
		r.runJob(ctx, job)
	}
}

// noteFailure backs off exponentially and logs the first occurrence of each
// distinct complaint, so an unreachable plane does not fill the log.
func (r *RemoteSource) noteFailure(err error) {
	if r.backoff == 0 {
		r.backoff = r.pollInterval
	} else {
		r.backoff *= 2
	}
	if r.backoff > maxRemoteBackoff {
		r.backoff = maxRemoteBackoff
	}
	key := err.Error()
	if !r.warned[key] {
		r.warned[key] = true
		log.Printf("plane poll failed (retrying, backoff now %s): %v", r.backoff, err)
	}
}

// claim asks the plane for one job.
func (r *RemoteSource) claim(ctx context.Context) (*RemoteJob, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"node_id":       r.identity.NodeID,
		"agent_version": r.agentVersion,
	})

	raw, err := r.signedPost(ctx, pathClaim, body)
	if err != nil {
		return nil, err
	}

	var payload struct {
		Job *RemoteJob `json:"job"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("plane sent an unreadable claim response: %w", err)
	}
	if payload.Job == nil {
		return nil, nil
	}

	// The plane routes; the node checks. A job whose node is not this node is
	// refused rather than run, whatever the plane's routing believed — the
	// signature already proves who asked, and this proves who was answered.
	if payload.Job.NodeID != r.identity.NodeID {
		log.Printf("REFUSED job #%d: the plane offered a job addressed to node #%d, and this is node #%d",
			payload.Job.JobID, payload.Job.NodeID, r.identity.NodeID)
		r.postResult(ctx, payload.Job.JobID, "refused", nil, "",
			fmt.Sprintf("this job is addressed to node #%d; this agent is node #%d",
				payload.Job.NodeID, r.identity.NodeID))
		return nil, nil
	}
	if payload.Job.JobID <= 0 {
		return nil, fmt.Errorf("plane offered a job with no id")
	}

	return payload.Job, nil
}

// runJob executes one primitive and reports the outcome.
func (r *RemoteSource) runJob(ctx context.Context, job *RemoteJob) {
	r.jobLock.Lock()
	defer r.jobLock.Unlock()

	// Held for exactly as long as the lock is, because they answer the same
	// question from two sides: the lock stops this agent swapping its own binary
	// mid-job, and the marker stops install_agent.sh doing it from the outside
	// when a job runs the upgrade or the host installers. See jobmarker.go.
	clearJobMarker := markJobRunning(job.JobID)
	defer clearJobMarker()

	log.Printf("claimed job #%d from plane: primitive=%s", job.JobID, job.Primitive)

	result, err := primitives.Execute(ctx, r.env, r.policy, primitives.Request{
		JobID:     job.JobID,
		Primitive: job.Primitive,
		Params:    job.Params,
	})

	switch {
	case primitives.Refused(err):
		log.Printf("REFUSED job #%d (%s): %v", job.JobID, job.Primitive, err)
		r.postResult(ctx, job.JobID, "refused", nil, "", err.Error())
	case err != nil:
		log.Printf("job #%d (%s) FAILED: %v", job.JobID, job.Primitive, err)
		r.postResult(ctx, job.JobID, "failed", result, "", err.Error())
	default:
		log.Printf("job #%d (%s) completed", job.JobID, job.Primitive)
		r.postResult(ctx, job.JobID, "completed", result, "", "")
	}

	// A primitive may ask this process to end — restart_agent is the one that
	// does. It cannot exit from inside itself: the result has to be posted
	// first, or the job stays claimed until the plane's timeout returns it to
	// pending and the restarted agent runs it again, which reads as a hang and
	// then repeats. So the primitive records the intent and it is acted on here,
	// after the post above has returned.
	//
	// The exit is unconditional once requested. Whether anything will start this
	// agent again was settled inside the primitive, which refuses when the answer
	// is no; re-deciding it here would be a second opinion on a question already
	// answered with better information.
	if restart, by := primitives.ConsumeRestartRequest(); restart {
		log.Printf("job #%d asked this agent to restart — exiting; %s", job.JobID, by)
		// Explicitly, because os.Exit runs no deferred function. A marker left
		// behind by a deliberate exit names a pid that is gone, so the installer
		// would clear it as stale anyway — but leaving one is leaving a lie
		// about this node on its own disk.
		clearJobMarker()
		os.Exit(0)
	}
}

// postResult reports a terminal outcome. A failure to post is logged and
// dropped: the plane's claim timeout returns the job to pending, which is the
// same recovery path a crashed agent takes.
func (r *RemoteSource) postResult(ctx context.Context, jobID int64, status string, data map[string]interface{}, logText, reason string) {
	kept, total := capLog(logText)

	payload := map[string]interface{}{
		"node_id":         r.identity.NodeID,
		"job_id":          jobID,
		"status":          status,
		"log":             kept,
		"log_total_bytes": total,
	}
	if len(kept) < total {
		payload["log_truncated"] = true
	}
	if data != nil {
		payload["data"] = data
	}
	if reason != "" {
		payload["refusal_reason"] = reason
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("ERROR: could not encode result for job #%d: %v", jobID, err)
		return
	}

	// Shed, in order of what the plane can most afford to lose: the log first,
	// then the collected data. The STATUS always survives — a job whose outcome
	// never arrives is a job that sits claimed until it times out, and a
	// timeout says nothing about what actually happened.
	if len(body) > agentMaxResultBody {
		log.Printf("job #%d result is %d bytes, over the %d-byte limit — shedding the log",
			jobID, len(body), agentMaxResultBody)
		payload["log"] = ""
		payload["log_truncated"] = true
		body, _ = json.Marshal(payload)
	}
	if len(body) > agentMaxResultBody {
		log.Printf("job #%d result is still %d bytes — reporting the outcome without its data", jobID, len(body))
		delete(payload, "data")
		payload["refusal_reason"] = "the result was too large to post; the outcome is reported without it"
		body, _ = json.Marshal(payload)
	}

	if _, err := r.signedPost(ctx, pathResult, body); err != nil {
		log.Printf("ERROR: could not post result for job #%d (the plane will time the claim out and re-queue it): %v", jobID, err)
	}
}

func capLog(text string) (kept string, total int) {
	if len(text) <= agentMaxLogBytes {
		return text, len(text)
	}
	return text[:agentMaxLogBytes], len(text)
}

// signedPost issues one signed request and returns the envelope's data field.
func (r *RemoteSource) signedPost(ctx context.Context, path string, body []byte) (json.RawMessage, error) {
	return signedPlanePost(ctx, r.client, r.identity, path, body)
}

// signedPlanePost is the signed request itself, shared with the leave path
// (leave.go), which must be able to sign without a running job source.
func signedPlanePost(ctx context.Context, client *http.Client, id *NodeIdentity, path string, body []byte) (json.RawMessage, error) {
	url := strings.TrimRight(id.PlaneURL, "/") + path

	sum := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(sum[:])
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Joinery-Agent-Node", strconv.FormatInt(id.NodeID, 10))
	req.Header.Set("X-Joinery-Agent-Timestamp", timestamp)
	req.Header.Set("X-Joinery-Agent-Nonce", nonce)
	req.Header.Set("X-Joinery-Agent-Signature", id.Sign(http.MethodPost, path, timestamp, nonce, bodyHash))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return readCappedEnvelope(resp, url)
}

// readCappedEnvelope reads a plane response under the node's inbound cap.
//
// It reads ONE BYTE PAST the cap on purpose. Reading exactly the cap is
// ambiguous — a whole answer of that length looks identical to the front of a
// longer one — so a truncated response would be handed to the JSON parser and
// come back as "the plane sent nonsense" instead of "the plane sent too much".
func readCappedEnvelope(resp *http.Response, url string) (json.RawMessage, error) {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, agentMaxJobBody+1))
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", url, err)
	}
	if len(raw) > agentMaxJobBody {
		return nil, fmt.Errorf("plane response from %s exceeds this agent's %d-byte limit — refused unread",
			url, agentMaxJobBody)
	}

	var envelope struct {
		Data  json.RawMessage `json:"data"`
		Error string          `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("plane response from %s is not valid JSON (HTTP %d)", url, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		message := envelope.Error
		if message == "" {
			message = "no reason given"
		}
		return nil, fmt.Errorf("plane returned HTTP %d for %s: %s", resp.StatusCode, url, message)
	}
	return envelope.Data, nil
}

// Enrollment lives in join.go: the node-initiated join (Phase 1.5, A6). No
// token-based Pair exists — the agent generates its keypair when the local
// admin names a management node, and approval over there is the binding.
