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
	pathClaim    = "/api/v1/agent/claim"
	pathResult   = "/api/v1/agent/result"
	pathArtifact = "/api/v1/agent/artifact"
)

// What the artifact endpoint may be asked for. A flat, compiled-in set: the
// node names one of these five things and nothing else, so there is no shape
// in which a request from here becomes a path over there.
const (
	artifactKindAgentManifest   = "agent_manifest"
	artifactKindAgentBinary     = "agent_binary"
	artifactKindBundleInfo      = "bundle_manifest"
	artifactKindBundleBody      = "bundle_body"
	artifactKindReleaseManifest = "release_manifest"
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

	// extrasDropped latches when the plane refuses a field this agent added.
	//
	// The plane validates a claim STRICTLY — an undeclared key is refused, not
	// ignored — which is the right rule and makes a newer agent's extra fields
	// fatal against an older plane. In this fleet the plane is always upgraded
	// first, because the agent artifact ships inside the core release; but "in
	// practice first" is not an ordering guarantee, and a node whose site
	// upgraded ahead of its management node would otherwise stop claiming
	// altogether. Dropping the extras costs the plane a capability report;
	// dropping the claim costs it the node.
	extrasDropped bool

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

// scriptTrust is this node's own answer to whether it can verify the scripts it
// would run as root — the state that otherwise only becomes visible when a job
// is dispatched and refused.
//
// It reports on the MANIFEST, never on a file, for the same reason recovery
// fires only on the manifest: a file that fails its hash is a different event
// with an opposite remedy, and flattening the two into one health colour would
// have the dashboard recommend the wrong thing.
//
// Empty when there is nothing to report on — a machine with no site tree, or a
// verifier that is not manifest-backed. Silence, not a claim of health.
func (r *RemoteSource) scriptTrust() string {
	if r.env == nil {
		return ""
	}
	artifacts, ok := r.env.Manifest.(*primitives.ArtifactManifests)
	if !ok || artifacts == nil {
		return ""
	}
	if err := artifacts.Usable(""); err != nil {
		return "untrusted_manifest"
	}
	return "ok"
}

// claim asks the plane for one job.
func (r *RemoteSource) claim(ctx context.Context) (*RemoteJob, error) {
	claimBody := map[string]interface{}{
		"node_id":       r.identity.NodeID,
		"agent_version": r.agentVersion,
	}
	if !r.extrasDropped {
		// The node's own account of what it can do, sent on every poll for the
		// same reason the version is: this is the one moment the machine speaks
		// for itself, and the plane must never GUESS a node's vocabulary. The
		// first apply_update rollout dispatched the new primitive to nine
		// agents that predated it and all nine refused — a plane reading a
		// version number and inferring a capability from it.
		claimBody["primitives"] = strings.Join(primitives.Names(), ",")
		// Empty on a machine with no support bundle, which is every machine
		// that has a site tree to verify scripts against. It is the only
		// evidence the plane gets that the bundle actually landed somewhere.
		claimBody["bundle_version"] = installedBundleVersion()
		// Whether this node can verify the scripts it would run as root.
		//
		// The plane can already work this out from a refusal, but only for a
		// node it has sent a job to. A node that is refusing and has nothing
		// dispatched to it says nothing at all — and it polls every cycle, so
		// this is the one moment it can. Empty means "no answer", which is what
		// an older agent and a siteless machine both look like; the plane must
		// not read that as good news.
		if v := r.scriptTrust(); v != "" {
			claimBody["script_trust"] = v
		}
	}
	body, _ := json.Marshal(claimBody)

	raw, err := r.signedPost(ctx, pathClaim, body)
	if err != nil {
		if r.dropExtrasIfRefused(err) {
			return nil, nil
		}
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

// dropExtrasIfRefused reads one refusal and decides whether this agent is
// talking to a plane that predates the fields it just sent. Reports whether it
// latched, in which case the caller simply tries again next poll with the older
// shape.
//
// It matches on the plane's own words for an undeclared field, which is a
// narrow thing to depend on — and the failure of the match is not silent
// breakage but the status quo: the node keeps reporting the error it is already
// reporting, until the plane it answers is upgraded.
func (r *RemoteSource) dropExtrasIfRefused(err error) bool {
	if r.extrasDropped || !strings.Contains(err.Error(), "undeclared field") {
		return false
	}
	r.extrasDropped = true
	log.Printf("this management node does not accept the capability fields this agent sends " +
		"(it predates them) — claiming without them; upgrade the plane to restore vocabulary reporting")
	return true
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
	req, url, err := newSignedRequest(ctx, id, path, body)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return readCappedEnvelope(resp, url)
}

// newSignedRequest builds one signed request. Split out from signedPlanePost
// because the artifact endpoint signs identically and reads back differently:
// the signature covers the method, the path, this node's id, a timestamp, a
// nonce and the body hash, and none of that changes because the response
// happens to be bytes instead of an envelope.
func newSignedRequest(ctx context.Context, id *NodeIdentity, path string, body []byte) (*http.Request, string, error) {
	url := strings.TrimRight(id.PlaneURL, "/") + path

	sum := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(sum[:])
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	nonce, err := newNonce()
	if err != nil {
		return nil, url, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, url, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Joinery-Agent-Node", strconv.FormatInt(id.NodeID, 10))
	req.Header.Set("X-Joinery-Agent-Timestamp", timestamp)
	req.Header.Set("X-Joinery-Agent-Nonce", nonce)
	req.Header.Set("X-Joinery-Agent-Signature", id.Sign(http.MethodPost, path, timestamp, nonce, bodyHash))
	return req, url, nil
}

// artifactRequestBody is what the node asks the artifact endpoint for. A kind
// from the compiled-in set, and — for the binary — the architecture this build
// runs on. No file name, no path, no version: everything the plane needs to
// resolve the answer, it already knows better than the node does.
func artifactRequestBody(id *NodeIdentity, kind, platform string) []byte {
	payload := map[string]interface{}{
		"node_id": id.NodeID,
		"kind":    kind,
	}
	if platform != "" {
		payload["platform"] = platform
	}
	body, _ := json.Marshal(payload)
	return body
}

// releaseManifestRequestBody asks for the signed manifest of one artifact at one
// version.
//
// The node names an ARTIFACT and a VERSION; the plane resolves both against its
// own layout. Same discipline as asking for a binary by architecture: a request
// that cannot contain a path cannot be made to fetch one.
func releaseManifestRequestBody(id *NodeIdentity, owner, version string) []byte {
	body, _ := json.Marshal(map[string]interface{}{
		"node_id": id.NodeID,
		"kind":    artifactKindReleaseManifest,
		"owner":   owner,
		"version": version,
	})
	return body
}

// signedPlanePostCapped is signedPlanePost for the one answer that is legitimately
// larger than a job: the signed release manifest. The cap is still a cap — the
// caller names it, it is bounded, and nothing here reads an unbounded body.
func signedPlanePostCapped(ctx context.Context, client *http.Client, id *NodeIdentity,
	path string, body []byte, max int) (json.RawMessage, error) {
	req, url, err := newSignedRequest(ctx, id, path, body)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return readEnvelopeUpTo(resp, url, max)
}

// signedArtifactEnvelope asks for one of the small, JSON answers the artifact
// endpoint gives — a manifest, or the bundle's identity. These come back
// through the ordinary capped envelope reader, unchanged.
func signedArtifactEnvelope(ctx context.Context, client *http.Client, id *NodeIdentity, kind, platform string) (json.RawMessage, error) {
	return signedPlanePost(ctx, client, id, pathArtifact, artifactRequestBody(id, kind, platform))
}

// signedArtifactStream asks for BYTES, and is the one plane response this agent
// does not read through readCappedEnvelope.
//
// That reader exists to bound a job envelope at 64 KiB and is right to; an
// artifact is megabytes, so running one through it would refuse every download
// this endpoint exists to serve. What replaces the bound is not its absence: the
// stream is limited to max, one byte past which the transfer is abandoned
// unread, and the caller streams rather than buffering — so a plane that will
// not stop sending is a failed update, never an agent that ran a relay out of
// memory.
//
// A refusal still arrives as an envelope, because the plane answers a bad
// request the way it answers every other one. So a non-200 is read back
// through the capped reader and reported with the plane's own words.
func signedArtifactStream(ctx context.Context, client *http.Client, id *NodeIdentity, kind, platform string, max int64) (io.ReadCloser, error) {
	req, url, err := newSignedRequest(ctx, id, pathArtifact, artifactRequestBody(id, kind, platform))
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		if _, envErr := readCappedEnvelope(resp, url); envErr != nil {
			return nil, envErr
		}
		return nil, fmt.Errorf("plane returned HTTP %d for %s", resp.StatusCode, url)
	}
	return &cappedBody{
		body:      resp.Body,
		remaining: max + 1, // one past, so "exactly at the cap" is not ambiguous
		max:       max,
		url:       url,
	}, nil
}

// cappedBody is a response body that refuses to hand back more than it agreed
// to read. The overflow is an error rather than a silent truncation: a
// truncated artifact would fail its sha256 and be reported as a corrupt
// release, which is a true statement about the wrong thing.
type cappedBody struct {
	body      io.ReadCloser
	remaining int64
	max       int64
	url       string
}

func (c *cappedBody) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, fmt.Errorf("the artifact at %s is larger than this agent's %d-byte limit — abandoned unread", c.url, c.max)
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.body.Read(p)
	c.remaining -= int64(n)
	return n, err
}

func (c *cappedBody) Close() error { return c.body.Close() }

// readCappedEnvelope reads a plane response under the node's inbound cap.
//
// It reads ONE BYTE PAST the cap on purpose. Reading exactly the cap is
// ambiguous — a whole answer of that length looks identical to the front of a
// longer one — so a truncated response would be handed to the JSON parser and
// come back as "the plane sent nonsense" instead of "the plane sent too much".
func readCappedEnvelope(resp *http.Response, url string) (json.RawMessage, error) {
	return readEnvelopeUpTo(resp, url, agentMaxJobBody)
}

// readEnvelopeUpTo is readCappedEnvelope with the cap named by the caller.
//
// Every ordinary plane answer is a job or an acknowledgement and belongs under
// agentMaxJobBody. One answer legitimately is not: a signed release manifest is
// a few hundred kilobytes (0.8.370 is 186,343 bytes), and reading it is the only
// way a node that can no longer verify its own scripts gets back. Giving that
// one call its own bounded cap keeps the tight default everywhere else, which is
// the point of having a default at all.
func readEnvelopeUpTo(resp *http.Response, url string, max int) (json.RawMessage, error) {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(max)+1))
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", url, err)
	}
	if len(raw) > max {
		return nil, fmt.Errorf("plane response from %s exceeds this agent's %d-byte limit — refused unread",
			url, max)
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
