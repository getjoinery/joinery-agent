package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Node-initiated join (spec Phase 1.5, decision A6): enrollment shares NO
// secret. The site admin enters a management node's URL on the local admin
// page; the web tier records that ask in the settings table; this watcher —
// running as root — generates the keypair, sends the join request carrying
// only the PUBLIC half, and polls until a human on the management node
// approves it after comparing fingerprints across the two screens.
//
// The division of custody is the point: the web tier only ever holds a URL,
// the wire only ever carries the public key, and the private half is born and
// dies in root-owned files on this machine.

const (
	pathJoin       = "/api/v1/agent/join"
	pathJoinStatus = "/api/v1/agent/join_status"

	// settingJoinRequest is written by the admin page: {"url", "requested_time"}.
	// settingJoinState is written back by this watcher and rendered by that page.
	settingJoinRequest = "agent_join_request"
	settingJoinState   = "agent_join_state"

	joinCheckInterval = 5 * time.Second
	joinPollInterval  = 10 * time.Second

	// stagedIdentityFileName holds the keypair between asking and approval,
	// so a restart mid-join keeps the same fingerprint the human is comparing.
	stagedIdentityFileName = "node_identity.staged.json"
)

// Fingerprint is the short fingerprint both admin panels display: the first 16
// hex characters of SHA-256 over the RAW public key bytes. The management node
// computes the identical value — the contract is pinned by tests on both sides.
func Fingerprint(rawPublicKey []byte) string {
	sum := sha256.Sum256(rawPublicKey)
	return hex.EncodeToString(sum[:])[:16]
}

// stagedIdentity is the keypair while it awaits approval. Not yet an identity —
// it names no node.
type stagedIdentity struct {
	PlaneURL      string `json:"plane_url"`
	PublicKey     string `json:"public_key"`
	PrivateKey    string `json:"private_key"`
	RequestedTime string `json:"requested_time"`
	// ClaimedName is what this machine asked to be called on the plane (the
	// CLI's --name, else the hostname at the time of the ask), kept so a
	// renewal presents the same name the operator is looking for.
	ClaimedName string `json:"claimed_name,omitempty"`
}

func stagedIdentityPath() string {
	return filepath.Join(filepath.Dir(IdentityPath()), stagedIdentityFileName)
}

func loadStagedIdentity() *stagedIdentity {
	raw, err := os.ReadFile(stagedIdentityPath())
	if err != nil {
		return nil
	}
	var s stagedIdentity
	if json.Unmarshal(raw, &s) != nil || s.PublicKey == "" || s.PrivateKey == "" {
		return nil
	}
	return &s
}

func (s *stagedIdentity) save() error {
	body, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := stagedIdentityPath() + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, stagedIdentityPath())
}

func discardStagedIdentity() {
	_ = os.Remove(stagedIdentityPath())
}

// JoinWatcher waits for the admin page to name a management node, performs the
// join, and starts the remote source once approved.
type JoinWatcher struct {
	cfg          *Config
	db           *DB
	jobLock      *sync.Mutex
	agentVersion string
}

// Run loops until an approval turns into a running remote source, or the
// context ends. Every failure is a state the admin page can render, never a
// fatal — an agent that cannot join must keep serving its local queue.
func (w *JoinWatcher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(joinCheckInterval):
		}

		request := w.readJoinRequest()
		if request == nil {
			continue
		}

		if w.attemptJoin(ctx, request) {
			return
		}
	}
}

type joinRequest struct {
	URL           string `json:"url"`
	RequestedTime string `json:"requested_time"`
}

func (w *JoinWatcher) readJoinRequest() *joinRequest {
	value, err := w.readSetting(settingJoinRequest)
	if err != nil || strings.TrimSpace(value) == "" {
		return nil
	}
	var r joinRequest
	if json.Unmarshal([]byte(value), &r) != nil || strings.TrimSpace(r.URL) == "" {
		return nil
	}
	r.URL = strings.TrimRight(strings.TrimSpace(r.URL), "/")
	return &r
}

// attemptJoin drives one request to a terminal state. Returns true when the
// join was approved and the remote source is running.
func (w *JoinWatcher) attemptJoin(ctx context.Context, request *joinRequest) bool {
	staged := loadStagedIdentity()
	// A staged keypair belongs to one ask. A different URL, or a NEWER ask
	// (the admin cancelled and asked again — possibly after a rejection),
	// gets a fresh keypair, so a rejected key is never re-presented.
	if staged != nil && (staged.PlaneURL != request.URL || staged.RequestedTime != request.RequestedTime) {
		discardStagedIdentity()
		staged = nil
	}
	if staged == nil {
		pub, priv, err := GenerateIdentityKeys()
		if err != nil {
			w.writeJoinState(map[string]interface{}{
				"status": "error", "url": request.URL,
				"error": "could not generate a keypair: " + err.Error(),
			})
			return false
		}
		staged = &stagedIdentity{
			PlaneURL:      request.URL,
			PublicKey:     pub,
			PrivateKey:    priv,
			RequestedTime: request.RequestedTime,
		}
		if err := staged.save(); err != nil {
			w.writeJoinState(map[string]interface{}{
				"status": "error", "url": request.URL,
				"error": "could not store the staged keypair: " + err.Error(),
			})
			return false
		}
	}

	rawPub, err := base64.StdEncoding.DecodeString(staged.PublicKey)
	if err != nil {
		discardStagedIdentity()
		return false
	}
	fingerprint := Fingerprint(rawPub)

	hostname := w.claimedName()
	log.Printf("join: asking %s to adopt this node (key %s) as %q", request.URL, fingerprint, hostname)

	sendJoin := true
	for {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		// The admin can cancel (or replace) the ask at any moment; honour it
		// between polls rather than at the next restart.
		current := w.readJoinRequest()
		if current == nil || current.URL != request.URL || current.RequestedTime != request.RequestedTime {
			log.Printf("join: the request for %s was withdrawn", request.URL)
			return false
		}

		status, err := w.callJoin(ctx, request.URL, staged, hostname, sendJoin)
		if err != nil {
			w.writeJoinState(map[string]interface{}{
				"status": "error", "url": request.URL, "fingerprint": fingerprint,
				"error": err.Error(),
			})
			select {
			case <-ctx.Done():
				return false
			case <-time.After(joinPollInterval):
			}
			continue
		}
		sendJoin = false

		switch status.Status {
		case "pending":
			w.writeJoinState(map[string]interface{}{
				"status": "pending", "url": request.URL, "fingerprint": fingerprint,
			})
		case "expired", "unknown":
			// Renew by re-sending the join itself.
			sendJoin = true
		case "rejected":
			log.Printf("join: %s rejected this node's request", request.URL)
			w.writeJoinState(map[string]interface{}{
				"status": "rejected", "url": request.URL, "fingerprint": fingerprint,
			})
			// The key was declined; it is never presented again. The recorded
			// request is cleared so a fresh ask is unmistakably fresh.
			discardStagedIdentity()
			w.writeSetting(settingJoinRequest, "")
			return false
		case "approved":
			return w.promote(ctx, request, staged, status, fingerprint)
		default:
			w.writeJoinState(map[string]interface{}{
				"status": "error", "url": request.URL, "fingerprint": fingerprint,
				"error": fmt.Sprintf("the management node answered with an unknown status %q", status.Status),
			})
		}

		select {
		case <-ctx.Done():
			return false
		case <-time.After(joinPollInterval):
		}
	}
}

// promote turns an approval into the node identity and starts the remote source.
func (w *JoinWatcher) promote(ctx context.Context, request *joinRequest, staged *stagedIdentity, status *joinStatusResponse, fingerprint string) bool {
	if status.NodeID <= 0 {
		w.writeJoinState(map[string]interface{}{
			"status": "error", "url": request.URL, "fingerprint": fingerprint,
			"error": "the management node approved without naming a node",
		})
		return false
	}

	identity, err := identityFromApproval(request.URL, staged, status, w.cfg.PlaneTLSInsecure)
	if err != nil {
		w.writeJoinState(map[string]interface{}{
			"status": "error", "url": request.URL, "fingerprint": fingerprint,
			"error": "the staged keypair is unusable: " + err.Error(),
		})
		discardStagedIdentity()
		w.writeSetting(settingJoinRequest, "")
		return false
	}
	if err := identity.Save(IdentityPath()); err != nil {
		w.writeJoinState(map[string]interface{}{
			"status": "error", "url": request.URL, "fingerprint": fingerprint,
			"error": "approved, but the identity could not be stored: " + err.Error(),
		})
		return false
	}
	discardStagedIdentity()
	w.writeSetting(settingJoinRequest, "")
	w.writeJoinState(map[string]interface{}{
		"status": "connected", "url": request.URL, "fingerprint": fingerprint,
		"node_id": status.NodeID, "node_slug": status.NodeSlug,
	})

	log.Printf("join: approved — this is node #%d (%s) of %s; credential stored at %s",
		status.NodeID, status.NodeSlug, request.URL, IdentityPath())

	source := startRemoteSource(w.cfg, w.db, w.jobLock, w.agentVersion)
	if source != nil {
		// Connected mid-process, so the leave watcher main() starts for an
		// already-connected agent has to start here instead.
		leaver := &LeaveWatcher{db: w.db, identity: source.identity, jobLock: w.jobLock}
		go leaver.Run(ctx)
	}
	return source != nil
}

// identityFromApproval turns an approved join into the node identity. The
// hydrate() call is load-bearing: an identity that cannot sign is not an
// identity, and the freshly enrolled one must be able to sign IMMEDIATELY —
// the token-era enrollment once skipped this and the first claim panicked.
func identityFromApproval(planeURL string, staged *stagedIdentity, status *joinStatusResponse, tlsInsecure bool) (*NodeIdentity, error) {
	identity := &NodeIdentity{
		PlaneURL:    planeURL,
		NodeID:      status.NodeID,
		NodeSlug:    status.NodeSlug,
		PublicKey:   staged.PublicKey,
		PrivateKey:  staged.PrivateKey,
		PairedTime:  nowRFC3339(),
		PollSeconds: status.PollInterval,
		TLSInsecure: tlsInsecure,
	}
	if err := identity.hydrate(); err != nil {
		return nil, err
	}
	return identity, nil
}

type joinStatusResponse struct {
	Status       string `json:"status"`
	Fingerprint  string `json:"fingerprint"`
	NodeID       int64  `json:"node_id"`
	NodeSlug     string `json:"node_slug"`
	PollInterval int    `json:"poll_interval"`
}

// claimedName is what a site-driven ask calls this machine on the plane.
//
// A machine carrying a site claims the SITE's name — the site root's directory
// name, which is what its operator, its installer and its plane already call
// it. A siteless machine has nothing better than its OS hostname (the docker
// installer names those explicitly through the CLI's --name). Found live: a
// bare-metal site on a fresh cloud instance whose hostname was "localhost"
// asked to join as "localhost", and the operator approving it had to match a
// fingerprint against a name that named nothing.
func (w *JoinWatcher) claimedName() string {
	return claimedNameFor(func() string {
		if w.cfg == nil {
			return ""
		}
		return w.cfg.SiteRoot
	}())
}

func claimedNameFor(siteRoot string) string {
	if siteRoot != "" {
		base := filepath.Base(filepath.Clean(siteRoot))
		if base != "" && base != "." && base != string(filepath.Separator) {
			return base
		}
	}
	hostname, _ := os.Hostname()
	return hostname
}

// callJoin sends the join (first ask, or renewal) or the lighter status poll.
func (w *JoinWatcher) callJoin(ctx context.Context, planeURL string, staged *stagedIdentity, hostname string, sendJoin bool) (*joinStatusResponse, error) {
	var path string
	var payload map[string]interface{}
	if sendJoin {
		path = pathJoin
		payload = map[string]interface{}{
			"claimed_name":     hostname,
			"agent_public_key": staged.PublicKey,
			"agent_version":    w.agentVersion,
		}
	} else {
		path = pathJoinStatus
		payload = map[string]interface{}{
			"agent_public_key": staged.PublicKey,
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	url := planeURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := newPlaneClient(w.cfg.PlaneTLSInsecure).Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach the management node at %s: %w", planeURL, err)
	}
	defer resp.Body.Close()

	data, err := readCappedEnvelope(resp, url)
	if err != nil {
		return nil, err
	}
	var status joinStatusResponse
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, fmt.Errorf("the management node sent an unreadable join response: %w", err)
	}
	return &status, nil
}

// ── Settings-table plumbing ──
//
// The settings table is the handoff surface between the web tier and this
// root agent — the one storage both can already reach on every install. The
// rows are declared managed in settings.json and seeded from there; the
// UPSERT below matches Setting::put's, so a write works even in the gap
// between new code arriving and update_database seeding the rows.

func (w *JoinWatcher) readSetting(name string) (string, error) {
	return readAgentSetting(w.db, name)
}

func (w *JoinWatcher) writeSetting(name, value string) {
	_ = writeAgentSetting(w.db, name, value)
}

func readAgentSetting(db *DB, name string) (string, error) {
	var value sql.NullString
	err := db.SQL().QueryRow(
		"SELECT stg_value FROM stg_settings WHERE stg_name = $1", name).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return value.String, nil
}

func writeAgentSetting(db *DB, name, value string) error {
	_, err := db.SQL().Exec(
		`INSERT INTO stg_settings (stg_name, stg_value, stg_usr_user_id, stg_create_time, stg_update_time, stg_group_name)
		 VALUES ($1, $2, 1, NOW(), NOW(), 'general')
		 ON CONFLICT (stg_name) DO UPDATE SET stg_value = EXCLUDED.stg_value, stg_update_time = NOW()`,
		name, value)
	if err != nil {
		log.Printf("settings: could not write %s: %v", name, err)
	}
	return err
}

func (w *JoinWatcher) writeJoinState(state map[string]interface{}) {
	state["updated_time"] = gmNow()
	body, err := json.Marshal(state)
	if err != nil {
		return
	}
	w.writeSetting(settingJoinState, string(body))
}

func gmNow() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05")
}
