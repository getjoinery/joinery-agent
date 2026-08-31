package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"joinery-agent/primitives"
)

// The node-side approval for a destructive job.
//
// THE MANAGEMENT NODE IS NOT IN THIS FILE, and that is the design rather than a
// detail of it. A restore erases a live database, and the party that dispatches
// one is exactly the party the threat model assumes may be compromised — so no
// control the management node enforces can count for anything here. The
// challenge and the answer both live between this machine's own site and this
// machine's own agent. A compromised plane can dispatch a restore job and can do
// nothing whatsoever to get it approved: it cannot forge the answer (it does not
// hold the recovery key), it cannot relay one (the restore vocabulary declares
// no parameter an answer could arrive through), and it cannot substitute the
// public key the challenge is sealed to (that setting is writable only from this
// site's own superadmin session, and refuses to overwrite a proven key without
// an explicit rotation).
//
// WHAT AUTHORIZES IT is the machine's own backup recovery key — the one whose
// private half the operator keeps in their password manager, and whose
// possession they have already proven to this site. Nothing is enrolled and
// nothing is registered: every node in the fleet holds a proven recovery key
// already, because holding one is what lets it seal a backup at all. Whoever
// holds that key can already read every backup this machine ever made, so
// proving possession of it is at least as strong an authority over a restore as
// anything that could be invented.
//
// WHY A SEALED SECRET AND NOT A SIGNATURE. The recovery key is X25519, which
// cannot produce a signature at all — so "sign this challenge" was never an
// option to decline. The construction is the one the browser already knows how
// to open, from the possession ceremony: ephemeral X25519, HKDF-SHA256, then
// AES-256-GCM. What is sealed is a one-time secret bound to this job and to this
// node's own statement of what it would do, so an answer recovered for one job
// can never satisfy another.
//
// THE HANDOFF IS THE SETTINGS TABLE, the same surface the join and leave
// watchers already use: the one storage the web tier and this root agent can
// both reach on every install. Note what travels through it and what does not —
// the challenge and the answer do, and neither is a secret worth protecting from
// the machine's own web tier, because the machine's own web tier is the thing
// serving the approval screen. What never travels through it is a key.

const (
	// settingApprovalRequest holds the pending challenge, written by the agent
	// and rendered by the node's own admin.
	settingApprovalRequest = "restore_approval_request"
	// settingApprovalAnswer holds what the operator recovered, written by the
	// node's own admin and consumed by the agent.
	settingApprovalAnswer = "restore_approval_answer"

	// settingRecoveryPublicKey / settingRecoveryProof mirror
	// BackupRecoveryKey::PUBLIC_KEY_SETTING and ::PROOF_SETTING. Both are read;
	// neither is written from here.
	settingRecoveryPublicKey = "backup_recovery_public_key"
	settingRecoveryProof     = "backup_recovery_public_key_proven_fpr"

	// approvalInfoPrefix is the HKDF context. DIFFERENT from the possession
	// ceremony's, so an approval challenge and a possession challenge can never
	// be answers to each other even if their plaintexts were ever to converge.
	// The browser passes the matching prefix; see backup_key_verify.js.
	approvalInfoPrefix = "joinery-restore-approval:"

	// restoreApprovalPollInterval is how often the agent looks for an answer.
	// Short enough that approving feels immediate, long enough that a
	// fifteen-minute wait is a few hundred queries rather than a few hundred
	// thousand. Named apart from cli.go's join-approval poll: they wait on
	// different things, on different machines, for different people.
	restoreApprovalPollInterval = 2 * time.Second
)

// approvalStore is the slice of the settings table this gate needs. *DB
// satisfies it through dbSettings; the tests substitute an in-memory fake, so
// the challenge, the binding and the refusals can be exercised without a
// database — which matters, because the refusals are the behaviour worth
// proving and they are the hardest to reach by hand.
type approvalStore interface {
	Read(name string) (string, error)
	// Write REPORTS FAILURE, and that return is not decoration.
	//
	// This is the handoff that puts the approval screen in front of a human. A
	// write that silently does nothing produces a node that seals a challenge
	// nobody is ever shown and then waits the full window for an answer to a
	// question it never asked — indistinguishable, from every surface, from an
	// operator who chose not to approve. The first live restore attempt spent
	// fifteen minutes in exactly that state.
	Write(name, value string) error
}

// dbSettings adapts the agent's database handle to approvalStore, using the same
// two helpers the join and leave watchers use.
type dbSettings struct{ db *DB }

func (d dbSettings) Read(name string) (string, error) { return readAgentSetting(d.db, name) }
func (d dbSettings) Write(name, value string) error   { return writeAgentSetting(d.db, name, value) }

// SettingsApproval asks this machine's own operator, through this machine's own
// site, using this machine's own recovery key.
type SettingsApproval struct {
	store approvalStore
	// now is the clock, overridable so the expiry can be tested without waiting
	// a quarter of an hour. Nil means time.Now().UTC().
	now func() time.Time
}

// NewSettingsApproval builds the gate. A nil DB is not an error here — Require
// refuses, naming the reason, which is the honest answer on a machine whose
// database is down: it cannot ask, so it will not act.
func NewSettingsApproval(db *DB) *SettingsApproval {
	if db == nil {
		return &SettingsApproval{}
	}
	return &SettingsApproval{store: dbSettings{db: db}}
}

func (a *SettingsApproval) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now().UTC()
}

// approvalRequest is what the node's own admin page renders. Every field is
// composed here, on the node; none of it comes from the job.
type approvalRequest struct {
	JobID        int64                     `json:"job_id"`
	Primitive    string                    `json:"primitive"`
	Summary      string                    `json:"summary"`
	Facts        []primitives.ApprovalFact `json:"facts"`
	StatementSHA string                    `json:"statement_sha256"`
	Challenge    string                    `json:"challenge"`
	PublicKey    string                    `json:"public_key"`
	Info         string                    `json:"info"`
	IssuedTime   string                    `json:"issued_time"`
	ExpiresTime  string                    `json:"expires_time"`
}

// approvalAnswer is what the node's own admin page writes back.
type approvalAnswer struct {
	JobID    int64  `json:"job_id"`
	Answer   string `json:"answer"`
	Declined bool   `json:"declined"`
}

// Require issues a challenge, waits for this machine's operator to answer it,
// and returns nil only when the answer is the one that was sealed.
func (a *SettingsApproval) Require(ctx context.Context, jobID int64, statement primitives.ApprovalStatement) error {
	if a == nil || a.store == nil {
		return &primitives.RefusalError{Reason: "this machine cannot reach its own database, so it cannot " +
			"ask its operator to approve a restore — and it will not run one unasked"}
	}

	recipient, err := a.provenRecoveryKey()
	if err != nil {
		return err
	}

	// The secret the operator must give back. Random, one-time, and never
	// written anywhere but inside the sealed box: the settings row carries the
	// CIPHERTEXT, so the machine's own web tier can render an approval screen
	// without being able to approve anything itself.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("could not generate an approval challenge: %w", err)
	}

	statementJSON, err := json.Marshal(statement)
	if err != nil {
		return fmt.Errorf("could not describe this restore for approval: %w", err)
	}
	statementSHA := sha256.Sum256(statementJSON)

	// BOUND INSIDE THE BOX, not beside it. The plaintext names the job and the
	// hash of the statement, so an answer recovered against one job's challenge
	// is not the answer to another's, and an answer recovered against a
	// statement cannot be replayed after the statement changes. Everything that
	// binds the approval is under the AEAD; nothing that binds it is in a field
	// the web tier could edit.
	//
	// ONE LINE, AND THE WHOLE OF IT IS WHAT IS COMPARED. Two reasons, and the
	// first is that an earlier shape got this wrong in a way no unit test on
	// either side could catch. The browser posts back the ENTIRE recovered
	// plaintext (recovery-readiness.js attachCeremony), so an agent that
	// compared only the first line of a multi-line plaintext would refuse every
	// genuine approval — each side tested against its author's belief about the
	// other, which is the exact drift primitive_transport_parity exists for.
	// The second reason is transport: a form POST normalises line breaks to
	// CRLF, so a plaintext with newlines in it would not survive the round trip
	// byte-for-byte even once the comparison was right.
	//
	// Comparing the whole line also makes the binding part of the CHECK rather
	// than only part of the ciphertext: an answer for another job differs in the
	// bytes being compared, not merely in a field alongside them.
	plaintext := approvalPlaintext(secret, jobID, hex.EncodeToString(statementSHA[:]))

	challenge, err := sealToRecoveryKey(recipient, plaintext)
	if err != nil {
		return fmt.Errorf("could not seal the approval challenge: %w", err)
	}

	issued := a.clock()
	request := approvalRequest{
		JobID:        jobID,
		Primitive:    statement.Primitive,
		Summary:      statement.Summary,
		Facts:        statement.Facts,
		StatementSHA: hex.EncodeToString(statementSHA[:]),
		Challenge:    challenge,
		PublicKey:    base64.StdEncoding.EncodeToString(recipient),
		Info:         approvalInfoPrefix,
		IssuedTime:   issued.Format("2006-01-02 15:04:05"),
		ExpiresTime:  issued.Add(primitives.ApprovalWindow).Format("2006-01-02 15:04:05"),
	}
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("could not stage the approval challenge: %w", err)
	}

	// A stale answer from an earlier job must not satisfy this one. Cleared
	// before the request is published rather than after, so there is no instant
	// in which a fresh challenge sits beside somebody else's answer.
	if err := a.store.Write(settingApprovalAnswer, ""); err != nil {
		return &primitives.RefusalError{Reason: "this machine could not clear the previous approval " +
			"answer from its own settings, so it will not ask for a new one: " + err.Error()}
	}
	if err := a.store.Write(settingApprovalRequest, string(body)); err != nil {
		return &primitives.RefusalError{Reason: "this machine could not put the approval request on its " +
			"own site, so nobody would ever have been shown it: " + err.Error()}
	}

	// READ IT BACK. The write reported success; this asks the row whether it
	// agrees. A staging step that cannot be observed to have worked is the one
	// place in this mechanism where failure is invisible by construction — every
	// other refusal names itself, and this one would present as "no one
	// approved", fifteen minutes later, on a node whose operator was watching an
	// empty page the whole time.
	if back, err := a.store.Read(settingApprovalRequest); err != nil || strings.TrimSpace(back) == "" {
		return &primitives.RefusalError{Reason: "this machine wrote the approval request and could not " +
			"read it back, so its own site would not have shown it. The restore was not run"}
	}

	// Whatever happens next, the challenge does not outlive this job. An
	// unanswered one left on the admin page is an approval screen for a restore
	// that is no longer running, which is the shape of an operator approving
	// something that then happens later for reasons they cannot see.
	defer func() {
		_ = a.store.Write(settingApprovalRequest, "")
		_ = a.store.Write(settingApprovalAnswer, "")
	}()

	log.Printf("  job #%d is destructive and is waiting for approval on this machine's own site (%s)",
		jobID, primitives.ApprovalWindow)

	return a.await(ctx, jobID, plaintext, issued)
}

// await polls the handoff row until the operator answers, declines, or the
// window closes.
func (a *SettingsApproval) await(ctx context.Context, jobID int64, expected string, issued time.Time) error {
	deadline := issued.Add(primitives.ApprovalWindow)
	ticker := time.NewTicker(restoreApprovalPollInterval)
	defer ticker.Stop()

	for {
		raw, err := a.store.Read(settingApprovalAnswer)
		if err == nil && raw != "" {
			var answer approvalAnswer
			if json.Unmarshal([]byte(raw), &answer) == nil && answer.JobID == jobID {
				if answer.Declined {
					return &primitives.RefusalError{
						Reason: "the operator of this machine declined this restore on its own admin page"}
				}
				// Constant time, because the comparison is against a secret and
				// the loser of a timing race here is the machine's own data.
				// Trimmed, because the value came through a browser form and a
				// paste box: leading or trailing whitespace is the operator's,
				// not the attacker's, and refusing an otherwise-correct answer
				// over a stray newline would read as "my recovery key does not
				// work" at the worst possible moment.
				if hmac.Equal([]byte(trimSpace(answer.Answer)), []byte(expected)) {
					log.Printf("  job #%d approved on this machine with its own recovery key", jobID)
					return nil
				}
				// A wrong answer is not a retry. It is either the wrong key or
				// the wrong challenge, and both mean whoever is at the keyboard
				// should look at what they are approving rather than paste
				// again into a window that is still counting down.
				return &primitives.RefusalError{
					Reason: "the answer given on this machine's admin page is not what this node's " +
						"approval challenge opens to, so the restore was not run"}
			}
			// An answer for a different job: somebody else's, or a leftover.
			// Cleared rather than treated as an error, so a stale row cannot
			// wedge every future approval.
			if err == nil {
				_ = a.store.Write(settingApprovalAnswer, "")
			}
		}

		if !a.clock().Before(deadline) {
			return &primitives.RefusalError{
				Reason: fmt.Sprintf("no one approved this restore on this machine's own Backups page "+
					"within %s, so it was not run. Dispatch it again when someone is at the keyboard "+
					"with the recovery key", primitives.ApprovalWindow)}
		}

		select {
		case <-ctx.Done():
			return &primitives.RefusalError{
				Reason: "the wait for approval ended before anyone answered, so this restore was not run"}
		case <-ticker.C:
		}
	}
}

// provenRecoveryKey reads this machine's recovery public key and refuses unless
// its possession has been proven here.
//
// THE PROOF IS THE POINT. An unproven key is a value somebody typed: sealing to
// it always appears to succeed, so a challenge sealed to a mistyped key would be
// unopenable by anyone, and the restore would fail as "nobody approved" rather
// than "this machine's recovery key is wrong". Worse, a key that arrived from
// somewhere else and was never proven here would let its sender approve
// restores. Proven means an operator opened a challenge with the private half,
// on this site, and that is the only state this accepts.
func (a *SettingsApproval) provenRecoveryKey() ([]byte, error) {
	b64, err := a.store.Read(settingRecoveryPublicKey)
	if err != nil && err != sql.ErrNoRows {
		return nil, &primitives.RefusalError{
			Reason: "this machine could not read its own recovery key setting, so it cannot ask for approval"}
	}
	raw, decodeErr := base64.StdEncoding.DecodeString(trimSpace(b64))
	if trimSpace(b64) == "" || decodeErr != nil || len(raw) != curve25519.ScalarSize {
		return nil, &primitives.RefusalError{
			Reason: "this machine has no usable backup recovery key, so there is no one it can ask to " +
				"approve a restore. Set one up on its own Backups page first — it is the same key that " +
				"opens this machine's backups"}
	}

	proof, _ := a.store.Read(settingRecoveryProof)
	sum := sha256.Sum256(raw)
	if !hmac.Equal([]byte(trimSpace(proof)), []byte(hex.EncodeToString(sum[:]))) {
		return nil, &primitives.RefusalError{
			Reason: "this machine's recovery key has never been proven here, so a challenge sealed to it " +
				"might be one nobody can open. Prove it on this machine's own Backups page first"}
	}
	return raw, nil
}

// approvalPlaintext is the exact string that is sealed, that the browser
// recovers, and that the agent compares an answer against — all three, from one
// place.
//
// One function rather than a format string at each site, because the three uses
// have to agree byte-for-byte and they live in different languages and different
// files. The browser-parity gate seals through this and then asks the shipped
// JavaScript to reproduce it, so a change here that broke the round trip fails
// the gate rather than the next real restore.
func approvalPlaintext(secret []byte, jobID int64, statementSHA string) string {
	return fmt.Sprintf("joinery-restore-approval %s job:%d statement:%s",
		base64.StdEncoding.EncodeToString(secret), jobID, statementSHA)
}

// sealToRecoveryKey produces the blob the browser opens: ephemeral X25519 →
// HKDF-SHA256 → AES-256-GCM, laid out as
// base64( ephemeralPublic[32] || iv[12] || ciphertext || tag[16] ).
//
// Byte-for-byte the construction BackupRecoveryKey::browser_challenge() uses,
// because the browser code that opens it is the same code — only the HKDF info
// string differs, which is what keeps an approval challenge and a possession
// challenge from ever being answers to each other. It is NOT libsodium's sealed
// box: that is the backup envelope's construction, and it has no WebCrypto
// equivalent, so a challenge built that way could not be opened on the page
// where the operator actually is.
func sealToRecoveryKey(recipient []byte, plaintext string) (string, error) {
	var ephSecret [32]byte
	if _, err := rand.Read(ephSecret[:]); err != nil {
		return "", err
	}
	ephPublic, err := curve25519.X25519(ephSecret[:], curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	shared, err := curve25519.X25519(ephSecret[:], recipient)
	if err != nil {
		return "", err
	}
	zero(ephSecret[:])

	info := append([]byte(approvalInfoPrefix), ephPublic...)
	info = append(info, recipient...)
	aesKey := make([]byte, 32)
	if _, err := hkdf.New(sha256.New, shared, nil, info).Read(aesKey); err != nil {
		return "", err
	}
	zero(shared)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	zero(aesKey)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, iv, []byte(plaintext), nil)

	blob := make([]byte, 0, len(ephPublic)+len(iv)+len(sealed))
	blob = append(blob, ephPublic...)
	blob = append(blob, iv...)
	blob = append(blob, sealed...)
	return base64.StdEncoding.EncodeToString(blob), nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// trimSpace without pulling in strings for one call in this file's hot path of
// two. Settings values arrive with whatever whitespace a paste box left behind.
func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}
