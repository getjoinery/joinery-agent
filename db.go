package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// Job represents a management job from the database.
type Job struct {
	ID          int64
	NodeID      int64
	JobType     string
	Status      string
	Commands    JobCommands
	Output      string
	CurrentStep int
	TotalSteps  int
}

// JobCommands is the JSON structure stored in mjb_commands.
type JobCommands struct {
	Steps []Step `json:"steps"`
}

// Step represents a single execution step within a job.
type Step struct {
	Type            string `json:"type"`
	Label           string `json:"label"`
	Cmd             string `json:"cmd"`
	NodeID          int64  `json:"node_id,omitempty"`
	OnHost          bool   `json:"on_host,omitempty"`
	Direction       string `json:"direction,omitempty"`
	RemotePath      string `json:"remote_path,omitempty"`
	LocalPath       string `json:"local_path,omitempty"`
	ContinueOnError bool   `json:"continue_on_error,omitempty"`
	Timeout         int    `json:"timeout,omitempty"`
	Teardown        bool   `json:"teardown,omitempty"`

	// Fields specific to the `api` step type
	Method       string            `json:"method,omitempty"`
	Endpoint     string            `json:"endpoint,omitempty"`
	ExpectStatus int               `json:"expect_status,omitempty"`
	Query        map[string]string `json:"query,omitempty"`
	Body         interface{}       `json:"body,omitempty"`
}

// How long a reachability probe waits before calling the database unavailable.
// Short on purpose: this answers "can I do database work this minute", and a
// caller blocked on the answer is a caller not doing the work it still can.
const dbProbeTimeout = 5 * time.Second

// DB wraps the database connection and provides job queue operations.
type DB struct {
	conn *sql.DB
	cfg  *Config
}

// NewDB prepares the connection pool. It does NOT connect, and it does not fail
// when PostgreSQL is down.
//
// This is the agent's independence, and it is worth stating plainly: a sick node
// is when its agent is most needed. An agent that refuses to start without a
// database gives up exactly then — and because the supervisor restarts it into
// the same failure, a database outage used to mean an agent crash-looping until
// someone with SSH intervened, on the very machine whose remote access this
// migration is removing.
//
// sql.Open builds a pool without dialling; the driver connects on first use and
// reconnects on its own afterwards. So laziness here is not machinery, it is
// declining to add an eager Ping whose only effect was to convert a transient
// outage into a dead process.
//
// Only a malformed DSN fails, and that is a config fault the caller should hear
// about. Everything else surfaces per-query, where the caller can say which
// piece of work is degraded instead of taking the process down with it.
func NewDB(cfg *Config) (*DB, error) {
	connStr := fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
		cfg.DBHost, cfg.DBPort, cfg.DBName, cfg.DBUser, cfg.DBPassword)

	conn, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("could not open database connection: %w", err)
	}

	conn.SetMaxOpenConns(5)
	conn.SetMaxIdleConns(2)

	return &DB{conn: conn, cfg: cfg}, nil
}

// Available reports whether the database is reachable right now, with the
// diagnosis attached. Callers use it to decide what they can do this minute, not
// whether to exist — nothing in the agent should treat this as fatal.
func (d *DB) Available() error {
	ctx, cancel := context.WithTimeout(context.Background(), dbProbeTimeout)
	defer cancel()

	if err := d.conn.PingContext(ctx); err != nil {
		return d.diagnose(err)
	}
	return nil
}

// diagnose turns a driver error into something an operator can act on. These
// messages used to be the agent's dying words; they are now what it says while
// carrying on with the work that does not need a database.
func (d *DB) diagnose(err error) error {
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "password authentication failed"):
		return fmt.Errorf("database authentication failed for user %q on database %q.\n"+
			"  Credentials were read from %s.\n"+
			"  Verify dbusername and dbpassword are correct in that file.",
			d.cfg.DBUser, d.cfg.DBName, defaultJoineryConfig)
	case strings.Contains(errStr, "does not exist"):
		return fmt.Errorf("database %q does not exist.\n"+
			"  This was read from dbname in %s.", d.cfg.DBName, defaultJoineryConfig)
	case strings.Contains(errStr, "connection refused"):
		return fmt.Errorf("could not connect to PostgreSQL at %s:%s — connection refused.\n"+
			"  Is PostgreSQL running? Check: sudo systemctl status postgresql",
			d.cfg.DBHost, d.cfg.DBPort)
	}
	return fmt.Errorf("could not connect to database: %w", err)
}

func (d *DB) Close() error {
	return d.conn.Close()
}

// Provider hands primitives a connection resolved at use, with the reachability
// check attached. This is the only way a primitive reaches the database, and it
// is deliberately not a bare handle: the agent runs through outages now, so
// "here is the database" has to be able to answer "it is not there right now".
func (d *DB) Provider() func() (*sql.DB, error) {
	return func() (*sql.DB, error) {
		if err := d.Available(); err != nil {
			return nil, err
		}
		return d.conn, nil
	}
}

// SQL exposes the connection for the agent's own plane-local queries. Primitives
// go through Provider instead.
func (d *DB) SQL() *sql.DB {
	return d.conn
}

// localJobTables are the server_manager tables the plane-local job queue and
// its heartbeat live in. They exist on a control plane and nowhere else.
var localJobTables = []string{"mgn_managed_nodes", "mjb_management_jobs", "ahb_agent_heartbeats"}

// MissingLocalJobTables reports which of the plane-local tables this database
// lacks. An empty result means this machine has a local job queue to serve.
//
// This is a capability question, not a health check: an agent on a plain
// managed node has none of these tables and is working exactly as intended —
// it takes its work from the management node it joined, over the channel, and
// never reads a queue out of the local database. Only a control plane, where
// server_manager is installed, has local work of its own.
func (d *DB) MissingLocalJobTables() ([]string, error) {
	missing := []string{}

	for _, table := range localJobTables {
		var exists bool
		err := d.conn.QueryRow(
			"SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)", table,
		).Scan(&exists)
		if err != nil {
			return nil, fmt.Errorf("could not check for table %s: %w", table, err)
		}
		if !exists {
			missing = append(missing, table)
		}
	}

	return missing, nil
}

// ClaimNextJob finds the oldest pending job, checks per-node concurrency,
// and atomically claims it. Returns nil if no jobs are available.
func (d *DB) ClaimNextJob() (*Job, error) {
	row := d.conn.QueryRow(`
		SELECT mjb_id, mjb_mgn_node_id, mjb_job_type, mjb_commands, mjb_total_steps
		FROM mjb_management_jobs
		WHERE mjb_status = 'pending'
		  AND mjb_delete_time IS NULL
		  AND NOT jsonb_exists(mjb_commands, 'primitive')
		ORDER BY mjb_id ASC
		LIMIT 1
	`)

	var job Job
	var nodeID sql.NullInt64
	var commandsJSON string

	err := row.Scan(&job.ID, &nodeID, &job.JobType, &commandsJSON, &job.TotalSteps)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scanning pending job: %w", err)
	}

	if nodeID.Valid {
		job.NodeID = nodeID.Int64

		// Check per-node concurrency lock
		var runningCount int
		err = d.conn.QueryRow(`
			SELECT COUNT(*) FROM mjb_management_jobs
			WHERE mjb_mgn_node_id = $1
			  AND mjb_status = 'running'
			  AND mjb_id != $2
		`, job.NodeID, job.ID).Scan(&runningCount)
		if err != nil {
			return nil, fmt.Errorf("checking node lock: %w", err)
		}
		if runningCount > 0 {
			return nil, nil // Another job is running on this node, skip
		}
	}

	// Claim the job
	result, err := d.conn.Exec(`
		UPDATE mjb_management_jobs
		SET mjb_status = 'running',
		    mjb_started_time = now(),
		    mjb_update_time = now()
		WHERE mjb_id = $1
		  AND mjb_status = 'pending'
	`, job.ID)
	if err != nil {
		return nil, fmt.Errorf("claiming job: %w", err)
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		return nil, nil // Race condition: another agent claimed it
	}

	if err := json.Unmarshal([]byte(commandsJSON), &job.Commands); err != nil {
		d.FailJob(job.ID, "Failed to parse job commands: "+err.Error())
		return nil, fmt.Errorf("parsing commands for job %d: %w", job.ID, err)
	}

	job.Status = "running"
	return &job, nil
}

// AppendOutput appends text to a job's output and updates current step.
func (d *DB) AppendOutput(jobID int64, text string, currentStep int) error {
	_, err := d.conn.Exec(`
		UPDATE mjb_management_jobs
		SET mjb_output = COALESCE(mjb_output, '') || $1,
		    mjb_current_step = $2,
		    mjb_update_time = now()
		WHERE mjb_id = $3
	`, text, currentStep, jobID)
	return err
}

// CompleteJob marks a job as completed.
func (d *DB) CompleteJob(jobID int64) error {
	_, err := d.conn.Exec(`
		UPDATE mjb_management_jobs
		SET mjb_status = 'completed',
		    mjb_completed_time = now(),
		    mjb_update_time = now()
		WHERE mjb_id = $1
	`, jobID)
	return err
}

// FailJob marks a job as failed with an error message.
func (d *DB) FailJob(jobID int64, errorMsg string) error {
	_, err := d.conn.Exec(`
		UPDATE mjb_management_jobs
		SET mjb_status = 'failed',
		    mjb_error_message = $1,
		    mjb_completed_time = now(),
		    mjb_update_time = now()
		WHERE mjb_id = $2
	`, errorMsg, jobID)
	return err
}

// RecoverStaleJobs marks any jobs stuck in 'running' state as failed and
// returns them so their teardown steps can be replayed. A job whose commands
// no longer parse is still marked failed; it is just omitted from the result.
func (d *DB) RecoverStaleJobs() ([]*Job, error) {
	rows, err := d.conn.Query(`
		UPDATE mjb_management_jobs
		SET mjb_status = 'failed',
		    mjb_error_message = 'Agent restarted while job was running. Job may have partially completed. Check job output for details, then use Re-run if needed.',
		    mjb_completed_time = now(),
		    mjb_update_time = now()
		WHERE mjb_status = 'running'
		  AND NOT jsonb_exists(mjb_commands, 'primitive')
		RETURNING mjb_id, mjb_mgn_node_id, mjb_job_type, mjb_commands, COALESCE(mjb_current_step, 0)
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []*Job
	for rows.Next() {
		var job Job
		var nodeID sql.NullInt64
		var commandsJSON string
		if err := rows.Scan(&job.ID, &nodeID, &job.JobType, &commandsJSON, &job.CurrentStep); err != nil {
			return jobs, err
		}
		if nodeID.Valid {
			job.NodeID = nodeID.Int64
		}
		if err := json.Unmarshal([]byte(commandsJSON), &job.Commands); err != nil {
			log.Printf("WARNING: stale job #%d has unparseable commands — teardown not replayed: %v", job.ID, err)
			continue
		}
		job.Status = "failed"
		jobs = append(jobs, &job)
	}
	return jobs, rows.Err()
}

// UpdateHeartbeat inserts or updates the agent's heartbeat record, including
// what the shipped agent_dist offers (bundled version) and the self-update
// state. Falls back to the legacy column set when the schema predates the
// release channel — the agent binary and the tree upgrade independently, and
// a heartbeat must never be lost to that ordering.
func (d *DB) UpdateHeartbeat(agentName, agentVersion, bundledVersion, updateState string) error {
	_, err := d.conn.Exec(`
		INSERT INTO ahb_agent_heartbeats (ahb_agent_name, ahb_last_heartbeat, ahb_agent_version, ahb_bundled_version, ahb_update_state, ahb_status, ahb_create_time)
		VALUES ($1, now(), $2, $3, $4, 'running', now())
		ON CONFLICT (ahb_agent_name)
		DO UPDATE SET ahb_last_heartbeat = now(),
		              ahb_agent_version = $2,
		              ahb_bundled_version = $3,
		              ahb_update_state = $4,
		              ahb_status = 'running',
		              ahb_update_time = now()
	`, agentName, agentVersion, bundledVersion, updateState)
	if err != nil && strings.Contains(err.Error(), "ahb_bundled_version") {
		_, err = d.conn.Exec(`
			INSERT INTO ahb_agent_heartbeats (ahb_agent_name, ahb_last_heartbeat, ahb_agent_version, ahb_status, ahb_create_time)
			VALUES ($1, now(), $2, 'running', now())
			ON CONFLICT (ahb_agent_name)
			DO UPDATE SET ahb_last_heartbeat = now(),
			              ahb_agent_version = $2,
			              ahb_status = 'running',
			              ahb_update_time = now()
		`, agentName, agentVersion)
	}
	return err
}

// GetNodeAPIInfo returns management-API connection info for a managed node.
// Returns an error — NOT just empty strings — if credentials aren't configured,
// so the api step fails with a clear message instead of silently doing nothing.
func (d *DB) GetNodeAPIInfo(nodeID int64) (*NodeAPIInfo, error) {
	row := d.conn.QueryRow(`
		SELECT mgn_id, mgn_site_url, mgn_api_public_key, mgn_api_secret_key,
		       COALESCE(mgn_tls_insecure, false)
		FROM mgn_managed_nodes
		WHERE mgn_id = $1
	`, nodeID)

	var info NodeAPIInfo
	var siteURL, publicKey, secretKey sql.NullString

	err := row.Scan(&info.ID, &siteURL, &publicKey, &secretKey, &info.TLSInsecure)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("node #%d not found in mgn_managed_nodes", nodeID)
	}
	if err != nil {
		return nil, fmt.Errorf("loading API info for node #%d: %w", nodeID, err)
	}

	if siteURL.Valid {
		info.SiteURL = siteURL.String
	}
	if publicKey.Valid {
		info.PublicKey = publicKey.String
	}
	if secretKey.Valid {
		info.SecretKey = secretKey.String
	}

	if info.SiteURL == "" || info.PublicKey == "" || info.SecretKey == "" {
		return nil, fmt.Errorf("node #%d has no management API credentials configured "+
			"(mgn_site_url, mgn_api_public_key, mgn_api_secret_key)", nodeID)
	}

	return &info, nil
}

// GetBackupTargetCredentials returns the raw bkt_credentials value (a JSON
// string — either a legacy plaintext credential object or the sealed
// {"enc":"..."} shape) for a backup target. Used to resolve __SM_CREDS_<id>__
// placeholders at step-execution time.
func (d *DB) GetBackupTargetCredentials(targetID int64) (string, error) {
	return d.backupTargetColumn(targetID, "bkt_credentials", "credentials")
}

// GetBackupTargetNodeCredentials returns the raw bkt_node_credentials value —
// the write-only credential handed to nodes — for __SM_NODE_CREDS_<id>__
// placeholders. The builder only emits that token when the slot is filled, so
// an empty slot here means it was cleared after the job was built: fail the
// step rather than fall back to the more powerful main credential.
func (d *DB) GetBackupTargetNodeCredentials(targetID int64) (string, error) {
	return d.backupTargetColumn(targetID, "bkt_node_credentials", "node credentials")
}

func (d *DB) backupTargetColumn(targetID int64, column, label string) (string, error) {
	var creds sql.NullString
	err := d.conn.QueryRow(
		`SELECT `+column+` FROM bkt_backup_targets WHERE bkt_id = $1 AND bkt_delete_time IS NULL`,
		targetID,
	).Scan(&creds)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("backup target #%d not found (or deleted)", targetID)
	}
	if err != nil {
		return "", fmt.Errorf("loading %s for backup target #%d: %w", label, targetID, err)
	}
	if !creds.Valid || creds.String == "" || creds.String == "null" || creds.String == "{}" || creds.String == "[]" {
		return "", fmt.Errorf("backup target #%d has no %s configured", targetID, label)
	}
	return creds.String, nil
}

// nowUTC returns current time formatted for PostgreSQL.
func nowUTC() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05")
}
