package main

import (
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

// DB wraps the database connection and provides job queue operations.
type DB struct {
	conn *sql.DB
}

func NewDB(cfg *Config) (*DB, error) {
	connStr := fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
		cfg.DBHost, cfg.DBPort, cfg.DBName, cfg.DBUser, cfg.DBPassword)

	conn, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("could not open database connection: %w", err)
	}

	if err := conn.Ping(); err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "password authentication failed") {
			return nil, fmt.Errorf("database authentication failed for user %q on database %q.\n"+
				"  Credentials were read from %s.\n"+
				"  Verify dbusername and dbpassword are correct in that file.", cfg.DBUser, cfg.DBName, defaultJoineryConfig)
		}
		if strings.Contains(errStr, "does not exist") {
			return nil, fmt.Errorf("database %q does not exist.\n"+
				"  This was read from dbname in %s.", cfg.DBName, defaultJoineryConfig)
		}
		if strings.Contains(errStr, "connection refused") {
			return nil, fmt.Errorf("could not connect to PostgreSQL at %s:%s — connection refused.\n"+
				"  Is PostgreSQL running? Check: sudo systemctl status postgresql", cfg.DBHost, cfg.DBPort)
		}
		return nil, fmt.Errorf("could not connect to database: %w", err)
	}

	conn.SetMaxOpenConns(5)
	conn.SetMaxIdleConns(2)

	return &DB{conn: conn}, nil
}

func (d *DB) Close() error {
	return d.conn.Close()
}

// SQL exposes the connection for collectors that read local state. Handed to a
// primitive through ExecEnv.DB, which is the only way a primitive reaches it.
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

// GetNodeConnInfo returns connection info for a managed node.
func (d *DB) GetNodeConnInfo(nodeID int64) (*NodeConnInfo, error) {
	row := d.conn.QueryRow(`
		SELECT mgn_id, mgn_host, mgn_ssh_user, mgn_ssh_key_path, mgn_ssh_port,
		       mgn_container_name, mgn_container_user
		FROM mgn_managed_nodes
		WHERE mgn_id = $1
	`, nodeID)

	var info NodeConnInfo
	var sshKeyPath, containerName, containerUser sql.NullString
	var sshPort sql.NullInt32

	err := row.Scan(&info.ID, &info.Host, &info.SSHUser, &sshKeyPath, &sshPort,
		&containerName, &containerUser)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("node #%d not found in mgn_managed_nodes. It may have been deleted. "+
			"Check the node list at /admin/server_manager/nodes", nodeID)
	}
	if err != nil {
		return nil, fmt.Errorf("loading node #%d: %w", nodeID, err)
	}

	if sshKeyPath.Valid {
		info.SSHKeyPath = sshKeyPath.String
	}
	info.SSHPort = 22
	if sshPort.Valid {
		info.SSHPort = int(sshPort.Int32)
	}
	if containerName.Valid {
		info.ContainerName = containerName.String
	}
	if containerUser.Valid {
		info.ContainerUser = containerUser.String
	}

	return &info, nil
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
