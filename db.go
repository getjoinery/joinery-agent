package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
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

// ValidateSchema checks that the required plugin tables exist.
// Called on startup to fail fast with a clear message instead of
// crashing later with cryptic SQL errors.
func (d *DB) ValidateSchema() error {
	requiredTables := []string{"mgn_managed_nodes", "mjb_management_jobs", "ahb_agent_heartbeats"}
	missing := []string{}

	for _, table := range requiredTables {
		var exists bool
		err := d.conn.QueryRow(
			"SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)", table,
		).Scan(&exists)
		if err != nil {
			return fmt.Errorf("could not check for table %s: %w", table, err)
		}
		if !exists {
			missing = append(missing, table)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("required tables missing from database: %s\n"+
			"  The server_manager plugin is not installed or not activated.\n"+
			"  To fix this:\n"+
			"    1. Log in to your Joinery admin panel\n"+
			"    2. Go to /admin/admin_plugins\n"+
			"    3. Find 'Server Manager' and click Install, then Activate\n"+
			"    4. Restart the agent: sudo systemctl restart joinery-agent",
			strings.Join(missing, ", "))
	}

	return nil
}

// ClaimNextJob finds the oldest pending job, checks per-node concurrency,
// and atomically claims it. Returns nil if no jobs are available.
func (d *DB) ClaimNextJob() (*Job, error) {
	row := d.conn.QueryRow(`
		SELECT mjb_id, mjb_mgn_node_id, mjb_job_type, mjb_commands, mjb_total_steps
		FROM mjb_management_jobs
		WHERE mjb_status = 'pending'
		  AND mjb_delete_time IS NULL
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

// RecoverStaleJobs marks any jobs stuck in 'running' state as failed.
func (d *DB) RecoverStaleJobs() (int, error) {
	result, err := d.conn.Exec(`
		UPDATE mjb_management_jobs
		SET mjb_status = 'failed',
		    mjb_error_message = 'Agent restarted while job was running. Job may have partially completed. Check job output for details, then use Re-run if needed.',
		    mjb_completed_time = now(),
		    mjb_update_time = now()
		WHERE mjb_status = 'running'
	`)
	if err != nil {
		return 0, err
	}
	affected, _ := result.RowsAffected()
	return int(affected), nil
}

// UpdateHeartbeat inserts or updates the agent's heartbeat record.
func (d *DB) UpdateHeartbeat(agentName, agentVersion string) error {
	_, err := d.conn.Exec(`
		INSERT INTO ahb_agent_heartbeats (ahb_agent_name, ahb_last_heartbeat, ahb_agent_version, ahb_status, ahb_create_time)
		VALUES ($1, now(), $2, 'running', now())
		ON CONFLICT (ahb_agent_name)
		DO UPDATE SET ahb_last_heartbeat = now(),
		              ahb_agent_version = $2,
		              ahb_status = 'running',
		              ahb_update_time = now()
	`, agentName, agentVersion)
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

// nowUTC returns current time formatted for PostgreSQL.
func nowUTC() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05")
}
