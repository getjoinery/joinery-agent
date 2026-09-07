package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// How long a reachability probe waits before calling the database unavailable.
// Short on purpose: this answers "can I do database work this minute", and a
// caller blocked on the answer is a caller not doing the work it still can.
const dbProbeTimeout = 5 * time.Second

// DB wraps this machine's own site database. It is a place the agent reads
// facts about the site it runs on and writes its own heartbeat — never a
// source of work. Jobs arrive over the signed channel and nowhere else.
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

// HasHeartbeatTable reports whether this machine's own site carries the
// server_manager heartbeat table, which is the one thing an agent writes to a
// local database about itself.
//
// This is a capability question, not a health check. A plain managed node has
// no such table and is working exactly as intended — it takes its work from
// the management node it joined, over the channel, and its liveness is the
// polling itself. Only a machine running server_manager has a dashboard that
// wants a row here, and asking every tick rather than once at boot is what
// lets a heartbeat come back after the plugin is installed, or after an
// outage, without a restart.
func (d *DB) HasHeartbeatTable() bool {
	var exists bool
	err := d.conn.QueryRow(
		"SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)",
		"ahb_agent_heartbeats",
	).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
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

// nowUTC returns current time formatted for PostgreSQL.
func nowUTC() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05")
}
