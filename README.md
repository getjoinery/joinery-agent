# Joinery Agent

A generic job executor for the [Joinery](https://github.com/getjoinery/joinery) Server Manager plugin. The agent polls a PostgreSQL job queue for pending work, executes steps via SSH/SCP/local commands, and writes output back to the database.

The agent has no knowledge of job types. All intelligence about what commands to run lives in the PHP plugin's `JobCommandBuilder` class. Adding a new operation (e.g., "restart Apache") requires only a new PHP method -- no Go changes, no agent redeployment.

## How It Works With Joinery

[Joinery](https://github.com/getjoinery/joinery) is a PHP membership and event management platform. Its **Server Manager** plugin (`plugins/server_manager/`) provides a web-based admin interface for managing remote Joinery instances -- backups, database operations, updates, and health monitoring.

The plugin handles all the decision-making: an admin triggers an operation from the web UI, and the plugin's `JobCommandBuilder` translates that into an ordered array of shell commands. These are written to the `mjb_management_jobs` table as a JSON step list with status `pending`. That's where the PHP side ends and this Go agent takes over.

The agent runs as a systemd service on the same server, polling the job table every few seconds. When it finds a pending job, it claims it, executes each step in order (SSH into a remote host, transfer files via SCP, or run local commands), writes output back to the database after each step, and marks the job completed or failed. The plugin's admin UI polls for status updates and streams the output in real time.

**Supported operations** (all defined in PHP, not Go):

| Operation | What it does |
|-----------|-------------|
| Test Connection | SSH echo to verify node reachability |
| Check Status | Collects disk, memory, uptime, PostgreSQL stats, error logs |
| Backup Database | Runs `pg_dump` on the remote node with optional encryption |
| Backup Project | Archives the remote Joinery installation files |
| Fetch Backup | SCP downloads a backup file from a remote node |
| Copy Database | Dumps source DB, transfers to target node, restores (with auto-safety backup) |
| Restore Database | Restores a database from a backup file (with auto-safety backup) |
| Apply Update | Runs `upgrade.php` on a remote node to apply a Joinery version update |
| Publish Upgrade | Runs `publish_upgrade.php` locally to package a new release |
| Discover Nodes | Probes a remote host via SSH to find Joinery instances (Docker and bare metal) |

**Key database tables:**

- `mjb_management_jobs` -- Job queue with status tracking, step JSON, and output
- `mgn_managed_nodes` -- Remote server inventory with SSH credentials and health data
- `ahb_agent_heartbeats` -- Agent liveness tracking (the admin dashboard shows online/offline based on heartbeat age)

## Architecture

```
Plugin (PHP)                          Agent (Go)
  |                                      |
  |  1. Admin triggers operation         |
  |  2. JobCommandBuilder generates      |
  |     ordered step array               |
  |  3. Writes job row to DB             |
  |     (status = 'pending')             |
  |                                      |
  |                                      |  4. Agent polls, finds pending job
  |                                      |  5. Claims job (status = 'running')
  |                                      |  6. Executes steps sequentially:
  |                                      |     - ssh: SSH to host, run command
  |                                      |     - scp: file transfer
  |                                      |     - local: run on control plane
  |                                      |  7. Writes output to mjb_output
  |                                      |  8. Marks job completed/failed
  |                                      |
  |  9. UI polls ajax/job_status.php     |
  |     for live output                  |
```

## Three Primitives

| Type | Description |
|------|-------------|
| `ssh` | Connect to host via SSH, run a command. Auto-wraps in `docker exec` for container nodes. |
| `scp` | Copy a file between control plane and remote host (upload or download). |
| `local` | Run a command on the control plane itself. |

## Prerequisites

- Go 1.22+ (build only)
- PostgreSQL access to the Joinery control plane database
- SSH key access to managed servers (the agent runs SSH commands using keys configured on each node)
- The `server_manager` [Joinery](https://github.com/getjoinery/joinery) plugin must be installed and activated

## Install

### 1. Build the installer

```bash
cd /home/user1/joinery-agent
make release VERSION=1.0.0
```

This compiles the binary and packages it into `joinery-agent-installer.sh`.

### 2. Run the installer

```bash
sudo bash joinery-agent-installer.sh --verbose
```

This creates:
- `/usr/local/bin/joinery-agent` -- the binary
- `/etc/systemd/system/joinery-agent.service` -- systemd unit (enabled automatically)
- `/etc/joinery-agent/joinery-agent.env` -- configuration (first install only, never overwritten on upgrade)

### 3. Start

No configuration needed on a standard install. The agent reads database credentials directly from `Globalvars_site.php` at `/var/www/html/joinerytest/config/Globalvars_site.php`.

If your Joinery install is at a different path, edit the env file:

```bash
sudo nano /etc/joinery-agent/joinery-agent.env
# Set: JOINERY_CONFIG=/var/www/html/mysite/config/Globalvars_site.php
```

```bash
sudo systemctl start joinery-agent
sudo systemctl status joinery-agent
```

The dashboard at `/admin/server_manager` should show **Agent Status: Online** within a few seconds.

If something is wrong, check the logs:

```bash
journalctl -u joinery-agent -f
```

Startup errors are self-explanatory. Common issues:
- **"Could not read Joinery config"** -- set `JOINERY_CONFIG` in the env file to the correct path
- **"database authentication failed"** -- `Globalvars_site.php` has wrong credentials
- **"required tables missing"** -- install and activate the Server Manager plugin first

### 4. Add nodes

Go to `/admin/server_manager/nodes_edit`. The **Auto-Detect** panel scans a remote host for Joinery instances:

1. Enter the SSH host IP and key path
2. Click **Detect** -- the agent SSHes in and finds all Joinery installs (Docker containers and bare metal)
3. Click **Add This Node** on any detected instance -- saves in one click with all fields populated

Auto-detect runs through the agent, so it must be running first.

## Upgrade

```bash
cd /home/user1/joinery-agent
make release VERSION=1.x.x
sudo bash joinery-agent-installer.sh --verbose
```

The installer auto-detects upgrade vs fresh install. On upgrade it stops the service, swaps the binary, restarts, and rolls back automatically if the service fails to start within 2 seconds.

## Configuration Reference

Database credentials are read automatically from `Globalvars_site.php`. Environment variables override the auto-detected values.

| Variable | Default | Description |
|----------|---------|-------------|
| `JOINERY_CONFIG` | `/var/www/html/joinerytest/config/Globalvars_site.php` | Path to Joinery config (DB creds read from here) |
| `DB_HOST` | `localhost` | PostgreSQL host (override) |
| `DB_PORT` | `5432` | PostgreSQL port (override) |
| `DB_NAME` | _(from Globalvars)_ | Database name (override) |
| `DB_USER` | _(from Globalvars)_ | Database user (override) |
| `DB_PASSWORD` | _(from Globalvars)_ | Database password (override) |
| `POLL_INTERVAL` | `5s` | Job queue poll interval |
| `HEARTBEAT_INTERVAL` | `30s` | Heartbeat update interval |
| `AGENT_NAME` | `joinery-agent` | Agent identifier (shown in admin UI) |

## Safety Features

1. **Stale job recovery**: On startup, any jobs stuck in `running` state are marked `failed` with a descriptive message. This handles agent crashes mid-job.

2. **Per-node concurrency lock**: The agent skips pending jobs if another job is already `running` on the same node, preventing conflicting operations (e.g., backup + update on the same server).

3. **Step timeout**: Each step has a 30-minute default timeout. Override per-step with a `timeout` field in the step JSON. On timeout, the SSH session is killed and the job fails.

4. **Single-threaded execution**: One job at a time. Queued jobs run sequentially. This simplifies concurrency, SSH connection management, and output logging.

5. **SSH connection pooling**: Within a single job, SSH connections to the same host are reused across steps, avoiding repeated authentication overhead.

## File Structure

```
joinery-agent/
  main.go          Entry point, signal handling, poll loop
  config.go        Configuration from environment variables
  db.go            PostgreSQL: job claiming, output writing, heartbeat
  runner.go        Step executor: dispatches to ssh/scp/local handlers
  ssh.go           SSH connection pooling and remote command execution
  scp.go           SCP file transfer (upload/download)
  server.go        Node connection info struct
  Makefile          build / test / release targets
  go.mod            Go module definition
  install/
    joinery-agent.service   systemd unit file
  config/
    joinery-agent.env.example   example configuration
```

## Development

```bash
# Build
make build

# Run tests
make test

# Run directly (for development)
DB_NAME=joinerytest DB_PASSWORD=xxx ./joinery-agent

# Check version
./joinery-agent --version
```

## License

[PolyForm Noncommercial 1.0.0](LICENSE) -- free for noncommercial use. Contact [Joinery](https://getjoinery.com) for commercial licensing.
