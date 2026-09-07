# Joinery Agent

A machine's own manager. The agent runs as root on a managed machine, asks the management node it joined whether there is work for it, and runs only the operations compiled into this binary — named primitives with fixed, validated parameters. It never takes a command string from anyone, and it has no shell of its own.

Adding an operation means adding a primitive here and a `build_<op>_primitive` method in the plugin. The Go side is not a generic executor and adding a PHP method alone does not reach a node.

## How It Works With Joinery

[Joinery](https://github.com/getjoinery/joinery) is a PHP membership and event management platform. Its **Server Manager** plugin (`plugins/server_manager/`) provides a web-based admin interface for managing Joinery instances -- backups, restores, updates, certificates and health.

An admin triggers an operation, and the plugin's `JobCommandBuilder` produces a `{primitive, params}` envelope: the NAME of an operation, not an instruction. The management node holds that until the node's own agent asks for it.

The agent polls its management node over a signed channel, outbound only. When it is handed a job it looks the name up in its own compiled-in vocabulary, validates the parameters itself, checks the operation's class against its root-owned policy, runs it, and posts the result back signed. **A job it does not recognise, or whose parameters do not validate, is refused** — and a refusal is recorded as such, so it can be counted rather than grepped for.

Anything destructive needs one thing more: an approval the node issues itself, sealed to its own backup recovery key and answered by a human on that node's own site. The answer never passes through the management node in either direction, so a fully compromised management node still cannot destroy anything.

**Where the database fits.** The agent reads its own site's database to answer questions about the machine it runs on, and writes one row to it — its own heartbeat. It takes no work from it. Inserting a row into `mjb_management_jobs` by hand executes nothing.

**Key database tables:**

- `mgn_managed_nodes` -- the management node's inventory: each node's public key, agent version, reported vocabulary and health
- `mjb_management_jobs` -- the management node's queue, handed out over the channel; not a source of work for any agent
- `ahb_agent_heartbeats` -- agent liveness on a machine that runs the plugin (the dashboard shows version, pending update and last-seen)

## Architecture

```
Management node (PHP)                 Agent (Go), on the managed machine
  |                                      |
  |  1. Admin triggers an operation      |
  |  2. JobCommandBuilder emits          |
  |     {primitive, params}              |
  |  3. Job stored, awaiting a claim     |
  |                                      |
  |         <---- signed claim --------  |  4. Agent asks: anything for me?
  |         ----- job envelope ------->  |
  |                                      |  5. Name looked up in THIS binary's
  |                                      |     vocabulary; unknown = refused
  |                                      |  6. Params validated here, not there
  |                                      |  7. Policy check; destructive also
  |                                      |     needs the node's own approval
  |                                      |  8. Runs. Scripts are verified
  |                                      |     against the signed manifest
  |         <---- signed result -------  |  9. completed | failed | refused
  |                                      |
  | 10. UI streams the result            |
```

The one exception is a machine's first minutes: `install_node` and `retire_install_password` run plane-side, over the provision's sealed password, because there is no agent yet to dispatch to. They are the only SSH the platform does, and the only jobs that carry steps rather than a name.

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
| `HEARTBEAT_INTERVAL` | `30s` | Heartbeat update interval |
| `AGENT_NAME` | `joinery-agent` | Agent identifier (shown in admin UI) |

## Safety Features

1. **A bounded vocabulary**: the agent runs the operations compiled into this binary and nothing else. It cannot be sent a command, a script path, a version source or an arbitrary argument, because no primitive declares a parameter that could carry one.

2. **The node validates its own parameters**: every primitive checks what it was handed before acting. A management node cannot talk a node into an operation the node would not do on its own.

3. **A root-owned policy**: which classes of operation this machine accepts is a file only root can write, on the machine itself. Destructive operations additionally need an approval the node issues and verifies itself, answered by a human on that node's own site.

4. **Scripts are verified before they run**: a script primitive checks the file against the signed release manifest, using the release key compiled into this binary. A machine with nothing to verify against refuses rather than running unverified.

5. **Single-threaded execution**: one job at a time, under a lock the self-update, bundle sync and manifest healer also take — so nothing swaps the binary or its scripts out from under a running job.

6. **A claim that never comes back is returned**: the management node re-queues a claim older than its budget and fails the job after three, so a crash mid-job strands nothing.

## File Structure

```
joinery-agent/
  main.go          Entry point: starts the job source and the watchers, then waits
  config.go        This machine's own configuration and posture
  remote.go        The signed channel: claim, run, post the result
  primitives/      The vocabulary — one file per operation, plus the policy
  approval.go      Destructive approval: the node's own challenge and its answer
  victim.go        A host asking a site for consent to its own removal
  join.go          Node-initiated enrollment
  leave.go         Ending a pairing from this side
  stagedwatch.go   Finishing a CLI join once the management node approves
  identity.go      This node's Ed25519 identity
  update.go        Signed self-update, with a watchdog rollback
  bundle.go        The support bundle, for a machine with no site tree
  manifestheal.go  Recovering a node that has stopped trusting its own files
  quiet.go         The run switch
  db.go            This machine's own site database: facts out, heartbeat in
  cli.go           One-shot operator subcommands
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
