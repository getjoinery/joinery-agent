package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

const defaultStepTimeout = 30 * time.Minute

// Runner executes jobs by processing their steps sequentially.
type Runner struct {
	db      *DB
	sshPool *SSHPool
}

func NewRunner(db *DB) *Runner {
	return &Runner{
		db:      db,
		sshPool: NewSSHPool(),
	}
}

// Execute runs all steps in a job sequentially.
func (r *Runner) Execute(job *Job) {
	defer r.sshPool.CloseAll()

	steps := job.Commands.Steps
	if len(steps) == 0 {
		if err := r.db.CompleteJob(job.ID); err != nil {
			log.Printf("ERROR: could not mark job #%d as completed: %v", job.ID, err)
		}
		return
	}

	for i, step := range steps {
		log.Printf("  job #%d step %d/%d: [%s] %s", job.ID, i+1, len(steps), step.Type, step.Label)

		header := fmt.Sprintf("\n=== [Step %d/%d] %s ===\n", i+1, len(steps), step.Label)
		if err := r.db.AppendOutput(job.ID, header, i); err != nil {
			log.Printf("WARNING: could not write step header for job #%d: %v", job.ID, err)
		}

		timeout := defaultStepTimeout
		if step.Timeout > 0 {
			timeout = time.Duration(step.Timeout) * time.Second
		}

		output, err := r.executeStep(job, &step, timeout)

		// Write output
		if output != "" {
			if writeErr := r.db.AppendOutput(job.ID, output+"\n", i); writeErr != nil {
				log.Printf("WARNING: could not write output for job #%d step %d: %v", job.ID, i+1, writeErr)
			}
		}

		if err != nil {
			if step.ContinueOnError {
				errMsg := fmt.Sprintf("[ERROR (continuing): %s]\n", err.Error())
				r.db.AppendOutput(job.ID, errMsg, i)
				log.Printf("  job #%d step %d failed (continuing): %v", job.ID, i+1, err)
				continue
			}

			errMsg := fmt.Sprintf("[FAILED: %s]\n", err.Error())
			r.db.AppendOutput(job.ID, errMsg, i)
			failMsg := fmt.Sprintf("Step %d (%s) failed: %s", i+1, step.Label, err.Error())
			if failErr := r.db.FailJob(job.ID, failMsg); failErr != nil {
				log.Printf("ERROR: could not mark job #%d as failed: %v", job.ID, failErr)
			}
			log.Printf("  job #%d FAILED at step %d: %v", job.ID, i+1, err)
			return
		}
	}

	if err := r.db.CompleteJob(job.ID); err != nil {
		log.Printf("ERROR: could not mark job #%d as completed: %v", job.ID, err)
	}
	log.Printf("  job #%d completed successfully", job.ID)
}

// executeStep dispatches a step to the appropriate handler.
func (r *Runner) executeStep(job *Job, step *Step, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	switch step.Type {
	case "ssh":
		return r.executeSSH(ctx, job, step)
	case "scp":
		return r.executeSCP(ctx, job, step)
	case "local":
		return r.executeLocal(ctx, step)
	default:
		return "", fmt.Errorf("unknown step type %q — valid types are: ssh, scp, local", step.Type)
	}
}

// executeSSH runs a command on a remote host via SSH.
func (r *Runner) executeSSH(ctx context.Context, job *Job, step *Step) (string, error) {
	nodeID := job.NodeID
	if step.NodeID > 0 {
		nodeID = step.NodeID
	}

	if nodeID == 0 {
		return "", fmt.Errorf("SSH step %q has no target node. The job's node may have been deleted, " +
			"or this step is missing a node_id field", step.Label)
	}

	info, err := r.db.GetNodeConnInfo(nodeID)
	if err != nil {
		return "", err
	}

	cmd := step.Cmd

	// Wrap in docker exec if node is a container (unless on_host is set)
	if info.IsContainer() && !step.OnHost {
		escaped := strings.ReplaceAll(cmd, "'", "'\"'\"'")
		if info.ContainerUser != "" {
			cmd = fmt.Sprintf("docker exec -u %s %s bash -c '%s'", info.ContainerUser, info.ContainerName, escaped)
		} else {
			cmd = fmt.Sprintf("docker exec %s bash -c '%s'", info.ContainerName, escaped)
		}
	}

	return r.sshPool.RunCommand(ctx, info, cmd)
}

// executeSCP transfers a file between control plane and remote host.
func (r *Runner) executeSCP(ctx context.Context, job *Job, step *Step) (string, error) {
	nodeID := job.NodeID
	if step.NodeID > 0 {
		nodeID = step.NodeID
	}

	if nodeID == 0 {
		return "", fmt.Errorf("SCP step %q has no target node", step.Label)
	}

	info, err := r.db.GetNodeConnInfo(nodeID)
	if err != nil {
		return "", err
	}

	if step.Direction == "" {
		return "", fmt.Errorf("SCP step %q missing 'direction' field (must be 'upload' or 'download')", step.Label)
	}
	if step.RemotePath == "" {
		return "", fmt.Errorf("SCP step %q missing 'remote_path' field", step.Label)
	}
	if step.LocalPath == "" {
		return "", fmt.Errorf("SCP step %q missing 'local_path' field", step.Label)
	}

	return SCPTransfer(ctx, info, step.Direction, step.RemotePath, step.LocalPath)
}

// executeLocal runs a command on the control plane itself.
func (r *Runner) executeLocal(ctx context.Context, step *Step) (string, error) {
	if step.Cmd == "" {
		return "", fmt.Errorf("local step %q has no command to run", step.Label)
	}

	cmd := exec.CommandContext(ctx, "bash", "-c", step.Cmd)
	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return string(output), fmt.Errorf("TIMEOUT — command exceeded time limit")
	}

	if err != nil {
		return string(output), fmt.Errorf("command exited with error: %w", err)
	}

	return string(output), nil
}
