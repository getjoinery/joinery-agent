package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"time"
)

const defaultStepTimeout = 30 * time.Minute

// runnerStore is the slice of DB the runner needs. *DB implements it; the
// runner tests substitute an in-memory fake so the main/teardown flow can be
// exercised without a database or SSH.
type runnerStore interface {
	AppendOutput(jobID int64, text string, currentStep int) error
	CompleteJob(jobID int64) error
	FailJob(jobID int64, errorMsg string) error
	GetNodeAPIInfo(nodeID int64) (*NodeAPIInfo, error)
	GetBackupTargetCredentials(targetID int64) (string, error)
	GetBackupTargetNodeCredentials(targetID int64) (string, error)
}

// Runner executes jobs by processing their steps sequentially.
type Runner struct {
	db runnerStore
	// secretBoxKey unseals backup-target credentials for __SM_CREDS_<id>__
	// placeholder resolution. Decoded once at construction; nil if unset or
	// malformed (placeholder resolution then fails loudly for sealed targets).
	secretBoxKey *[32]byte
	// exec runs a single step. Overridable in tests.
	exec func(job *Job, step *Step, timeout time.Duration) (string, error)
}

func NewRunner(db *DB, secretBoxKey string) *Runner {
	r := &Runner{
		db: db,
	}
	if secretBoxKey != "" {
		if key, err := decodeSecretBoxKey(secretBoxKey); err != nil {
			log.Printf("WARNING: secret_box_key present but unusable (%v) — encrypted backup-target credentials will not resolve", err)
		} else {
			r.secretBoxKey = key
		}
	}
	r.exec = r.executeStep
	return r
}

// partitionSteps splits a job's steps into the main phase and the teardown
// phase, preserving order within each. Builders that never set the flag
// produce an empty teardown phase and run exactly as before.
func partitionSteps(steps []Step) (mainSteps, teardownSteps []Step) {
	for _, s := range steps {
		if s.Teardown {
			teardownSteps = append(teardownSteps, s)
		} else {
			mainSteps = append(mainSteps, s)
		}
	}
	return mainSteps, teardownSteps
}

// Execute runs a job: the main steps in order, then the teardown steps on
// every exit path — success, hard failure, and the empty-main-steps case —
// then writes the outcome the main phase determined. The job stays 'running'
// while teardown executes, so the per-node lock in ClaimNextJob is held and
// the job detail view keeps streaming teardown output.
func (r *Runner) Execute(job *Job) {

	mainSteps, teardownSteps := partitionSteps(job.Commands.Steps)

	failMsg, lastIndex := r.runMainPhase(job, mainSteps)

	r.runTeardown(job, teardownSteps, lastIndex)

	// Teardown never changes the outcome: write the held result unmodified,
	// so a failed job keeps naming the step that actually failed.
	if failMsg != "" {
		if failErr := r.db.FailJob(job.ID, failMsg); failErr != nil {
			log.Printf("ERROR: could not mark job #%d as failed: %v", job.ID, failErr)
		}
		return
	}
	if err := r.db.CompleteJob(job.ID); err != nil {
		log.Printf("ERROR: could not mark job #%d as completed: %v", job.ID, err)
	}
	log.Printf("  job #%d completed successfully", job.ID)
}

// runMainPhase executes the main steps, stopping at the first hard failure.
// Returns the job's failure message ("" on success) and the step index the
// output stream ended at, which teardown appends reuse so they never advance
// the progress counter.
func (r *Runner) runMainPhase(job *Job, steps []Step) (failMsg string, lastIndex int) {
	for i, step := range steps {
		lastIndex = i
		log.Printf("  job #%d step %d/%d: [%s] %s", job.ID, i+1, len(steps), step.Type, step.Label)

		header := fmt.Sprintf("\n=== [Step %d/%d] %s ===\n", i+1, len(steps), step.Label)
		if err := r.db.AppendOutput(job.ID, header, i); err != nil {
			log.Printf("WARNING: could not write step header for job #%d: %v", job.ID, err)
		}

		timeout := defaultStepTimeout
		if step.Timeout > 0 {
			timeout = time.Duration(step.Timeout) * time.Second
		}

		output, err := r.exec(job, &step, timeout)

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
			log.Printf("  job #%d FAILED at step %d: %v", job.ID, i+1, err)
			return fmt.Sprintf("Step %d (%s) failed: %s", i+1, step.Label, err.Error()), i
		}
	}
	return "", lastIndex
}

// runTeardown executes the teardown steps. One failing does not stop the
// rest, and no failure is ever promoted to the job's outcome — it is logged
// under the teardown header and the job keeps the main phase's result.
func (r *Runner) runTeardown(job *Job, steps []Step, lastIndex int) {
	if len(steps) == 0 {
		return
	}

	if err := r.db.AppendOutput(job.ID, "\n=== Teardown ===\n", lastIndex); err != nil {
		log.Printf("WARNING: could not write teardown header for job #%d: %v", job.ID, err)
	}

	for i, step := range steps {
		log.Printf("  job #%d teardown %d/%d: [%s] %s", job.ID, i+1, len(steps), step.Type, step.Label)

		if err := r.db.AppendOutput(job.ID, fmt.Sprintf("--- %s ---\n", step.Label), lastIndex); err != nil {
			log.Printf("WARNING: could not write teardown step header for job #%d: %v", job.ID, err)
		}

		timeout := defaultStepTimeout
		if step.Timeout > 0 {
			timeout = time.Duration(step.Timeout) * time.Second
		}

		output, err := r.exec(job, &step, timeout)

		if output != "" {
			r.db.AppendOutput(job.ID, output+"\n", lastIndex)
		}
		if err != nil {
			r.db.AppendOutput(job.ID, fmt.Sprintf("[teardown error (ignored): %s]\n", err.Error()), lastIndex)
			log.Printf("  job #%d teardown step %d failed (ignored): %v", job.ID, i+1, err)
		}
	}
}

// ReplayTeardown runs only a job's teardown steps. Used for jobs force-failed
// by stale recovery: scratch paths are per-job unique and every teardown
// command is idempotent, so replaying is safe no matter how far the job got.
func (r *Runner) ReplayTeardown(job *Job) {
	_, teardownSteps := partitionSteps(job.Commands.Steps)
	r.runTeardown(job, teardownSteps, job.CurrentStep)
}

// resolveCmd substitutes any credential placeholders (__SM_CREDS_<id>__ for
// the main slot, __SM_NODE_CREDS_<id>__ for the node-facing write-only slot)
// in a command with the target's real (unsealed) credentials, in memory, just
// before the command runs. A command with no placeholder is returned
// unchanged; a lookup or unseal failure aborts the step.
func (r *Runner) resolveCmd(cmd string) (string, error) {
	return substituteCredPlaceholders(cmd, r.secretBoxKey,
		r.db.GetBackupTargetCredentials, r.db.GetBackupTargetNodeCredentials)
}

// executeStep dispatches a step to the appropriate handler.
func (r *Runner) executeStep(job *Job, step *Step, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	switch step.Type {
	case "ssh", "scp":
		// Removed deliberately. This was a legacy runner with no connection to
		// the primitive path, and leaving it in place kept producing designs
		// that worked around it instead of replacing it. Steps of this type are
		// still composed plane-side; refusing them here is the tripwire that
		// says so.
		return "", fmt.Errorf("SSH and SCP capability is deprecated (step type %q)", step.Type)
	case "local":
		return r.executeLocal(ctx, step)
	case "api":
		return r.executeAPI(ctx, job, step)
	default:
		return "", fmt.Errorf("unknown step type %q — valid types are: ssh, scp, local, api", step.Type)
	}
}

// executeLocal runs a command on the control plane itself.
func (r *Runner) executeLocal(ctx context.Context, step *Step) (string, error) {
	if step.Cmd == "" {
		return "", fmt.Errorf("local step %q has no command to run", step.Label)
	}

	resolved, err := r.resolveCmd(step.Cmd)
	if err != nil {
		return "", err
	}

	cmd := exec.CommandContext(ctx, "bash", "-c", resolved)
	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return string(output), fmt.Errorf("TIMEOUT — command exceeded time limit")
	}

	if err != nil {
		return string(output), fmt.Errorf("command exited with error: %w", err)
	}

	return string(output), nil
}
