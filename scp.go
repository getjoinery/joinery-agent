package main

import (
	"context"
	"fmt"
	"os/exec"
)

// SCPTransfer copies a file between the control plane and a remote host.
// direction: "upload" (local→remote) or "download" (remote→local).
func SCPTransfer(ctx context.Context, info *NodeConnInfo, direction, remotePath, localPath string) (string, error) {
	args := buildSCPArgs(info)

	remote := fmt.Sprintf("%s@%s:%s", info.SSHUser, info.Host, remotePath)

	switch direction {
	case "download":
		args = append(args, remote, localPath)
	case "upload":
		args = append(args, localPath, remote)
	default:
		return "", fmt.Errorf("unknown SCP direction: %s", direction)
	}

	cmd := exec.CommandContext(ctx, "scp", args...)
	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return string(output), fmt.Errorf("SCP TIMEOUT")
	}

	if err != nil {
		return string(output), fmt.Errorf("SCP failed: %w\n%s", err, string(output))
	}

	return fmt.Sprintf("SCP %s completed: %s", direction, remotePath), nil
}

// buildSCPArgs builds the common SCP arguments from node connection info.
func buildSCPArgs(info *NodeConnInfo) []string {
	args := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=15",
	}

	if info.SSHKeyPath != "" {
		args = append(args, "-i", info.SSHKeyPath)
	}

	if info.SSHPort != 22 {
		args = append(args, "-P", fmt.Sprintf("%d", info.SSHPort))
	}

	return args
}
