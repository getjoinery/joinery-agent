package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHPool manages reusable SSH connections keyed by host:port.
type SSHPool struct {
	mu      sync.Mutex
	clients map[string]*ssh.Client
}

func NewSSHPool() *SSHPool {
	return &SSHPool{
		clients: make(map[string]*ssh.Client),
	}
}

// getClient returns a cached or new SSH client for the given node.
func (p *SSHPool) getClient(info *NodeConnInfo) (*ssh.Client, error) {
	key := fmt.Sprintf("%s:%d", info.Host, info.SSHPort)

	p.mu.Lock()
	if client, ok := p.clients[key]; ok {
		_, _, err := client.SendRequest("keepalive@joinery-agent", true, nil)
		if err == nil {
			p.mu.Unlock()
			return client, nil
		}
		client.Close()
		delete(p.clients, key)
	}
	p.mu.Unlock()

	// Validate SSH key path before attempting connection
	if info.SSHKeyPath == "" {
		return nil, fmt.Errorf("no SSH key path configured for node %q (%s).\n"+
			"  Edit this node at /admin/server_manager/nodes_edit?mgn_id=%d and set the SSH Key Path field.\n"+
			"  Available keys on this server: ls ~/.ssh/id_*",
			info.Host, key, info.ID)
	}

	if _, err := os.Stat(info.SSHKeyPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("SSH key file not found: %s\n"+
			"  This key path is configured for node %q.\n"+
			"  Either the file was moved/deleted, or the path is wrong.\n"+
			"  Edit this node at /admin/server_manager/nodes_edit?mgn_id=%d to fix it.\n"+
			"  Available keys on this server: ls ~/.ssh/id_*",
			info.SSHKeyPath, info.Host, info.ID)
	}

	// Build SSH config
	sshConfig := &ssh.ClientConfig{
		User:            info.SSHUser,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	keyData, err := os.ReadFile(info.SSHKeyPath)
	if err != nil {
		return nil, fmt.Errorf("could not read SSH key %s: %w\n"+
			"  Check file permissions: ls -la %s",
			info.SSHKeyPath, err, info.SSHKeyPath)
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		if strings.Contains(err.Error(), "passphrase") {
			return nil, fmt.Errorf("SSH key %s is passphrase-protected, which is not supported.\n"+
				"  Generate a key without a passphrase: ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_joinery",
				info.SSHKeyPath)
		}
		return nil, fmt.Errorf("could not parse SSH key %s: %w\n"+
			"  The file may be corrupted or in an unsupported format.",
			info.SSHKeyPath, err)
	}
	sshConfig.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}

	addr := fmt.Sprintf("%s:%d", info.Host, info.SSHPort)
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "connection refused") {
			return nil, fmt.Errorf("SSH connection refused at %s.\n"+
				"  Is SSH running on the remote host? Check: ssh %s@%s -p %d -i %s\n"+
				"  Is the port correct? Current setting: %d",
				addr, info.SSHUser, info.Host, info.SSHPort, info.SSHKeyPath, info.SSHPort)
		}
		if strings.Contains(errStr, "no route to host") || strings.Contains(errStr, "network is unreachable") {
			return nil, fmt.Errorf("cannot reach host %s — network unreachable.\n"+
				"  Is the server online? Try: ping %s",
				info.Host, info.Host)
		}
		if strings.Contains(errStr, "i/o timeout") {
			return nil, fmt.Errorf("SSH connection to %s timed out after 15 seconds.\n"+
				"  The host may be down, or a firewall may be blocking port %d.\n"+
				"  Try: ssh %s@%s -p %d -i %s",
				addr, info.SSHPort, info.SSHUser, info.Host, info.SSHPort, info.SSHKeyPath)
		}
		if strings.Contains(errStr, "unable to authenticate") || strings.Contains(errStr, "no supported methods") {
			return nil, fmt.Errorf("SSH authentication failed for %s@%s.\n"+
				"  The key %s may not be authorized on the remote host.\n"+
				"  To fix: copy the public key to the remote host:\n"+
				"    ssh-copy-id -i %s %s@%s -p %d",
				info.SSHUser, info.Host, info.SSHKeyPath,
				info.SSHKeyPath, info.SSHUser, info.Host, info.SSHPort)
		}
		return nil, fmt.Errorf("SSH connection to %s failed: %w\n"+
			"  Try manually: ssh %s@%s -p %d -i %s",
			addr, err, info.SSHUser, info.Host, info.SSHPort, info.SSHKeyPath)
	}

	p.mu.Lock()
	p.clients[key] = client
	p.mu.Unlock()

	return client, nil
}

// RunCommand executes a command on the remote host and returns the output.
func (p *SSHPool) RunCommand(ctx context.Context, info *NodeConnInfo, cmd string) (string, error) {
	client, err := p.getClient(info)
	if err != nil {
		return "", err
	}

	session, err := client.NewSession()
	if err != nil {
		// Connection may have died, clear cache and retry once
		p.mu.Lock()
		key := fmt.Sprintf("%s:%d", info.Host, info.SSHPort)
		if c, ok := p.clients[key]; ok {
			c.Close()
			delete(p.clients, key)
		}
		p.mu.Unlock()

		client, err = p.getClient(info)
		if err != nil {
			return "", err
		}
		session, err = client.NewSession()
		if err != nil {
			return "", fmt.Errorf("could not create SSH session to %s:%d after reconnecting: %w",
				info.Host, info.SSHPort, err)
		}
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- session.Run(cmd)
	}()

	select {
	case <-ctx.Done():
		session.Signal(ssh.SIGKILL)
		return stdout.String() + stderr.String(), fmt.Errorf("TIMEOUT — command exceeded time limit")
	case err := <-done:
		output := stdout.String()
		if stderr.Len() > 0 {
			if output != "" {
				output += "\n"
			}
			output += stderr.String()
		}
		if err != nil {
			return output, fmt.Errorf("command exited with error: %w", err)
		}
		return output, nil
	}
}

// CloseAll closes all cached SSH connections.
func (p *SSHPool) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, client := range p.clients {
		client.Close()
		delete(p.clients, key)
	}
}

// sshAddr returns the SSH address string for a node.
func sshAddr(info *NodeConnInfo) string {
	return net.JoinHostPort(info.Host, fmt.Sprintf("%d", info.SSHPort))
}
