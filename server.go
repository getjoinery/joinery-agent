package main

// NodeConnInfo holds SSH connection details for a managed node.
type NodeConnInfo struct {
	ID             int64
	Host           string
	SSHUser        string
	SSHKeyPath     string
	SSHPort        int
	ContainerName  string
	ContainerUser  string
}

// IsContainer returns true if this node runs inside a Docker container.
func (n *NodeConnInfo) IsContainer() bool {
	return n.ContainerName != ""
}
