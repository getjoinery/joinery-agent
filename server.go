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

// NodeAPIInfo holds the management-API credentials/URL for a managed node.
// Separate from NodeConnInfo because SSH and API are orthogonal transports;
// a node may have one, both, or neither configured.
type NodeAPIInfo struct {
	ID           int64
	SiteURL      string
	PublicKey    string
	SecretKey    string
	TLSInsecure  bool
}
