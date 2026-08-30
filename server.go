package main

// NodeAPIInfo holds the management-API credentials/URL for a managed node.
// The agent has one remote transport of its own — the management API. Remote
// shell and file transfer were removed deliberately: they belong to the
// plane-side executor, which runs as the site user rather than as root.
type NodeAPIInfo struct {
	ID          int64
	SiteURL     string
	PublicKey   string
	SecretKey   string
	TLSInsecure bool
}
