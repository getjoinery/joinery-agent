package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"joinery-agent/primitives"
)

// Fetching one deployment file for restore_release_file.
//
// The node names a VERSION and one of the five self-update files, both chosen by
// the agent from its own tree and compiled list. The plane resolves them against
// its own layout and answers with the file's bytes out of the published core
// archive. The agent does not trust them: restore_release_file checks the sha256
// against the installed, key-verified manifest before writing a byte, so this
// carries bytes and decides nothing. The same position the manifest and the
// agent binary are served from.
//
// maxReleaseFileEnvelopeBytes bounds the whole JSON answer: the file's own cap
// (primitives' 4 MiB), its base64 expansion, and the envelope.
const maxReleaseFileEnvelopeBytes = 6 << 20

func releaseFileRequestBody(id *NodeIdentity, version, rel string) []byte {
	body, _ := json.Marshal(map[string]interface{}{
		"node_id": id.NodeID,
		"kind":    artifactKindReleaseFile,
		"version": version,
		"file":    rel,
	})
	return body
}

// releaseFileFetcher returns the ExecEnv hook, or nil where this machine has no
// site to repair.
func releaseFileFetcher(cfg *Config) func(ctx context.Context, version, rel string) ([]byte, error) {
	if cfg == nil || cfg.SiteRoot == "" {
		return nil
	}
	client := newPlaneClient(cfg.PlaneTLSInsecure)
	return func(ctx context.Context, version, rel string) ([]byte, error) {
		return fetchReleaseFile(ctx, client, version, rel)
	}
}

func fetchReleaseFile(ctx context.Context, client *http.Client, version, rel string) ([]byte, error) {
	if !primitives.IsSelfUpdateFile(rel) {
		return nil, fmt.Errorf("%s is not a file this agent asks for", rel)
	}
	id, err := LoadIdentity(IdentityPath())
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, errors.New("this machine is not enrolled with a management node")
	}
	ctx, cancel := context.WithTimeout(ctx, remoteHTTPTimeout)
	defer cancel()
	raw, err := signedPlanePostCapped(ctx, client, id, pathArtifact,
		releaseFileRequestBody(id, version, rel), maxReleaseFileEnvelopeBytes)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Available bool   `json:"available"`
		Content   string `json:"content"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("the management node sent an unreadable answer: %w", err)
	}
	if !payload.Available || payload.Content == "" {
		return nil, errors.New("the management node has no copy of that file for this release")
	}
	body, err := base64.StdEncoding.DecodeString(payload.Content)
	if err != nil {
		return nil, errors.New("the management node sent an unreadable file")
	}
	return body, nil
}
