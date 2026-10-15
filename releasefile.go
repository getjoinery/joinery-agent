package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"joinery-agent/primitives"
)

// Fetching one deployment file for restore_release_file and repair_release_files.
//
// The node names one of the five self-update files, compiled into the agent,
// and the sha256 its installed, key-verified manifest lists for that file. The
// plane finds the published release whose copy of the file has that hash and
// answers with the bytes. The node's VERSION travels too, as a hint of where to
// look first, and only as a hint: on a node whose VERSION and manifest disagree
// (a rollback that put the old code back under the new release's manifest) the
// hash is the one thing both the node and the plane can agree on, and the
// VERSION names a release whose file would be refused.
//
// The agent does not trust what comes back: the word checks the sha256 against
// the manifest before writing a byte, so this carries bytes and decides nothing.
// The same position the manifest and the agent binary are served from.
//
// maxReleaseFileEnvelopeBytes bounds the whole JSON answer: the file's own cap
// (primitives' 4 MiB), its base64 expansion, and the envelope.
const maxReleaseFileEnvelopeBytes = 6 << 20

var releaseFileHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func releaseFileRequestBody(id *NodeIdentity, version, rel, sha256 string) []byte {
	body, _ := json.Marshal(map[string]interface{}{
		"node_id": id.NodeID,
		"kind":    artifactKindReleaseFile,
		"version": version,
		"file":    rel,
		"sha256":  sha256,
	})
	return body
}

// releaseFileFetcher returns the ExecEnv hook, or nil where this machine has no
// site to repair.
func releaseFileFetcher(cfg *Config) func(ctx context.Context, version, rel, sha256 string) ([]byte, error) {
	if cfg == nil || cfg.SiteRoot == "" {
		return nil
	}
	client := newPlaneClient(cfg.PlaneTLSInsecure)
	return func(ctx context.Context, version, rel, sha256 string) ([]byte, error) {
		return fetchReleaseFile(ctx, client, version, rel, sha256)
	}
}

func fetchReleaseFile(ctx context.Context, client *http.Client, version, rel, sha256 string) ([]byte, error) {
	if !primitives.IsSelfUpdateFile(rel) {
		return nil, fmt.Errorf("%s is not a file this agent asks for", rel)
	}
	if !releaseFileHashPattern.MatchString(sha256) {
		return nil, errors.New("a release file is asked for by the sha256 the signed manifest lists, and none was given")
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
		releaseFileRequestBody(id, version, rel, sha256), maxReleaseFileEnvelopeBytes)
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
		return nil, errors.New("the management node has no published release that carries this file with that hash")
	}
	body, err := base64.StdEncoding.DecodeString(payload.Content)
	if err != nil {
		return nil, errors.New("the management node sent an unreadable file")
	}
	return body, nil
}
