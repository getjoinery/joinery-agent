package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// executeAPI performs an HTTP call against the target node's management API.
//
// Resolves node credentials from mgn_managed_nodes (site URL, public/secret key,
// tls_insecure flag), issues the request, and returns the response body as a
// string. For endpoints that produce large binary payloads (backups/fetch),
// the step's `local_path` field redirects the body to a file on the control
// plane instead of into the job output.
func (r *Runner) executeAPI(ctx context.Context, job *Job, step *Step) (string, error) {
	if step.Endpoint == "" {
		return "", fmt.Errorf("api step %q is missing the 'endpoint' field", step.Label)
	}

	nodeID := job.NodeID
	if step.NodeID > 0 {
		nodeID = step.NodeID
	}
	if nodeID == 0 {
		return "", fmt.Errorf("api step %q has no target node — set node_id on the step "+
			"or on the job", step.Label)
	}

	api, err := r.db.GetNodeAPIInfo(nodeID)
	if err != nil {
		return "", err
	}

	method := strings.ToUpper(step.Method)
	if method == "" {
		method = "GET"
	}

	targetURL, err := buildAPIURL(api.SiteURL, step.Endpoint, step.Query)
	if err != nil {
		return "", err
	}

	var bodyReader io.Reader
	if step.Body != nil && method != "GET" && method != "DELETE" {
		payload, err := json.Marshal(step.Body)
		if err != nil {
			return "", fmt.Errorf("marshaling api step body: %w", err)
		}
		bodyReader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return "", fmt.Errorf("building api request: %w", err)
	}
	req.Header.Set("public_key", api.PublicKey)
	req.Header.Set("secret_key", api.SecretKey)
	req.Header.Set("Accept", "application/json, application/octet-stream")
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: api.TLSInsecure},
			TLSHandshakeTimeout: 15 * time.Second,
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("api request to %s failed: %w", targetURL, err)
	}
	defer resp.Body.Close()

	expected := step.ExpectStatus
	if expected == 0 {
		expected = 200
	}

	// For backup fetches and any other "stream to file" step, LocalPath tells us
	// where to write the body. Keeps huge binary payloads out of mjb_output.
	if step.LocalPath != "" {
		return streamAPIResponseToFile(resp, step.LocalPath, expected, targetURL)
	}

	// Buffered read — small JSON payloads go into job output.
	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return "", fmt.Errorf("reading api response body: %w", readErr)
	}
	bodyStr := string(bodyBytes)

	if resp.StatusCode != expected {
		return truncate(bodyStr, 4096),
			fmt.Errorf("api %s %s returned HTTP %d (expected %d)",
				method, targetURL, resp.StatusCode, expected)
	}

	return bodyStr, nil
}

// streamAPIResponseToFile copies the response body to local_path in chunks.
// Cleans up the partial file on failure.
func streamAPIResponseToFile(resp *http.Response, localPath string, expected int, targetURL string) (string, error) {
	if resp.StatusCode != expected {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return string(preview),
			fmt.Errorf("api GET %s returned HTTP %d (expected %d)",
				targetURL, resp.StatusCode, expected)
	}

	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return "", fmt.Errorf("creating directory for %s: %w", localPath, err)
	}

	file, err := os.Create(localPath)
	if err != nil {
		return "", fmt.Errorf("creating file %s: %w", localPath, err)
	}

	bytesWritten, copyErr := io.Copy(file, resp.Body)
	closeErr := file.Close()

	if copyErr != nil {
		_ = os.Remove(localPath)
		return "", fmt.Errorf("streaming api response to %s: %w", localPath, copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(localPath)
		return "", fmt.Errorf("closing %s: %w", localPath, closeErr)
	}

	return fmt.Sprintf("Streamed %d bytes to %s", bytesWritten, localPath), nil
}

// buildAPIURL composes the full URL: baseURL + /api/v1/management/<endpoint> + ?query
func buildAPIURL(baseURL, endpoint string, query map[string]string) (string, error) {
	base := strings.TrimRight(baseURL, "/")
	endpoint = strings.TrimLeft(endpoint, "/")

	full := fmt.Sprintf("%s/api/v1/management/%s", base, endpoint)

	u, err := url.Parse(full)
	if err != nil {
		return "", fmt.Errorf("parsing api url %s: %w", full, err)
	}

	if len(query) > 0 {
		q := u.Query()
		for k, v := range query {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}

	return u.String(), nil
}

// truncate returns s limited to max bytes, with an ellipsis if truncated.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…(truncated)"
}
