package primitives

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// The copy's read of a backup at a real provider (specs/storage_targets.md
// F7). Runs only when JOINERY_LIVE_MANIFESTS names a file listing real chain
// manifests, each with a link signed for it, as the management node signs one
// for copy_take_key: [{provider, url, chain_id, sha, sealed, fingerprint}].
// Nothing is written.
func TestReadStoredManifestLive(t *testing.T) {
	path := os.Getenv("JOINERY_LIVE_MANIFESTS")
	if path == "" {
		t.Skip("JOINERY_LIVE_MANIFESTS is not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Provider    string `json:"provider"`
		URL         string `json:"url"`
		ChainID     string `json:"chain_id"`
		Sha         string `json:"sha"`
		Sealed      string `json:"sealed"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil || len(cases) == 0 {
		t.Fatalf("no manifests in %s: %v", path, err)
	}
	for _, c := range cases {
		got, err := readStoredManifest(context.Background(), c.URL, c.ChainID, c.Sha, c.Sealed, c.Fingerprint)
		if err != nil {
			t.Errorf("%s: %v", c.Provider, err)
			continue
		}
		if got.StoredAt == "" || got.StoredTime.IsZero() || got.StoredTime.After(time.Now().Add(time.Minute)) {
			t.Errorf("%s: stored %v at %q; want the provider's date", c.Provider, got.StoredTime, got.StoredAt)
		}
		if got.NewestRun.After(got.StoredTime.Add(storedManifestSlack)) {
			t.Errorf("%s: newest run %v after it was stored %v", c.Provider, got.NewestRun, got.StoredTime)
		}
		t.Logf("%s: chain %s, newest run %s, stored %s by %s", c.Provider, c.ChainID,
			got.NewestRun.Format(time.RFC3339), got.StoredTime.Format(time.RFC3339), got.StoredAt)
		other := c.Sha[:63] + "0"
		if other == c.Sha {
			other = c.Sha[:63] + "1"
		}
		if _, err := readStoredManifest(context.Background(), c.URL, c.ChainID, other, c.Sealed, c.Fingerprint); err == nil {
			t.Errorf("%s: a manifest whose hash differs from the one named was taken", c.Provider)
		}
	}
}
