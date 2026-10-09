package primitives

// The backup a copy from backups is about to take, read by THIS machine from
// its storage provider (specs/storage_targets.md F7, WP9).
//
// copy_take_key asks the owner to open a chain's key, and before this check
// the statement it showed them (the chain, its manifest's hash, its newest
// run) was the management node's word. A management node that has been taken
// over could make a whole chain of its own, sealed to the recovery PUBLIC key,
// and name it: every check would pass and the copy would become its site.
//
// What it cannot do is make a stored object look older than it is. A storage
// provider stamps each object with the moment it arrived (Last-Modified), and
// no request sets or backdates that stamp. So this machine downloads the
// chain's manifest itself, through a link the management node signs, and
// holds it to four things:
//
//   - the bytes hash to the manifest the management node named;
//   - the manifest is that chain's and carries the very key, sealed to the
//     very recovery key, the job asks the owner to open;
//   - its newest run is no later than the moment it was stored;
//   - when the link is at a provider's own storage address, the moment it was
//     stored, which the page shows the owner beside the run. A chain made up
//     after the site's server died shows a date after it died.
//
// The date is believed only from a provider's storage host (storageProviders
// below): there a management node chooses the bucket and the key and nothing
// else. Anywhere else it could run the server that answers, and set any date
// it likes, so the page says the date could not be checked.
//
// A lock on the bucket is not what makes the date true (F8 keeps backups from
// being deleted). It is true on every bucket at these providers.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// storedManifestMaxBytes bounds the download: a chain's manifest names its
// runs and archives, a few kilobytes even for a long chain.
const storedManifestMaxBytes = 4 << 20

// storedManifestSlack is how far a manifest's newest run may be after the
// moment it was stored: the two clocks are different machines'.
const storedManifestSlack = 15 * time.Minute

// storageProviders are the storage addresses whose Last-Modified this machine
// believes: each provider's S3 endpoint in the form this platform's links use
// (StorageProvider's catalogue on the PHP side). Website and CDN hosts serve
// the same objects through machinery a bucket's owner configures, so only the
// API hosts match: each pattern allows the one label layout of its API host,
// which no website or CDN host has.
var storageProviders = []struct {
	label string
	host  *regexp.Regexp
}{
	{"Backblaze B2", regexp.MustCompile(`^s3\.[a-z0-9-]+\.backblazeb2\.com$`)},
	// The bucket as a host label, then s3 and a region: never an access point
	// or Object Lambda host, whose answers the bucket's owner can write.
	{"Amazon S3", regexp.MustCompile(`^([a-z0-9][a-z0-9.-]*\.)?s3([.-][a-z]{2}(-gov)?-[a-z]+-[0-9])?\.amazonaws\.com$`)},
	{"Cloudflare R2", regexp.MustCompile(`^[a-f0-9]+(\.[a-z]+)?\.r2\.cloudflarestorage\.com$`)}, // .eu, .fedramp
	{"Wasabi", regexp.MustCompile(`^s3\.[a-z0-9-]+\.wasabisys\.com$`)},
	{"DigitalOcean Spaces", regexp.MustCompile(`^[a-z0-9-]+\.digitaloceanspaces\.com$`)},
	{"Linode", regexp.MustCompile(`^[a-z0-9-]+\.linodeobjects\.com$`)},
	{"Hetzner", regexp.MustCompile(`^[a-z0-9-]+\.your-objectstorage\.com$`)},
}

// storageProviderOf names the provider whose storage host this is, or "".
// A variable so a test can name its own server.
var storageProviderOf = func(host string) string {
	host = strings.ToLower(host)
	for _, p := range storageProviders {
		if p.host.MatchString(host) {
			return p.label
		}
	}
	return ""
}

// storedManifestClient fetches the manifest. No redirect is followed: the
// signature is for one object at one host, and a redirect is somewhere else.
var storedManifestClient = &http.Client{
	Timeout: 2 * time.Minute,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// StoredManifest is what the copy learned from the manifest it read.
type StoredManifest struct {
	NewestRun  time.Time // the manifest's newest run
	StoredTime time.Time // the provider's Last-Modified; zero when not checked
	StoredAt   string    // the provider's name; "" when the date could not be checked
}

// readStoredManifest downloads the chain's manifest from rawURL and holds it
// to what the job says it is.
func readStoredManifest(ctx context.Context, rawURL, chainID, manifestSHA, sealed, fingerprint string) (StoredManifest, error) {
	var out StoredManifest
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return out, errors.New("the link to the backup's manifest is not an https link")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return out, err
	}
	resp, err := storedManifestClient.Do(req)
	if err != nil {
		return out, fmt.Errorf("the backup's manifest could not be fetched from its storage: %v", redactURLError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return out, errors.New("the backup's storage answered HTTP 403 for its manifest: the link may have expired " +
			"before this job ran; start the copy run again for a fresh one")
	}
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("the backup's storage answered HTTP %d for its manifest", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, storedManifestMaxBytes+1))
	if err != nil {
		return out, fmt.Errorf("the backup's manifest could not be read from its storage: %v", err)
	}
	if len(body) > storedManifestMaxBytes {
		return out, errors.New("the backup's manifest in its storage is larger than any manifest is")
	}

	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != manifestSHA {
		return out, errors.New("the backup's manifest in its storage is not the one the management node named: its hash differs")
	}
	var m struct {
		ChainID  string `json:"chain_id"`
		Envelope struct {
			Recipients []struct {
				Kind        string `json:"kind"`
				Fingerprint string `json:"fingerprint"`
				Sealed      string `json:"sealed"`
			} `json:"recipients"`
		} `json:"envelope"`
		Runs []struct {
			Time string `json:"time"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return out, errors.New("the backup's manifest in its storage is not a manifest")
	}
	if m.ChainID != chainID {
		return out, fmt.Errorf("the manifest in backup storage is chain %q's, not %s's", m.ChainID, chainID)
	}
	matched := false
	for _, r := range m.Envelope.Recipients {
		if r.Kind == "recovery" && r.Fingerprint == fingerprint && r.Sealed == sealed {
			matched = true
		}
	}
	if !matched {
		return out, errors.New("the key the management node asks the owner to open is not the one this backup's manifest seals to the recovery key")
	}
	for _, r := range m.Runs {
		t, err := time.Parse(time.RFC3339, r.Time)
		if err != nil {
			return out, fmt.Errorf("the backup's manifest names a run at %q, which is not a time", r.Time)
		}
		if t.After(out.NewestRun) {
			out.NewestRun = t.UTC()
		}
	}
	if out.NewestRun.IsZero() {
		return out, errors.New("the backup's manifest names no run")
	}

	provider := storageProviderOf(u.Hostname())
	if provider == "" {
		return out, nil
	}
	stored, err := http.ParseTime(resp.Header.Get("Last-Modified"))
	if err != nil {
		return out, fmt.Errorf("%s did not say when the backup's manifest was stored", provider)
	}
	stored = stored.UTC()
	if out.NewestRun.After(stored.Add(storedManifestSlack)) {
		return out, fmt.Errorf("the backup's manifest says its newest run was at %s, but %s stored it at %s: "+
			"a run cannot be recorded before it happens", out.NewestRun.Format(time.RFC3339), provider, stored.Format(time.RFC3339))
	}
	out.StoredTime, out.StoredAt = stored, provider
	return out, nil
}

// redactURLError drops the signed link from a transport error: its query is
// a bearer signature, and the error goes back in the job's result.
func redactURLError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}
