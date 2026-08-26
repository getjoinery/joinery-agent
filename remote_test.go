package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"joinery-agent/primitives"
)

func testIdentity(t *testing.T, planeURL string, nodeID int64) *NodeIdentity {
	t.Helper()
	pub, priv, err := GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	id := &NodeIdentity{PlaneURL: planeURL, NodeID: nodeID, NodeSlug: "test", PublicKey: pub, PrivateKey: priv}
	raw, _ := base64.StdEncoding.DecodeString(priv)
	id.private = ed25519.PrivateKey(raw)
	return id
}

func testSource(t *testing.T, id *NodeIdentity) *RemoteSource {
	t.Helper()
	return NewRemoteSource(id,
		&primitives.Policy{Accept: []primitives.Class{primitives.ClassObserve, primitives.ClassOperate}},
		&primitives.ExecEnv{SiteRoot: t.TempDir(), WebRoot: t.TempDir(), Manifest: primitives.UnavailableVerifier{}},
		&sync.Mutex{})
}

// The plane-supplied poll interval is a number from the wire like any other.
// A hostile plane must not be able to set 0 (a hot loop against its own
// endpoint) or an hour (a channel that is dead but looks configured).
// A freshly paired identity must be able to sign immediately. It could not:
// Pair() filled the stored base64 private key but never decoded it into the
// signing key, so the very first claim after pairing panicked on a zero-length
// key. Every test until this one built its identity by hand and hydrated it as
// a side effect, which is exactly how a gap like this survives a green suite.
func TestFreshlyPairedIdentityCanSignImmediately(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte(`{"api_version":"1.0","data":{"node_id":42,"node_slug":"fresh","poll_interval":15}}`))
	}))
	defer server.Close()

	id, err := Pair(context.Background(), server.URL, "a-token", false, "0.0.0-test", "host")
	if err != nil {
		t.Fatalf("pairing: %v", err)
	}
	if id.NodeID != 42 {
		t.Fatalf("paired as node %d, want 42", id.NodeID)
	}

	signature := id.Sign("POST", pathClaim, "1756180000", "n", "h")
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := base64.StdEncoding.DecodeString(id.PublicKey)
	message := SigningMessage("POST", pathClaim, 42, "1756180000", "n", "h")
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(message), sig) {
		t.Fatal("a freshly paired identity produced a signature its own public half does not verify")
	}
}

// The clamp only protects anything if the plane's value actually reaches it.
// It did not: Pair() parsed poll_interval and discarded it, so every agent ran
// the compiled default and the clamp guarded a number that never arrived.
func TestPlaneSuppliedPollIntervalIsCarriedAndClamped(t *testing.T) {
	cases := []struct {
		supplied int
		want     time.Duration
	}{
		{30, 30 * time.Second},
		{0, defaultPollInterval}, // unset by the plane — the compiled default
		{1, minPollInterval},     // hostile: a hot loop
		{86400, maxPollInterval}, // hostile: a channel that is dead but looks configured
	}
	for _, c := range cases {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Write([]byte(`{"api_version":"1.0","data":{"node_id":1,"node_slug":"n","poll_interval":` +
				strconv.Itoa(c.supplied) + `}}`))
		}))
		id, err := Pair(context.Background(), server.URL, "t", false, "v", "h")
		server.Close()
		if err != nil {
			t.Fatalf("pairing with poll_interval %d: %v", c.supplied, err)
		}
		if id.PollSeconds != c.supplied {
			t.Errorf("identity kept poll_seconds %d, want %d", id.PollSeconds, c.supplied)
		}
		src := NewRemoteSource(id, ShippedTestPolicy(), &primitives.ExecEnv{}, &sync.Mutex{})
		if src.pollInterval != c.want {
			t.Errorf("poll_interval %d became %s, want %s", c.supplied, src.pollInterval, c.want)
		}
	}
}

// ShippedTestPolicy is the fleet-uniform policy, for transport tests that do
// not care which classes are accepted.
func ShippedTestPolicy() *primitives.Policy { return primitives.ShippedPolicy() }

func TestPollIntervalIsClampedToACompiledRange(t *testing.T) {
	cases := []struct {
		supplied int
		want     time.Duration
	}{
		{0, minPollInterval},
		{-1, minPollInterval},
		{1, minPollInterval},
		{30, 30 * time.Second},
		{99999, maxPollInterval},
	}
	for _, c := range cases {
		if got := clampPollInterval(c.supplied); got != c.want {
			t.Errorf("clampPollInterval(%d) = %s, want %s", c.supplied, got, c.want)
		}
	}
}

// The two caps exist for opposite reasons and must not be collapsed into one.
// The inbound (plane→agent) cap is deliberately the smaller: a job is a name
// and a few parameters, while a result carries collected output.
func TestTheTwoCapsAreDistinctAndOrdered(t *testing.T) {
	if agentMaxJobBody >= agentMaxLogBytes {
		t.Fatalf("the plane→agent job cap (%d) must stay below the agent's own log budget (%d); "+
			"one constant serving both is the bug this pattern exists to prevent",
			agentMaxJobBody, agentMaxLogBytes)
	}
}

// Reading exactly the cap is ambiguous — a whole answer of that length looks
// identical to the front of a longer one — so a truncated response would reach
// the JSON parser and be reported as "the plane sent nonsense".
func TestOversizedPlaneResponseIsRefusedAsOversizedNotAsGarbage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte(`{"api_version":"1.0","data":{"pad":"` + strings.Repeat("x", agentMaxJobBody) + `"}}`))
	}))
	defer server.Close()

	src := testSource(t, testIdentity(t, server.URL, 7))
	_, err := src.signedPost(context.Background(), pathClaim, []byte("{}"))
	if err == nil {
		t.Fatal("an oversized plane response must be refused")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("the refusal must name the size limit, not a parse failure; got %q", err)
	}
}

// A response exactly at the cap is a whole answer and must be accepted — the
// one-byte-past read is what makes that distinguishable.
func TestResponseExactlyAtTheCapIsAccepted(t *testing.T) {
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write(body)
	}))
	defer server.Close()

	prefix := `{"api_version":"1.0","data":{"job":null,"pad":"`
	suffix := `"}}`
	body = []byte(prefix + strings.Repeat("x", agentMaxJobBody-len(prefix)-len(suffix)) + suffix)
	if len(body) != agentMaxJobBody {
		t.Fatalf("test built a %d-byte body, wanted exactly %d", len(body), agentMaxJobBody)
	}

	src := testSource(t, testIdentity(t, server.URL, 7))
	if _, err := src.signedPost(context.Background(), pathClaim, []byte("{}")); err != nil {
		t.Fatalf("a response exactly at the cap is whole and must be accepted: %v", err)
	}
}

// The signed message is a fixed field list. Two different requests must not be
// able to produce the same bytes to sign, and the shape must not drift silently.
func TestSigningMessageIsAFixedFieldList(t *testing.T) {
	got := SigningMessage("post", "/api/v1/agent/claim", 42, "1756180000", "nonce==", "abc123")
	want := "joinery-agent-v1\nPOST\n/api/v1/agent/claim\n42\n1756180000\nnonce==\nabc123"
	if got != want {
		t.Errorf("signing message drifted:\n got %q\nwant %q", got, want)
	}

	// Different node, same everything else — must differ.
	other := SigningMessage("post", "/api/v1/agent/claim", 43, "1756180000", "nonce==", "abc123")
	if got == other {
		t.Error("the node id must be part of what is signed")
	}
}

func TestSignatureVerifiesWithTheSharedPublicHalfOnly(t *testing.T) {
	id := testIdentity(t, "https://plane.example", 9)
	message := SigningMessage("POST", pathClaim, 9, "1756180000", "n", "h")
	sig, err := base64.StdEncoding.DecodeString(id.Sign("POST", pathClaim, "1756180000", "n", "h"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := base64.StdEncoding.DecodeString(id.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(message), sig) {
		t.Fatal("the public half the plane stores must verify what the node signs")
	}
	if ed25519.Verify(ed25519.PublicKey(pub), []byte(message+"x"), sig) {
		t.Fatal("a modified message must not verify")
	}
}

// The plane routes; the node checks. A job addressed to another node is refused
// and reported, whatever the plane's routing believed.
func TestJobAddressedToAnotherNodeIsRefused(t *testing.T) {
	var posted map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case pathClaim:
			w.Write([]byte(`{"api_version":"1.0","data":{"job":{"job_id":5,"node_id":999,"primitive":"check_status"}}}`))
		case pathResult:
			json.NewDecoder(req.Body).Decode(&posted)
			w.Write([]byte(`{"api_version":"1.0","data":{}}`))
		}
	}))
	defer server.Close()

	src := testSource(t, testIdentity(t, server.URL, 7))
	job, err := src.claim(context.Background())
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if job != nil {
		t.Fatal("a job addressed to another node must not be returned for execution")
	}
	if posted["status"] != "refused" {
		t.Fatalf("the refusal must be reported back, got %+v", posted)
	}
	if reason, _ := posted["refusal_reason"].(string); !strings.Contains(reason, "999") {
		t.Errorf("the recorded reason must name the mismatch; got %q", reason)
	}
}

func TestClaimSendsTheSignedHeaders(t *testing.T) {
	var headers http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		headers = req.Header.Clone()
		w.Write([]byte(`{"api_version":"1.0","data":{"job":null}}`))
	}))
	defer server.Close()

	src := testSource(t, testIdentity(t, server.URL, 7))
	if _, err := src.claim(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"X-Joinery-Agent-Node", "X-Joinery-Agent-Timestamp", "X-Joinery-Agent-Nonce", "X-Joinery-Agent-Signature"} {
		if headers.Get(h) == "" {
			t.Errorf("claim did not send %s", h)
		}
	}
	if headers.Get("X-Joinery-Agent-Node") != "7" {
		t.Errorf("node header = %q, want 7", headers.Get("X-Joinery-Agent-Node"))
	}
	if ts, err := strconv.ParseInt(headers.Get("X-Joinery-Agent-Timestamp"), 10, 64); err != nil || time.Since(time.Unix(ts, 0)) > time.Minute {
		t.Errorf("timestamp header is not a fresh unix time: %q", headers.Get("X-Joinery-Agent-Timestamp"))
	}
}

// A refused primitive is reported as a decision, with its reason, not as a
// silent nothing and not as a failure.
func TestRefusedPrimitiveIsPostedWithItsReason(t *testing.T) {
	var posted map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		json.NewDecoder(req.Body).Decode(&posted)
		w.Write([]byte(`{"api_version":"1.0","data":{}}`))
	}))
	defer server.Close()

	src := testSource(t, testIdentity(t, server.URL, 7))
	src.runJob(context.Background(), &RemoteJob{JobID: 11, NodeID: 7, Primitive: "definitely_not_a_primitive"})

	if posted["status"] != "refused" {
		t.Fatalf("status = %v, want refused", posted["status"])
	}
	if reason, _ := posted["refusal_reason"].(string); reason == "" {
		t.Error("a refusal must carry a recorded reason")
	}
}

// A result the plane would refuse for size must still REPORT its outcome. A
// result that never arrives leaves the job claimed until it times out, and a
// timeout says nothing about what happened.
func TestOversizedResultShedsPayloadButStillReportsTheOutcome(t *testing.T) {
	var posted map[string]interface{}
	var bodyLen int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		raw, _ := io.ReadAll(req.Body)
		bodyLen = len(raw)
		json.Unmarshal(raw, &posted)
		w.Write([]byte(`{"api_version":"1.0","data":{}}`))
	}))
	defer server.Close()

	src := testSource(t, testIdentity(t, server.URL, 7))
	huge := map[string]interface{}{"output": strings.Repeat("q", agentMaxResultBody)}
	src.postResult(context.Background(), 99, "completed", huge, strings.Repeat("L", agentMaxLogBytes), "")

	if bodyLen > agentMaxResultBody {
		t.Errorf("posted %d bytes, over the %d-byte limit the plane enforces", bodyLen, agentMaxResultBody)
	}
	if posted["status"] != "completed" {
		t.Fatalf("the outcome must survive the shedding, got %v", posted["status"])
	}
	if _, kept := posted["data"]; kept {
		t.Error("the oversized data should have been shed")
	}
	if posted["log"] != "" {
		t.Error("the log should have been shed first")
	}
}

// The script output ceiling has to leave room for everything else in a result.
func TestScriptOutputCeilingFitsInsideAResult(t *testing.T) {
	if primitives.MaxScriptOutputBytes+agentMaxLogBytes >= agentMaxResultBody {
		t.Fatalf("a script at its %d-byte ceiling plus a log at its %d-byte ceiling does not fit "+
			"under the %d-byte result cap — a chatty script's result would be refused and lost",
			primitives.MaxScriptOutputBytes, agentMaxLogBytes, agentMaxResultBody)
	}
}

func TestLogIsCappedAndReportsItsRealTotal(t *testing.T) {
	kept, total := capLog(strings.Repeat("z", agentMaxLogBytes+500))
	if len(kept) != agentMaxLogBytes {
		t.Errorf("kept %d bytes, want the cap %d", len(kept), agentMaxLogBytes)
	}
	if total != agentMaxLogBytes+500 {
		t.Errorf("total = %d — the REAL total must be reported, not the length of what survived", total)
	}
}

// The private key is the node's whole identity. A file anything but its owner
// can read is not a credential store.
func TestIdentityFileWithLoosePermissionsIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node_identity.json")
	pub, priv, _ := GenerateIdentityKeys()
	body, _ := json.Marshal(NodeIdentity{PlaneURL: "https://p", NodeID: 1, PublicKey: pub, PrivateKey: priv})
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(path); err == nil {
		t.Fatal("a world-readable identity file must be refused, not loaded")
	} else if !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("the error should say how to fix it; got %q", err)
	}
}

func TestAbsentIdentityIsNotAnError(t *testing.T) {
	id, err := LoadIdentity(filepath.Join(t.TempDir(), "nothing.json"))
	if err != nil || id != nil {
		t.Fatalf("a control-plane-only agent has no identity and that is normal; got (%v, %v)", id, err)
	}
}

func TestIdentityRoundTripsAt0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node_identity.json")
	original := testIdentity(t, "https://plane.example", 12)
	if err := original.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("identity file mode is %04o, want 0600", info.Mode().Perm())
	}
	loaded, err := LoadIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.NodeID != 12 || loaded.PublicKey != original.PublicKey {
		t.Errorf("identity did not survive the round trip: %+v", loaded)
	}
	if loaded.Sign("POST", pathClaim, "1", "n", "h") != original.Sign("POST", pathClaim, "1", "n", "h") {
		t.Error("the loaded private key does not produce the same signature")
	}
}

// A spent pairing token must not be left lying in a group-readable env file.
func TestSpentPairingTokenIsStrippedFromTheEnvFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "joinery-agent.env")
	body := "JOINERY_CONFIG=/var/www/site/config/Globalvars_site.php\n" +
		"JOINERY_PAIRING_TOKEN=abc123\n" +
		"JOINERY_PLANE_URL=https://plane.example\n"
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	stripPairingTokenFromEnvFile(path)

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), "JOINERY_PAIRING_TOKEN") {
		t.Error("the spent token is still in the env file")
	}
	for _, keep := range []string{"JOINERY_CONFIG=", "JOINERY_PLANE_URL="} {
		if !strings.Contains(string(after), keep) {
			t.Errorf("stripping the token removed %s as well", keep)
		}
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o640 {
		t.Errorf("env file mode changed to %04o", info.Mode().Perm())
	}
}
