package primitives

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The probe pair is two primitives that write and unlink a file in the webroot
// as root. Almost everything worth asserting is about what they will NOT be
// told to do.

func sslProbeEnv(t *testing.T) (*ExecEnv, string) {
	t.Helper()
	root := t.TempDir()
	web := filepath.Join(root, "public_html")
	if err := os.MkdirAll(web, 0o755); err != nil {
		t.Fatal(err)
	}
	return &ExecEnv{SiteRoot: root, WebRoot: web}, web
}

const goodToken = "sm-ssl-probe-0123456789abcdef01234567"

func placeProbe(t *testing.T, env *ExecEnv, token string) (map[string]interface{}, error) {
	t.Helper()
	return Execute(context.Background(), env, ShippedPolicy(), Request{
		JobID: 1, Primitive: "ssl_probe_place",
		Params: map[string]interface{}{"token": token},
	})
}

func clearProbe(t *testing.T, env *ExecEnv) (map[string]interface{}, error) {
	t.Helper()
	return Execute(context.Background(), env, ShippedPolicy(), Request{
		JobID: 2, Primitive: "ssl_probe_clear",
	})
}

// --- Vocabulary --------------------------------------------------------------

func TestNeitherProbePrimitiveCanBeToldAPath(t *testing.T) {
	// The whole reason these are two tiny primitives instead of one general
	// "write a file" is that neither can name where. A path parameter on place
	// is a root write anywhere; on clear it is a root unlink anywhere.
	for _, name := range []string{"ssl_probe_place", "ssl_probe_clear"} {
		p, ok := Lookup(name)
		if !ok {
			t.Fatalf("%s should be registered", name)
		}
		for _, spec := range p.Params {
			if spec.Name != "token" {
				t.Errorf("%s declares parameter %q — the only value that may cross is the token", name, spec.Name)
			}
		}
		for _, key := range []string{"path", "filename", "file", "dir", "directory", "webroot", "web_root", "domain"} {
			if _, err := Validate(p.Params, map[string]interface{}{key: "/etc/passwd"}); err == nil {
				t.Errorf("%s accepted %q; the location is compiled in and must stay that way", name, key)
			}
		}
	}
}

func TestProbeClearTakesNothingAtAll(t *testing.T) {
	p, _ := Lookup("ssl_probe_clear")
	if len(p.Params) != 0 {
		t.Fatalf("ssl_probe_clear declares %d parameter(s); \"remove the probe token\" has no argument", len(p.Params))
	}
	// Including the token: clearing does not depend on which token is there,
	// and a token parameter would only invite a caller to think it does.
	if _, err := Validate(p.Params, map[string]interface{}{"token": goodToken}); err == nil {
		t.Error("ssl_probe_clear should refuse a token parameter")
	}
	if _, err := Validate(p.Params, nil); err != nil {
		t.Errorf("the empty object is the only well-formed call, and it should validate: %v", err)
	}
}

func TestOnlyAWellShapedTokenIsAccepted(t *testing.T) {
	p, _ := Lookup("ssl_probe_place")

	for _, bad := range []string{
		"",                                        // absent-ish
		"hello",                                   // not a probe token
		"sm-ssl-probe-../../etc/passwd",           // traversal in the value
		"sm-ssl-probe-0123456789abcdef0123456",    // 23 hex, one short
		"sm-ssl-probe-0123456789abcdef012345678",  // 25 hex, one long
		"sm-ssl-probe-0123456789ABCDEF01234567",   // the plane mints lowercase hex
		"sm-ssl-probe-0123456789abcdef01234567 ",  // trailing space
		"sm-ssl-probe-0123456789abcdef01234567\n", // a second line
		"../sm-ssl-probe-0123456789abcdef01234567",
	} {
		if _, err := Validate(p.Params, map[string]interface{}{"token": bad}); err == nil {
			t.Errorf("token %q should be refused", bad)
		}
	}
	if _, err := Validate(p.Params, map[string]interface{}{"token": goodToken}); err != nil {
		t.Errorf("a well-formed token should validate: %v", err)
	}
	if _, err := Validate(p.Params, nil); err == nil {
		t.Error("place needs a token; an empty call should be refused")
	}
}

func TestBothProbePrimitivesAreOperateAndEmbedded(t *testing.T) {
	for _, name := range []string{"ssl_probe_place", "ssl_probe_clear"} {
		p, _ := Lookup(name)
		if p.Class != ClassOperate {
			t.Errorf("%s is operate, not %q", name, p.Class)
		}
		if p.Script != nil {
			t.Errorf("%s should be embedded Go; there is no script on the node that does this", name)
		}
		if p.Run == nil {
			t.Errorf("%s has no implementation", name)
		}
	}
}

// --- Placing -----------------------------------------------------------------

func TestThePlacedTokenIsWhatTheViewWillServe(t *testing.T) {
	// views/sm_ssl_probe.php reads the first 256 bytes, trims, and 404s unless
	// the result matches its own pattern. A token this node writes in a shape
	// that view refuses is a probe that can never pass, and the failure would
	// look like a routing problem.
	env, web := sslProbeEnv(t)

	result, err := placeProbe(t, env, goodToken)
	if err != nil {
		t.Fatalf("placing a probe token: %v", err)
	}
	if result["placed"] != true {
		t.Error("the result should say the token was placed")
	}
	if result["replaced"] != false {
		t.Error("nothing was there; replaced should be false")
	}

	raw, err := os.ReadFile(filepath.Join(web, sslProbeFilename))
	if err != nil {
		t.Fatalf("the token file should exist: %v", err)
	}
	if len(raw) > 256 {
		t.Error("the view reads only the first 256 bytes")
	}
	served := strings.TrimSpace(string(raw))
	if served != goodToken {
		t.Errorf("the view would serve %q, not the token that was asked for", served)
	}
	viewPattern := regexp.MustCompile(`^[A-Za-z0-9._-]{8,128}$`)
	if !viewPattern.MatchString(served) {
		t.Errorf("views/sm_ssl_probe.php would 404 on %q", served)
	}
}

func TestTheTokenIsReadableByTheWebServer(t *testing.T) {
	// Root writes it, a non-root web tier serves it. A private file is a probe
	// that fails as a 404 with nothing anywhere saying why.
	env, web := sslProbeEnv(t)
	if _, err := placeProbe(t, env, goodToken); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(web, sslProbeFilename))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o044 == 0 {
		t.Errorf("the token is mode %04o; the web server cannot read it", info.Mode().Perm())
	}
}

func TestPlacingOverAStaleTokenSucceedsAndSaysSo(t *testing.T) {
	// The decision, asserted. Refusing would look careful and would wedge the
	// domain: a probe that died between place and clear leaves a token behind,
	// and ProvisionPendingSsl retries precisely that path. The token has no
	// secrecy value, so refusing defends nothing.
	//
	// It must not be SILENT, though: the same overwrite is what two concurrent
	// probes against one node look like, and that is a plane-side problem the
	// plane can only act on if the node reports it.
	env, web := sslProbeEnv(t)
	stale := "sm-ssl-probe-ffffffffffffffffffffffff"
	if _, err := placeProbe(t, env, stale); err != nil {
		t.Fatal(err)
	}

	result, err := placeProbe(t, env, goodToken)
	if err != nil {
		t.Fatalf("a stale token must not wedge the next probe: %v", err)
	}
	if result["replaced"] != true {
		t.Error("replacing an existing token has to be visible in the result")
	}

	raw, _ := os.ReadFile(filepath.Join(web, sslProbeFilename))
	if strings.TrimSpace(string(raw)) != goodToken {
		t.Error("the new token should have won")
	}
}

func TestPlaceWillNotWriteThroughASymlink(t *testing.T) {
	// The webroot is writable by the web user while this runs as root, so a
	// symlink at the token's path is how a web-tier compromise aims a root
	// write. Nothing else about this primitive matters if this is wrong.
	env, web := sslProbeEnv(t)

	victim := filepath.Join(t.TempDir(), "important.conf")
	if err := os.WriteFile(victim, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(web, sslProbeFilename)); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}

	if _, err := placeProbe(t, env, goodToken); err == nil {
		t.Fatal("a symlink at the token path must be refused, not written through")
	} else if !Refused(err) {
		t.Errorf("that is a refusal, not an operational failure: %v", err)
	}

	after, _ := os.ReadFile(victim)
	if string(after) != "original\n" {
		t.Fatal("the symlink target was written as root — this is the whole hazard")
	}
}

func TestPlaceLeavesNoDebrisInThePublicWebroot(t *testing.T) {
	// The token is staged and renamed, which is what makes it atomic and
	// symlink-proof. A staging file left behind would sit in a public directory
	// on every probe.
	env, web := sslProbeEnv(t)
	if _, err := placeProbe(t, env, goodToken); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(web)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != sslProbeFilename {
			t.Errorf("the webroot also holds %q after a probe", e.Name())
		}
	}
}

// --- Clearing ----------------------------------------------------------------

func TestClearingRemovesTheToken(t *testing.T) {
	env, web := sslProbeEnv(t)
	if _, err := placeProbe(t, env, goodToken); err != nil {
		t.Fatal(err)
	}

	result, err := clearProbe(t, env)
	if err != nil {
		t.Fatalf("clearing: %v", err)
	}
	if result["cleared"] != true {
		t.Error("the result should say the token was removed")
	}
	if _, err := os.Lstat(filepath.Join(web, sslProbeFilename)); !os.IsNotExist(err) {
		t.Error("the token is still in the webroot")
	}
}

func TestClearingWhenThereIsNothingToClearIsSuccess(t *testing.T) {
	// The same end-state rule delete_backup states: the request names a state —
	// no probe token on this node — and an absent file satisfies it. The plane
	// calls this in a finally, and a finally that fails for having nothing to do
	// masks the error it was meant to clean up after.
	env, _ := sslProbeEnv(t)

	result, err := clearProbe(t, env)
	if err != nil {
		t.Fatalf("clearing nothing is not a failure: %v", err)
	}
	if result["cleared"] != false {
		t.Error("nothing was removed, and the result should say so rather than claim a deletion")
	}

	// And twice in a row, which is what a retried job does.
	if _, err := clearProbe(t, env); err != nil {
		t.Fatalf("clearing twice is not a failure: %v", err)
	}
}

func TestClearWillNotUnlinkSomethingThatIsNotAToken(t *testing.T) {
	// A symlink or a directory at that path means the token is not there and
	// something else is. Unlinking the link would report success while removing
	// the evidence.
	env, web := sslProbeEnv(t)

	victim := filepath.Join(t.TempDir(), "important.conf")
	if err := os.WriteFile(victim, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(web, sslProbeFilename)
	if err := os.Symlink(victim, link); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}

	if _, err := clearProbe(t, env); err == nil {
		t.Fatal("a symlink at the token path must be refused")
	} else if !Refused(err) {
		t.Errorf("that is a refusal: %v", err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Error("the symlink was removed anyway")
	}

	// A directory, likewise.
	os.Remove(link)
	if err := os.Mkdir(link, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := clearProbe(t, env); err == nil {
		t.Fatal("a directory at the token path must be refused")
	}
}

// --- Environment -------------------------------------------------------------

func TestNeitherPrimitiveGuessesAtAWebroot(t *testing.T) {
	// A node that does not know its own webroot cannot serve a probe either, so
	// there is no directory worth guessing at while running as root.
	env := &ExecEnv{SiteRoot: t.TempDir()}

	if _, err := placeProbe(t, env, goodToken); err == nil {
		t.Error("place should refuse without a webroot")
	} else if !Refused(err) {
		t.Errorf("that is a refusal: %v", err)
	}
	if _, err := clearProbe(t, env); err == nil {
		t.Error("clear should refuse without a webroot")
	}
}

func TestAProbeRoundTripLeavesTheWebrootAsItFoundIt(t *testing.T) {
	// place, the plane's fetch, clear. The node's half has to be a no-trace
	// operation: a token left in a public webroot outlives the moment it proved
	// anything.
	env, web := sslProbeEnv(t)

	before, err := os.ReadDir(web)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := placeProbe(t, env, goodToken); err != nil {
		t.Fatal(err)
	}
	if _, err := clearProbe(t, env); err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadDir(web)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("the webroot holds %d entries after a round trip, %d before", len(after), len(before))
	}
}
