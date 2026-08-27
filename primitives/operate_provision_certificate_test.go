package primitives

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// provision_certificate spends something when it is wrong: Let's Encrypt allows
// five failed validations per hostname per hour and five certificates per domain
// per week. So the tests are mostly about what never reaches certbot.

func certParams(t *testing.T, raw map[string]interface{}) (Params, error) {
	t.Helper()
	p, ok := Lookup("provision_certificate")
	if !ok {
		t.Fatal("provision_certificate should be registered")
	}
	return Validate(p.Params, raw)
}

func TestACertificateIsForANameAndNothingElse(t *testing.T) {
	p, _ := Lookup("provision_certificate")

	if len(p.Params) != 1 || p.Params[0].Name != "domain" {
		t.Fatalf("provision_certificate should take exactly one parameter, the domain; it declares %d", len(p.Params))
	}
	if !p.Params[0].Required {
		t.Error("there is no certificate to issue without a domain")
	}
	if _, err := certParams(t, nil); err == nil {
		t.Error("a job with no domain should be refused")
	}
}

func TestTheCertbotSurfaceIsNotReachableFromTheWire(t *testing.T) {
	// Everything the SSH steps composed, plus the flags someone would reach for
	// next. The script decides all of it from the node; none of it is the
	// plane's to send.
	for _, key := range []string{
		"admin_email", // the SSH job's -m; see the delta note
		"email",       //
		"sitename",    // the proto-patch path fragment, which is not migrated
		"web_root",    //
		"webroot",     // --webroot, a different challenge path
		"challenge",   //
		"server",      // --server, i.e. point this node at another CA
		"staging",     //
		"config_dir",  // --config-dir, i.e. write /etc/letsencrypt elsewhere
		"key_type",    //
		"extra_args",  //
		"cert_path",   //
		"force_renewal",
	} {
		params := map[string]interface{}{"domain": "dev.getjoinery.com", key: "anything"}
		if _, err := certParams(t, params); err == nil {
			t.Errorf("a job carrying %q must be refused as out-of-vocabulary", key)
		}
	}
}

func TestOnlyANameACACouldCertifyIsAccepted(t *testing.T) {
	for _, good := range []string{
		"dev.getjoinery.com",
		"a.co",
		"my-site.example.co.uk",
		"xn--80ak6aa92e.com",
		// An internationalised TLD. Punycode, so it carries digits; a plain
		// alphabetic TLD rule would refuse a node its certificate here.
		"example.xn--p1ai",
		"xn--80ak6aa92e.xn--p1ai",
	} {
		if _, err := certParams(t, map[string]interface{}{"domain": good}); err != nil {
			t.Errorf("domain %q should be accepted: %v", good, err)
		}
	}

	for _, bad := range []string{
		"",                    // nothing
		"localhost",           // single label; nowhere to validate from
		"1.2.3.4",             // an IP address has no certificate to issue
		"192.168.0.1",         //
		"::1",                 //
		"*.example.com",       // HTTP-01 cannot satisfy a wildcard
		"-bad.example.com",    // label may not start with a hyphen
		"bad-.example.com",    // nor end with one
		"exam ple.com",        // a space
		"example.com;whoami",  // shell metacharacters, which argv would pass through literally anyway
		"../example.com",      // traversal
		"example.com/../etc",  // a path, not a name
		"example.",            // trailing dot with no TLD
		".example.com",        // empty leading label
		"example.c0m",         // a digit in a non-punycode TLD
		"example.4",           // a numeric last label is how a bare IP gets in
		"example.xn--",        // the punycode prefix with nothing after it
		"example.com\nsecond", // a second line
	} {
		if _, err := certParams(t, map[string]interface{}{"domain": bad}); err == nil {
			t.Errorf("domain %q should be refused before it can spend a validation attempt", bad)
		}
	}
}

func TestProvisionCertificateInvokesTheShippedSslCommand(t *testing.T) {
	p, _ := Lookup("provision_certificate")

	if p.Class != ClassOperate {
		t.Errorf("provision_certificate is operate, not %q", p.Class)
	}
	if p.Script == nil {
		t.Fatal("it should invoke the platform's own script rather than composing a certbot argv")
	}
	if p.Script.ScriptPath != provisionCertificateScript {
		t.Errorf("should invoke %q, got %q", provisionCertificateScript, p.Script.ScriptPath)
	}
	if p.Script.Interpreter != "/bin/bash" {
		t.Errorf("interpreter is %q", p.Script.Interpreter)
	}
	if len(p.Script.Args) != 1 || p.Script.Args[0] != "{domain}" {
		t.Errorf("argv should be exactly the domain, got %v", p.Script.Args)
	}
	if p.Script.StdinFrom != nil {
		t.Error("setup_ssl.sh reads no stdin")
	}
	if owner := owningArtifact(provisionCertificateScript); owner != "" {
		t.Errorf("the ssl command resolved to artifact %q; it ships in the core archive", owner)
	}
}

func TestCertbotIsGivenLongerThanAFileWrite(t *testing.T) {
	// The SSH steps budgeted 120s for the apt install and 300s for certbot, and
	// this script can also install a DNS plugin and make a second attempt. The
	// default would kill the slow path halfway through an issuance.
	p, _ := Lookup("provision_certificate")
	if p.Timeout <= DefaultTimeout {
		t.Errorf("provision_certificate has the %v default; certbot's slow path outlives it", p.Timeout)
	}
	if p.Timeout > MaxTimeout {
		t.Errorf("timeout %v is over the ceiling", p.Timeout)
	}
}

// --- End to end, against a signed tree ---------------------------------------

// signedScriptRoot builds a temp site root holding one script at rel, with a
// manifest signed by a throwaway key.
func signedScriptRoot(t *testing.T, rel, body string) (string, ManifestVerifier) {
	t.Helper()

	root := t.TempDir()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256([]byte(body))
	manifest := []byte(hex.EncodeToString(sum[:]) + "  " + rel + "\n")

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewSignedTreeVerifier(root, manifest, ed25519.Sign(priv, manifest), pub)
	if err != nil {
		t.Fatal(err)
	}
	return root, verifier
}

func provisionCert(t *testing.T, root string, verifier ManifestVerifier, domain string) (map[string]interface{}, error) {
	t.Helper()
	env := &ExecEnv{
		SiteRoot: root,
		WebRoot:  filepath.Join(root, "public_html"),
		Manifest: verifier,
	}
	return Execute(context.Background(), env, ShippedPolicy(), Request{
		JobID: 1, Primitive: "provision_certificate",
		Params: map[string]interface{}{"domain": domain},
	})
}

func TestTheDomainReachesTheScriptAsOneUnalteredArgument(t *testing.T) {
	// Argv is handed to the kernel as a list, so there is nothing to re-parse
	// it. Asserted against a real process rather than the template, and the
	// count matters as much as the value: a second argument would mean the
	// framework had grown a way to append one.
	root, verifier := signedScriptRoot(t, provisionCertificateScript,
		"#!/bin/bash\necho \"argc=$#\"\necho \"domain=$1\"\n")

	result, err := provisionCert(t, root, verifier, "my-site.example.co.uk")
	if err != nil {
		t.Fatalf("a verified script should run: %v", err)
	}
	output := result["output"].(string)
	if !strings.Contains(output, "argc=1") {
		t.Errorf("the script should get exactly one argument. Output: %q", output)
	}
	if !strings.Contains(output, "domain=my-site.example.co.uk") {
		t.Errorf("the domain arrived altered. Output: %q", output)
	}
}

func TestANoCertificateOutcomeStillExitsZeroAndSaysSo(t *testing.T) {
	// provision_origin_cert returns 0 on every branch by design, so an install
	// without a challenge path leaves the site on HTTP rather than failing. The
	// consequence for this primitive is that the exit code cannot be read as
	// "issued", and the output is the only place the truth is written.
	root, verifier := signedScriptRoot(t, provisionCertificateScript,
		"#!/bin/bash\necho \"No origin cert issued for $1 (no LE challenge path available).\"\nexit 0\n")

	result, err := provisionCert(t, root, verifier, "dev.getjoinery.com")
	if err != nil {
		t.Fatalf("exit 0 is what this script does when it issues nothing: %v", err)
	}
	if !strings.Contains(result["output"].(string), "No origin cert issued") {
		t.Error("the only signal that nothing was issued is missing from the result")
	}
}

func TestABrokenApacheConfigSurfacesAsAFailure(t *testing.T) {
	// The one thing setup_ssl.sh does exit non-zero for. It must not cost the
	// output, which says what to look at.
	root, verifier := signedScriptRoot(t, provisionCertificateScript,
		"#!/bin/bash\necho 'WARNING: apache2ctl configtest failed' >&2\nexit 1\n")

	result, err := provisionCert(t, root, verifier, "dev.getjoinery.com")
	if err == nil {
		t.Fatal("a non-zero exit should surface as a failure")
	}
	if Refused(err) {
		t.Error("a script that ran and failed is a failure, not a node refusal")
	}
	if result == nil || !strings.Contains(result["output"].(string), "configtest failed") {
		t.Error("the output must come back with the failure")
	}
}

func TestAModifiedSslCommandIsRefusedBeforeItRunsAsRoot(t *testing.T) {
	// This one runs as root and reaches the network and /etc. If the manifest
	// gate is wrong here, nothing else about the primitive matters.
	root, verifier := signedScriptRoot(t, provisionCertificateScript, "#!/bin/bash\nexit 0\n")

	full := filepath.Join(root, filepath.FromSlash(provisionCertificateScript))
	if err := os.WriteFile(full, []byte("#!/bin/bash\necho pwned\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := provisionCert(t, root, verifier, "dev.getjoinery.com"); err == nil {
		t.Fatal("a script that no longer matches its signed hash must not execute")
	} else if !Refused(err) {
		t.Errorf("a hash mismatch is a refusal, not a run that failed: %v", err)
	}
}
