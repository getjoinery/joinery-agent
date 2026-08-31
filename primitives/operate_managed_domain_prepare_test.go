package primitives

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// managed_domain_prepare replaces a proc_open(['ssh', ...]) from PHP that
// composed `docker exec -i <container> bash -c 'cd <site dir> && php <utility>
// <domain>'`. Three of those four values were the plane's belief about this
// node. The tests are about the fact that only the fourth crosses now.

func prepareParams(t *testing.T, raw map[string]interface{}) (Params, error) {
	t.Helper()
	p, ok := Lookup("managed_domain_prepare")
	if !ok {
		t.Fatal("managed_domain_prepare should be registered")
	}
	return Validate(p.Params, raw)
}

func TestPreparingADomainTakesTheDomainAndNothingElse(t *testing.T) {
	p, ok := Lookup("managed_domain_prepare")
	if !ok {
		t.Fatal("managed_domain_prepare should be registered")
	}
	if len(p.Params) != 1 || p.Params[0].Name != "domain" {
		t.Fatalf("managed_domain_prepare should take exactly one parameter, the domain; it declares %d", len(p.Params))
	}
	if !p.Params[0].Required {
		t.Error("there is nothing to prepare without a domain")
	}
	if _, err := prepareParams(t, nil); err == nil {
		t.Error("a job with no domain should be refused")
	}
}

func TestTheNodesOwnIdentityIsNotOnTheWire(t *testing.T) {
	// Every value the SSH command carried besides the domain, plus the shapes a
	// future caller would reach for. All of them are things this node knows
	// about itself, and a node told its own name by a remote party is a node
	// whose identity is only as correct as a row somebody else can edit.
	for _, key := range []string{
		"container", // docker exec -i <container>
		"container_name",
		"sitename",    // the site directory the command cd'd into
		"site_name",   //
		"site_dir",    //
		"web_root",    // the same belief, spelled as a path
		"utility",     // which script to run
		"script",      //
		"php",         // which interpreter
		"sudo",        //
		"db_password", // the credential the shell would have scraped
		"pgpassword",  //
		"env",         //
		"extra_args",  //
	} {
		params := map[string]interface{}{"domain": "example.com", key: "anything"}
		if _, err := prepareParams(t, params); err == nil {
			t.Errorf("a job carrying %q must be refused as out-of-vocabulary; the node knows its own %s", key, key)
		}
	}
}

func TestOnlyADomainTheUtilityWouldAcceptIsAccepted(t *testing.T) {
	for _, good := range []string{
		"example.com",
		"a.co",
		"my-site.example.co.uk",
		"xn--80ak6aa92e.com",
	} {
		if _, err := prepareParams(t, map[string]interface{}{"domain": good}); err != nil {
			t.Errorf("domain %q should be accepted: %v", good, err)
		}
	}

	for _, bad := range []string{
		"",                        // no domain at all
		"localhost",               // single label; nothing to prepare mail for
		"198.51.100.7",            // an address, not a name
		"Example.com",             // one name, one spelling — the utility lowercases before it validates
		"example.com; rm -rf /",   // there is no shell, but it is refused before that matters
		"example.com foo",         //
		"example.com\nfoo.com",    // a second name smuggled on a newline
		"../../etc/passwd",        //
		"example.com/../../thing", //
	} {
		if _, err := prepareParams(t, map[string]interface{}{"domain": bad}); err == nil {
			t.Errorf("domain %q should be refused", bad)
		}
	}
}

func TestPreparingADomainIsOperateBecauseItWrites(t *testing.T) {
	// Not a taxonomy quibble. policy.go lets a node accept CLASSES rather than
	// individual primitives, so a node whose policy accepts only observe has to
	// be able to trust that an observe primitive changes nothing. Preparing a
	// domain registers it for receiving and mints a DKIM signing key.
	p, _ := Lookup("managed_domain_prepare")
	if p.Class != ClassOperate {
		t.Errorf("managed_domain_prepare writes state; it is operate, not %q", p.Class)
	}
}

func TestPrepareInvokesTheMailboxUtilityWithTheDomainAlone(t *testing.T) {
	p, _ := Lookup("managed_domain_prepare")

	if p.Script == nil {
		t.Fatal("managed_domain_prepare should be a script primitive")
	}
	if p.Script.ScriptPath != managedDomainPrepareScript {
		t.Errorf("should invoke %q, got %q", managedDomainPrepareScript, p.Script.ScriptPath)
	}
	if p.Script.Interpreter != "/usr/bin/php" {
		t.Errorf("the utility is PHP; interpreter is %q", p.Script.Interpreter)
	}
	if len(p.Script.Args) != 1 || p.Script.Args[0] != "{domain}" {
		t.Errorf("argv should be the domain alone, got %v", p.Script.Args)
	}
	if p.Script.StdinFrom != nil {
		t.Error("the utility reads no stdin; supplying one opens a channel nothing needs")
	}
}

func TestTheUtilityIsVerifiedAgainstTheMailboxPluginsOwnManifest(t *testing.T) {
	// It ships in the mailbox plugin's archive, so the artifact that shipped it
	// is the artifact that must speak for it. Resolving to the site-root
	// manifest would mean being verified by a manifest that never listed it.
	if owner := owningArtifact(managedDomainPrepareScript); owner != "public_html/plugins/mailbox" {
		t.Errorf("the utility resolved to artifact %q; it ships in the mailbox plugin archive", owner)
	}
}

// --- End to end, against a signed tree ---------------------------------------

func runPrepare(t *testing.T, root string, verifier ManifestVerifier, domain string) (map[string]interface{}, error) {
	t.Helper()
	env := &ExecEnv{
		SiteRoot: root,
		WebRoot:  filepath.Join(root, "public_html"),
		Manifest: verifier,
	}
	return Execute(context.Background(), env, ShippedPolicy(), Request{
		JobID:     1,
		Primitive: "managed_domain_prepare",
		Params:    map[string]interface{}{"domain": domain},
	})
}

func TestTheUtilityReceivesTheDomainAsOneArgument(t *testing.T) {
	// Asserted against a real process rather than against the template: the
	// framework prepends the script path, so "one argument" means the utility
	// sees $# of one and $1 is the name.
	root, verifier := signedScriptRoot(t, managedDomainPrepareScript,
		"<?php echo 'argc=', $argc-1, \"\\n\", 'arg1=', ($argv[1] ?? ''), \"\\n\";")

	result, err := runPrepare(t, root, verifier, "example.com")
	if err != nil {
		t.Fatalf("a verified utility should execute: %v", err)
	}
	output := result["output"].(string)
	if !strings.Contains(output, "argc=1") {
		t.Errorf("the utility should receive exactly one argument. Output: %q", output)
	}
	if !strings.Contains(output, "arg1=example.com") {
		t.Errorf("and it should be the domain. Output: %q", output)
	}
}

func TestARefusedPlanComesBackWholeRatherThanAsAFailure(t *testing.T) {
	// The utility exits 0 and prints {"ok":false,...} for a domain it could not
	// prepare, and exits 0 with dkim_ready:false for one that is publishable but
	// not finished. The verdict is the JSON line, so it has to survive intact —
	// the plane parses it, and summarising it here would throw away the only
	// account of what happened.
	root, verifier := signedScriptRoot(t, managedDomainPrepareScript,
		"<?php echo '{\"ok\":false,\"error\":\"the mailbox plugin is not active here\"}', \"\\n\";")

	result, err := runPrepare(t, root, verifier, "example.com")
	if err != nil {
		t.Fatalf("exit 0 is success at this layer; the verdict is in the output: %v", err)
	}
	if got := result["output"].(string); !strings.Contains(got, `"ok":false`) {
		t.Errorf("the JSON verdict must reach the plane unchanged, got %q", got)
	}
}

func TestAModifiedUtilityIsRefusedBeforeItRunsAsRoot(t *testing.T) {
	// The site tree is writable by the web user while the agent is root. This is
	// the assertion that a web-layer compromise does not become root the next
	// time a managed domain reaches its mail step.
	root, verifier := signedScriptRoot(t, managedDomainPrepareScript, "<?php exit(0);")

	full := filepath.Join(root, filepath.FromSlash(managedDomainPrepareScript))
	if err := os.WriteFile(full, []byte("<?php echo 'pwned';"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := runPrepare(t, root, verifier, "example.com"); err == nil {
		t.Fatal("a utility that no longer matches its signed hash must not execute")
	} else if !Refused(err) {
		t.Errorf("a hash mismatch is a refusal, not a run that failed: %v", err)
	}
}
