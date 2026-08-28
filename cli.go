package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

// The command-line front door, for machines that have no other one.
//
// A Joinery node enrolls through its own admin page: an operator names a
// management node, the web tier writes a settings row, and JoinWatcher notices
// it. A relay or a Docker host has no site, no web tier and no settings table,
// so that route does not exist for them (spec A13). This is the same ceremony
// reached a different way.
//
// IT IS THE SAME CEREMONY, and that matters more than the convenience. The
// keypair is generated here, on this machine, and the private half never
// leaves it. What the plane receives is a public key, and what approves the
// join is a HUMAN COMPARING FINGERPRINTS across two screens — the safety-number
// pattern A6 chose. Nothing here shares a secret, and nothing here can approve
// itself. A CLI that auto-approved, or that took a token, would be a second and
// weaker front door; this is the same door.
//
// Every command exits non-zero on failure and prints one line a human can act
// on. These are run by a person at a keyboard on a machine they are standing
// up, not by a script.

// howLongToWaitForApproval bounds `join`. A human has to walk to another screen
// and compare sixteen hex characters; a couple of minutes of waiting is
// friendlier than an immediate "pending" that leaves them wondering what to run
// next. It gives up politely rather than blocking a terminal for ever — the ask
// stays live on the plane either way, and `status` picks the story back up.
const howLongToWaitForApproval = 5 * time.Minute

// approvalPollInterval is how often the wait re-asks. The plane's own join
// status endpoint is cheap, and a human watching a terminal wants the answer
// promptly once they click.
const approvalPollInterval = 5 * time.Second

// runCLI handles a subcommand and reports whether it did. When it returns
// false, main() carries on and starts the agent as a service.
func runCLI(args []string) (handled bool, exit int) {
	if len(args) < 2 {
		return false, 0
	}

	switch args[1] {
	case "--version":
		fmt.Printf("joinery-agent %s\n", version)
		return true, 0
	case "join":
		return true, cliJoin(args[2:])
	case "status":
		return true, cliStatus()
	case "leave":
		return true, cliLeave()
	case "enable":
		return true, cliSwitch(true)
	case "disable":
		return true, cliSwitch(false)
	case "help", "--help", "-h":
		cliUsage(os.Stdout)
		return true, 0
	}
	return false, 0
}

func cliUsage(w *os.File) {
	fmt.Fprintf(w, `joinery-agent %s

  joinery-agent join --management-node=URL   ask a management node to adopt this machine
  joinery-agent status                       what this machine is connected to, and its key fingerprint
  joinery-agent leave                        disconnect from the management node and delete the credential
  joinery-agent enable | disable             turn the agent on or off on this machine
  joinery-agent --version

Joining prints a key fingerprint. Approve the request on the management node
only when the fingerprint shown there is character-for-character the one shown
here — that comparison is what binds this machine to that plane, and nothing
else does.
`, version)
}

// cliError prints one actionable line to stderr and returns the exit code.
func cliError(format string, args ...interface{}) int {
	fmt.Fprintf(os.Stderr, "joinery-agent: "+format+"\n", args...)
	return 1
}

func cliJoin(args []string) int {
	planeURL := ""
	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "--management-node="):
			planeURL = strings.TrimSuffix(strings.TrimPrefix(arg, "--management-node="), "/")
		default:
			return cliError("unrecognised argument %q; see `joinery-agent help`", arg)
		}
	}
	if planeURL == "" {
		return cliError("join needs a management node: joinery-agent join --management-node=https://plane.example.com")
	}
	if !strings.HasPrefix(planeURL, "https://") && !strings.HasPrefix(planeURL, "http://") {
		return cliError("the management node must be a full URL including the scheme, e.g. https://%s", planeURL)
	}

	if existing, err := LoadIdentity(IdentityPath()); err == nil && existing != nil {
		return cliError("this machine is already connected to %s as node #%d (%s).\n"+
			"  Run `joinery-agent leave` first if you mean to move it.",
			existing.PlaneURL, existing.NodeID, existing.NodeSlug)
	}

	cfg := cliConfig()
	watcher := &JoinWatcher{cfg: cfg, agentVersion: version}

	// A staged keypair belongs to one ask. Asking a different plane discards it
	// rather than presenting the same key twice — the node-side half of "a
	// rejected key is never re-presented".
	staged := loadStagedIdentity()
	if staged != nil && staged.PlaneURL != planeURL {
		discardStagedIdentity()
		staged = nil
	}
	if staged == nil {
		pub, priv, err := GenerateIdentityKeys()
		if err != nil {
			return cliError("could not generate a keypair: %v", err)
		}
		staged = &stagedIdentity{
			PlaneURL:      planeURL,
			PublicKey:     pub,
			PrivateKey:    priv,
			RequestedTime: time.Now().UTC().Format(time.RFC3339),
		}
		if err := staged.save(); err != nil {
			return cliError("could not store the staged keypair at %s: %v", stagedIdentityPath(), err)
		}
	}

	fingerprint, err := stagedFingerprint(staged)
	if err != nil {
		discardStagedIdentity()
		return cliError("the staged keypair is unusable and has been discarded; run join again: %v", err)
	}

	hostname, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(context.Background(), howLongToWaitForApproval+time.Minute)
	defer cancel()

	status, err := watcher.callJoin(ctx, planeURL, staged, hostname, true)
	if err != nil {
		return cliError("%v", err)
	}

	fmt.Printf("Asked %s to adopt this machine as %q.\n\n", planeURL, hostname)
	fmt.Printf("    Key fingerprint:  %s\n\n", fingerprint)
	fmt.Printf("Approve the request on the management node, and only if the fingerprint\n")
	fmt.Printf("shown there is exactly the one above.\n\n")

	// A plane that has already made up its mind says so on the first response —
	// most often when a previous ask from this machine was rejected and the key
	// is still remembered. Falling through to the wait loop would report that
	// five seconds later, which reads as a hang and then a surprise.
	switch status.Status {
	case "approved":
		return finishJoin(planeURL, staged, status, fingerprint)
	case "rejected":
		discardStagedIdentity()
		fmt.Printf("The management node REJECTED this request. The staged key has been discarded;\n")
		fmt.Printf("running join again asks with a fresh one.\n")
		return 1
	}

	fmt.Printf("Waiting up to %s for approval...\n", howLongToWaitForApproval)
	deadline := time.Now().Add(howLongToWaitForApproval)
	for time.Now().Before(deadline) {
		time.Sleep(approvalPollInterval)

		status, err := watcher.callJoin(ctx, planeURL, staged, hostname, false)
		if err != nil {
			// Transient: the plane may be restarting, and the ask is already
			// lodged. Keep waiting rather than throwing away a live request.
			continue
		}
		switch status.Status {
		case "approved":
			return finishJoin(planeURL, staged, status, fingerprint)
		case "rejected":
			discardStagedIdentity()
			fmt.Printf("The management node REJECTED this request. The staged key has been discarded.\n")
			return 1
		}
	}

	fmt.Printf("Still pending. The request stays live on the management node —\n")
	fmt.Printf("approve it there, then run `joinery-agent status` to confirm.\n")
	return 0
}

// finishJoin turns an approval into the stored credential. It deliberately does
// NOT start the agent: installing the identity and running the service are two
// decisions, and the supervisor already owns the second one.
func finishJoin(planeURL string, staged *stagedIdentity, status *joinStatusResponse, fingerprint string) int {
	if status.NodeID <= 0 {
		return cliError("the management node approved without naming a node; ask its administrator to retry the approval")
	}
	identity, err := identityFromApproval(planeURL, staged, status, cliConfig().PlaneTLSInsecure)
	if err != nil {
		discardStagedIdentity()
		return cliError("the staged keypair is unusable: %v", err)
	}
	if err := identity.Save(IdentityPath()); err != nil {
		return cliError("approved, but the identity could not be stored at %s: %v", IdentityPath(), err)
	}
	discardStagedIdentity()

	fmt.Printf("Approved. This machine is node #%d (%s) of %s.\n", status.NodeID, status.NodeSlug, planeURL)
	fmt.Printf("Credential stored at %s (fingerprint %s).\n", IdentityPath(), fingerprint)
	fmt.Printf("\nStart the agent if it is not already running: joinery-agent enable\n")
	return 0
}

func cliStatus() int {
	cfg := cliConfig()

	if cfg.Siteless {
		fmt.Printf("Posture:      machine (no Joinery site on this box)\n")
	} else {
		fmt.Printf("Posture:      node (site at %s)\n", cfg.SiteRoot)
	}

	if markerSaysRun() {
		fmt.Printf("Switch:       on\n")
	} else {
		fmt.Printf("Switch:       off\n")
	}

	identity, err := LoadIdentity(IdentityPath())
	switch {
	case err != nil:
		fmt.Printf("Connected to: (a credential exists at %s but is unusable: %v)\n", IdentityPath(), err)
		return 1
	case identity == nil:
		if staged := loadStagedIdentity(); staged != nil {
			fingerprint, ferr := stagedFingerprint(staged)
			if ferr == nil {
				fmt.Printf("Connected to: not yet — a join of %s is awaiting approval\n", staged.PlaneURL)
				fmt.Printf("Fingerprint:  %s\n", fingerprint)
				return 0
			}
		}
		fmt.Printf("Connected to: nothing. Run `joinery-agent join --management-node=URL`.\n")
		return 0
	default:
		fmt.Printf("Connected to: %s as node #%d (%s)\n", identity.PlaneURL, identity.NodeID, identity.NodeSlug)
		if raw, derr := base64.StdEncoding.DecodeString(identity.PublicKey); derr == nil {
			fmt.Printf("Fingerprint:  %s\n", Fingerprint(raw))
		}
		return 0
	}
}

func cliLeave() int {
	identity, err := LoadIdentity(IdentityPath())
	if err != nil {
		return cliError("the credential at %s is unusable: %v", IdentityPath(), err)
	}
	if identity == nil {
		fmt.Printf("This machine is not connected to a management node.\n")
		return 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// performLeave tells the plane and then deletes the credential locally. It
	// deletes it even when the plane could not be told, which is the operator's
	// command winning over the plane's reachability (A7) — the message says so,
	// so nobody is left believing the far side has forgotten this machine.
	if err := performLeave(ctx, newPlaneClient(cliConfig().PlaneTLSInsecure), identity); err != nil {
		return cliError("could not remove the local credential at %s: %v", IdentityPath(), err)
	}
	fmt.Printf("Disconnected from %s. The local credential is gone.\n", identity.PlaneURL)
	return 0
}

// cliSwitch writes the run marker directly.
//
// On a node the marker is a one-way projection of the agent_enabled setting,
// and the setting is the operator-facing truth. A siteless machine has no
// settings table, so here the marker IS the truth — which is why this writes it
// rather than asking a database that does not exist. On a machine that does
// have a site, the next projection from the setting overwrites this, and that
// is correct: the setting still wins where there is one.
func cliSwitch(on bool) int {
	if err := projectSwitch(on); err != nil {
		return cliError("could not write the run switch at %s: %v", markerPath(), err)
	}
	if on {
		fmt.Printf("Agent switched on. The supervisor starts it within a minute; `joinery-agent status` confirms.\n")
	} else {
		fmt.Printf("Agent switched off. A running agent finishes its current job and stops.\n")
	}
	return 0
}

// cliConfig loads configuration for a one-shot command. Unlike the service, a
// command must not block for a config that is not coming: a siteless machine
// legitimately has none, and a node with an unreadable one should be told so
// rather than left with a hanging terminal.
// It also silences the service log while it reads. LoadConfig narrates what it
// found for an operator reading journalctl, and those lines are wrong here in
// both content and tense — `status` is not "starting in machine posture", it is
// reporting on one. What a command prints should be its answer.
func cliConfig() *Config {
	restore := log.Writer()
	log.SetOutput(io.Discard)
	cfg, err := LoadConfig()
	log.SetOutput(restore)

	if err != nil {
		return &Config{Siteless: true, PlaneTLSInsecure: os.Getenv("JOINERY_PLANE_TLS_INSECURE") == "1"}
	}
	return cfg
}

func stagedFingerprint(staged *stagedIdentity) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(staged.PublicKey)
	if err != nil {
		return "", fmt.Errorf("the staged public key is not readable base64: %w", err)
	}
	return Fingerprint(raw), nil
}
