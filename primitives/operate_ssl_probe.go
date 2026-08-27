package primitives

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// ssl_probe_place / ssl_probe_clear: the node's half of the Cloudflare routing
// proof.
//
// Both primitives live in one file because they share the compiled-in path
// below and are meaningless apart: one writes the token, the other removes it,
// and neither may ever be told where.
//
// WHAT THE PROBE IS FOR. A control plane provisioning TLS for a
// Cloudflare-proxied domain cannot use DNS to learn whether that domain reaches
// the node it is provisioning: the name resolves to Cloudflare's edge from
// everywhere, so "it is behind Cloudflare" is all DNS can say. The proof is
// instead a round trip — the node writes a one-time token into its webroot, and
// the PLANE fetches /sm-ssl-probe.txt through the domain from outside. The token
// coming back is the proof that the zone proxies to this node and not to
// somebody else's.
//
// THE FETCH IS NOT A PRIMITIVE AND MUST NEVER BECOME ONE. It runs on the plane,
// deliberately: a node asking whether a domain reaches itself is a node
// answering its own question, which proves nothing at all. So the operation
// decomposes into two node primitives with a plane action between them, and the
// orchestration — resolve, place, fetch, clear — belongs to the plane.
//
// NEITHER PRIMITIVE TAKES A PATH. The filename is compiled in and the directory
// comes from the agent's own ExecEnv.WebRoot, so the entire vocabulary of "where
// does this node write a file as root" is: nowhere the plane can name. place
// takes one parameter, a token whose pattern is the shape the plane already
// mints; clear takes nothing whatsoever. A path parameter on either would hand a
// compromised plane a root write, or a root unlink, anywhere on the node — for
// the sake of a filename that has exactly one correct value.
const (
	// sslProbeFilename is the webroot file the node's own front controller
	// serves at /sm-ssl-probe.txt (views/sm_ssl_probe.php). A file dropped in
	// the webroot is not otherwise reachable on a Joinery site — every request
	// routes through serve.php — so that route is what makes the probe work at
	// all, and a node whose code predates it can never pass one.
	sslProbeFilename = "sm-ssl-probe.txt"

	// sslProbeMode is what the file is created as. The agent is root; the web
	// tier that serves the token is not, and has to be able to read it.
	sslProbeMode = 0o644
)

// sslProbeTokenPattern is the shape of a token, matching what the plane mints
// ('sm-ssl-probe-' followed by 24 hex characters). Bounded here as well as
// there because the plane is not trusted to have bounded it: this is the only
// value that crosses, so it is the only thing worth being strict about.
//
// It is deliberately tighter than the pattern the serving view accepts. The
// view has to tolerate whatever is in the file; the primitive decides what may
// be put there.
var sslProbeTokenPattern = regexp.MustCompile(`^sm-ssl-probe-[a-f0-9]{24}$`)

func init() {
	Register(Primitive{
		Name:        "ssl_probe_place",
		Class:       ClassOperate,
		Description: "Write a one-time routing-probe token into this node's webroot.",
		Params: []ParamSpec{
			// The nonce, and nothing else. The plane supplies the value it will
			// look for; it does not get to say what the file is called or where
			// it goes.
			{Name: "token", Type: ParamString, Required: true, MaxLen: 64, Pattern: sslProbeTokenPattern},
		},
		Run: runSslProbePlace,
	})

	Register(Primitive{
		Name:        "ssl_probe_clear",
		Class:       ClassOperate,
		Description: "Remove the routing-probe token from this node's webroot.",
		// Nothing. "Remove the probe token" has no argument, and a filename
		// parameter here would be a root unlink the plane could aim.
		Params: nil,
		Run:    runSslProbeClear,
	})
}

func runSslProbePlace(ctx context.Context, env *ExecEnv, params Params) (map[string]interface{}, error) {
	dir, err := sslProbeDir(env)
	if err != nil {
		return nil, err
	}
	return placeSslProbeIn(ctx, dir, params.String("token"))
}

func runSslProbeClear(ctx context.Context, env *ExecEnv, _ Params) (map[string]interface{}, error) {
	dir, err := sslProbeDir(env)
	if err != nil {
		return nil, err
	}
	return clearSslProbeIn(ctx, dir)
}

// sslProbeDir is the one place the webroot is resolved. A node that does not
// know its own webroot cannot serve a probe either, so refusing is the honest
// answer rather than guessing at a directory to write into as root.
func sslProbeDir(env *ExecEnv) (string, error) {
	if env == nil || env.WebRoot == "" {
		return "", refusedf("this node has no webroot, so it cannot place or clear a routing probe")
	}
	return env.WebRoot, nil
}

// placeSslProbeIn is the body, with the directory as an argument so it can be
// exercised against a temp tree — the arrangement list_backups and delete_backup
// use. The registered primitive passes ExecEnv.WebRoot and nothing else can.
//
// IT OVERWRITES AN EXISTING TOKEN, ON PURPOSE. Refusing would be the more
// cautious-looking choice and the wrong one. The token has no secrecy value —
// the view that serves it says so: serving it reveals nothing, matching it
// proves routing — so refusing defends nothing, while a token left behind by a
// probe that died between place and clear (an agent restart, a partitioned
// plane, a killed job) would then wedge every later attempt on that domain
// permanently, curable only by someone with filesystem access to the node. That
// is precisely the errand this migration exists to end, and ProvisionPendingSsl
// retries this path for exactly the reason that makes an abandoned token likely.
//
// The real hazard is two probes in flight against one node at once: the second
// place stomps the first, both fetches then see the wrong token, and both fail.
// That is a plane-side serialisation question, not something the node can fix —
// the node cannot know another plane job exists. What it CAN do is stop the
// stomp being invisible, so the result says whether it replaced something.
func placeSslProbeIn(_ context.Context, dir, token string) (map[string]interface{}, error) {
	// Belt as well as braces: the pattern already ran during validation, but
	// this function is reachable from the test tree directly and a token that
	// failed the shape would be written as root either way.
	if !sslProbeTokenPattern.MatchString(token) {
		return nil, refusedf("that is not the shape of a routing-probe token")
	}

	path := filepath.Join(dir, sslProbeFilename)

	// Lstat, not Stat: what matters is what is AT the path, not what it points
	// at. The webroot is writable by the web user while this runs as root, so a
	// symlink here is how a web-tier compromise would try to aim a root write.
	replaced := false
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return nil, refusedf(
				"%s on this node is not a regular file — something other than a probe token is at that path, "+
					"and this node will not write through it", sslProbeFilename)
		}
		replaced = true
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("could not examine %s: %w", sslProbeFilename, err)
	}

	// Written to a temp file and renamed into place. Two things fall out of
	// that and both matter: the plane never fetches a half-written token, and
	// rename REPLACES whatever sits at the destination rather than following
	// it, so the check above cannot be raced by a symlink planted between the
	// Lstat and the write.
	tmp, err := os.CreateTemp(dir, ".sm-ssl-probe-*")
	if err != nil {
		return nil, fmt.Errorf("could not stage a probe token in the webroot: %w", err)
	}
	staged := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			os.Remove(staged)
		}
	}()

	if _, err := tmp.WriteString(token + "\n"); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("could not write the probe token: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("could not write the probe token: %w", err)
	}
	// CreateTemp makes the file private to root; the web tier has to read it.
	if err := os.Chmod(staged, sslProbeMode); err != nil {
		return nil, fmt.Errorf("could not make the probe token readable by the web server: %w", err)
	}
	if err := os.Rename(staged, path); err != nil {
		return nil, fmt.Errorf("could not put the probe token in place: %w", err)
	}
	committed = true

	detail := "probe token placed in this node's webroot"
	if replaced {
		detail = "probe token placed, replacing one that was already there — " +
			"an earlier probe did not clean up, or another is in flight"
	}
	return map[string]interface{}{
		"filename": sslProbeFilename,
		"placed":   true,
		"replaced": replaced,
		"detail":   detail,
	}, nil
}

// clearSslProbeIn removes the token.
//
// A MISSING FILE IS SUCCESS, the same rule delete_backup states and for the same
// reason: the request names an end state — "there is no probe token on this
// node" — and a file that is already gone satisfies it. Clearing twice is not an
// error, and a job that failed because the token was never placed, or because a
// retry got there first, would be a lie about the node. The plane calls this in
// a finally; a finally that can fail for having nothing to do is a finally that
// masks the real error.
//
// What does NOT satisfy the end state still fails loudly. A directory or a
// symlink at that path means the token is not there and something else is, which
// is a fact about the node worth surfacing rather than tidying away — and
// unlinking a symlink would remove the evidence while reporting success.
func clearSslProbeIn(_ context.Context, dir string) (map[string]interface{}, error) {
	path := filepath.Join(dir, sslProbeFilename)

	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return map[string]interface{}{
			"filename": sslProbeFilename,
			"cleared":  false,
			"detail":   "no probe token on this node; nothing to clear",
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("could not examine %s: %w", sslProbeFilename, err)
	}
	if info.IsDir() {
		return nil, refusedf("%s on this node is a directory, not a probe token", sslProbeFilename)
	}
	if !info.Mode().IsRegular() {
		return nil, refusedf(
			"%s on this node is not a regular file — removing it would unlink something that is not a probe token",
			sslProbeFilename)
	}

	if err := os.Remove(path); err != nil {
		// Losing the race to another clear still leaves the asked-for end state.
		if os.IsNotExist(err) {
			return map[string]interface{}{
				"filename": sslProbeFilename,
				"cleared":  false,
				"detail":   "no probe token on this node; nothing to clear",
			}, nil
		}
		return nil, fmt.Errorf("could not remove %s: %w", sslProbeFilename, err)
	}

	return map[string]interface{}{
		"filename": sslProbeFilename,
		"cleared":  true,
		"detail":   "probe token removed from this node's webroot",
	}, nil
}
