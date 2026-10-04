package main

// The host's proof for decommission_moved_site (specs/site_copy.md WP14): a
// container site on this host may be removed without its operator's approval
// once every name this host serves it under reaches ANOTHER server — the old
// machine of a switch-over, whose new server already holds the site.
//
// WHY THE HOST AND NOT THE PLANE. The approval on an ordinary removal exists
// so that the management node alone cannot destroy a site. A management node
// that could say "its domain moved" would have that power back; this host
// asking the domain itself does not give it. (The SSL probe runs the other way
// round, on the plane, because there the party it distrusts is the node.)
//
// moved_site_check runs the same proof and removes nothing, so the management
// node can show where the domain goes beside the removal it would allow.
//
// THE PROOF, in order. Every doubt refuses: unreachable is not moved.
//
//  1. The names come from the host-owned vhost — the ServerName and any
//     ServerAlias of the blocks that proxy to the container — never from the
//     wire and never from the container's own config.
//  2. A one-time token goes into the container's public_html/sm-ssl-probe.txt
//     by `docker cp`, which runs nothing inside the container. Older containers
//     keep their code in the container's own layer, not a volume, so the
//     host-side volume path is not a place to write it.
//  3. Control: the container serves the token on its own port. If not, the
//     test can tell nothing and refuses.
//  4. Each name over https — certificate checked, no redirect followed, a
//     fresh query string so no cache answers. The token coming back refuses;
//     no answer, a certificate error or a 5xx refuses; any other answer is
//     another server holding the name. An alias that does not resolve at all
//     reaches nothing and passes; the ServerName itself must answer.
//  5. The token file is emptied afterwards (the probe view answers an empty
//     file with a 404), whatever the outcome.

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"joinery-agent/primitives"
)

const (
	// movedProbeFile is what the site's own front controller serves at
	// /sm-ssl-probe.txt (views/sm_ssl_probe.php).
	movedProbeFile = "sm-ssl-probe.txt"

	// movedContainerWebRoot is where install.sh puts a container site's code
	// inside its container. %s is the validated site name.
	movedContainerWebRoot = "/var/www/html/%s/public_html"

	movedFetchTimeout = 20 * time.Second
	movedCopyTimeout  = 30 * time.Second
	movedBodyCap      = 4096
)

// movedHostname is a name this host will fetch: plain DNS labels, no
// wildcard, no port, no path.
var movedHostname = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// movedSiteProber is the proof's reach into the world, as fields so the tests
// can stand in for docker, DNS and the network.
type movedSiteProber struct {
	// copyIn writes one file into the container's web root.
	copyIn func(ctx context.Context, site, name string, content []byte) error
	// local fetches a path from the container's own published port, as the
	// host's proxy would ask it for host.
	local func(ctx context.Context, port int, host, path string) (int, string, error)
	// resolve says whether a name exists in DNS at all.
	resolve func(ctx context.Context, name string) (bool, error)
	// remote fetches https://name + path from the public internet.
	remote func(ctx context.Context, name, path string) (int, string, error)
	// random returns n random bytes as hex.
	random func(n int) (string, error)
	// vhost reads the host-owned vhost for a site.
	vhost func(site string) ([]byte, error)
}

// movedSiteProofFor gates the proof on posture, as victimCeremonyFor does.
func movedSiteProofFor(cfg *Config) func(context.Context, string) (primitives.ApprovalStatement, primitives.ApprovalGate, func(), error) {
	if cfg == nil || !cfg.Siteless {
		return nil
	}
	return defaultMovedSiteProber().ceremony
}

// movedSiteCheckFor gates the check on posture, as movedSiteProofFor does.
func movedSiteCheckFor(cfg *Config) func(context.Context, string) (map[string]interface{}, error) {
	if cfg == nil || !cfg.Siteless {
		return nil
	}
	return defaultMovedSiteProber().check
}

func defaultMovedSiteProber() movedSiteProber {
	return movedSiteProber{
		copyIn:  dockerCopyIn,
		local:   fetchLocal,
		resolve: resolveName,
		remote:  fetchRemote,
		random:  randomHex,
		vhost: func(site string) ([]byte, error) {
			return os.ReadFile(fmt.Sprintf(victimVhostPattern, site))
		},
	}
}

// movedSiteTarget is what the host-owned vhost says about one site: the
// container's published port and every name the host proxies to it.
type movedSiteTarget struct {
	site    string
	port    int
	primary string
	aliases []string
}

func (t movedSiteTarget) names() []string {
	return append([]string{t.primary}, t.aliases...)
}

// errNoVhost is a site this host does not front: no vhost by its name.
var errNoVhost = errors.New("no vhost")

// locate reads the site's vhost. A refusal names what is wrong with it.
func (m movedSiteProber) locate(site string) (movedSiteTarget, error) {
	if !regexp.MustCompile(`^[a-z0-9_-]{1,50}$`).MatchString(site) {
		return movedSiteTarget{}, &primitives.RefusalError{Reason: "the site name is not one this host composes paths from"}
	}
	raw, err := m.vhost(site)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return movedSiteTarget{}, fmt.Errorf("%w: this host has no vhost for a site named %s, so there is no such container site here", errNoVhost, site)
		}
		return movedSiteTarget{}, &primitives.RefusalError{Reason: fmt.Sprintf("could not read the vhost for %s: %v", site, err)}
	}
	port, primary, aliases, err := vhostProxyNames(raw)
	if err != nil {
		return movedSiteTarget{}, &primitives.RefusalError{Reason: fmt.Sprintf("the vhost for %s: %v", site, err)}
	}
	return movedSiteTarget{site: site, port: port, primary: primary, aliases: aliases}, nil
}

// ceremony locates the site and composes the statement; the gate it returns
// runs the proof.
func (m movedSiteProber) ceremony(ctx context.Context, site string) (primitives.ApprovalStatement, primitives.ApprovalGate, func(), error) {
	none := primitives.ApprovalStatement{}
	t, err := m.locate(site)
	if err != nil {
		if errors.Is(err, errNoVhost) {
			return none, nil, nil, &primitives.RefusalError{Reason: strings.TrimPrefix(err.Error(), errNoVhost.Error()+": ")}
		}
		return none, nil, nil, err
	}

	names := t.names()
	statement := primitives.ApprovalStatement{
		Primitive: "decommission_moved_site",
		Summary: "This permanently DESTROYS the site " + site + " on this host — its container, database, " +
			"uploaded files and configuration — once this host proves that " + strings.Join(names, ", ") +
			" reach another server. Only its offsite backups survive.",
		Facts: []primitives.ApprovalFact{
			{Label: "Site", Value: site},
			{Label: "Names this host serves it under", Value: strings.Join(names, ", ")},
			{Label: "Stands in for the site's approval", Value: "every name answering from another server"},
		},
	}
	return statement, &movedSiteGate{prober: m, target: t}, nil, nil
}

// check is moved_site_check: the proof, reported instead of enforced.
//
//	state  moved   every name reaches another server
//	       here    the probe came back through a name: the domain still reaches this container
//	       unsure  the proof could not decide (no answer, a 5xx, the container silent)
//	       absent  this host has no vhost for the site: nothing here to reach
//	detail one sentence: why, or what each name answered
//	names  the names checked
func (m movedSiteProber) check(ctx context.Context, site string) (map[string]interface{}, error) {
	t, err := m.locate(site)
	if err != nil {
		if errors.Is(err, errNoVhost) {
			return map[string]interface{}{
				"state":  "absent",
				"detail": strings.TrimPrefix(err.Error(), errNoVhost.Error()+": ") + ".",
				"names":  []string{},
			}, nil
		}
		return nil, err
	}
	v := m.prove(ctx, t)
	state, detail := "unsure", v.reason
	switch {
	case v.moved:
		state, detail = "moved", strings.Join(v.evidence, "; ")+"."
	case v.here:
		state = "here"
	}
	return map[string]interface{}{"state": state, "detail": detail, "names": t.names()}, nil
}

// vhostProxyNames reads the container's published port and the names the
// host proxies to it. Only blocks that proxy count: the www block answers
// with a redirect and never reaches the container.
func vhostProxyNames(raw []byte) (int, string, []string, error) {
	port := 0
	primary := ""
	var aliases []string
	seen := map[string]bool{}
	blocks := strings.Split(string(raw), "<VirtualHost")
	for _, block := range blocks[1:] {
		m := proxyPassPort.FindStringSubmatch(block)
		if m == nil {
			continue
		}
		var p int
		fmt.Sscanf(m[1], "%d", &p)
		if p < 1 || p > 65535 {
			return 0, "", nil, errors.New("it names an unusable port")
		}
		if port != 0 && port != p {
			return 0, "", nil, errors.New("its blocks proxy to different ports")
		}
		port = p
		for _, line := range strings.Split(block, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
				continue
			}
			switch strings.ToLower(fields[0]) {
			case "servername":
				name := strings.ToLower(fields[1])
				if primary != "" && primary != name {
					return 0, "", nil, fmt.Errorf("its proxying blocks name two servers (%s, %s)", primary, name)
				}
				primary = name
			case "serveralias":
				for _, a := range fields[1:] {
					a = strings.ToLower(a)
					if !seen[a] {
						seen[a] = true
						aliases = append(aliases, a)
					}
				}
			}
		}
	}
	if port == 0 {
		return 0, "", nil, errors.New("it carries no ProxyPass port, so this is not a container site this host fronts")
	}
	if primary == "" {
		return 0, "", nil, errors.New("its proxying blocks name no ServerName")
	}
	var out []string
	for _, n := range append([]string{primary}, aliases...) {
		if !movedHostname.MatchString(n) {
			return 0, "", nil, fmt.Errorf("it names %q, which this host cannot check by asking it", n)
		}
		if n != primary {
			out = append(out, n)
		}
	}
	return port, primary, out, nil
}

// movedSiteGate enforces the proof. Require returns nil only when it says
// moved.
type movedSiteGate struct {
	prober movedSiteProber
	target movedSiteTarget
}

func (g *movedSiteGate) Require(ctx context.Context, jobID int64, _ primitives.ApprovalStatement) error {
	v := g.prober.prove(ctx, g.target)
	if !v.moved {
		return &primitives.RefusalError{Reason: v.reason + " Nothing was removed."}
	}
	log.Printf("decommission_moved_site %s (job %d): domain has left this host — %s",
		g.target.site, jobID, strings.Join(v.evidence, "; "))
	return nil
}

// movedVerdict is one run of the proof.
type movedVerdict struct {
	moved    bool     // every name reaches another server
	here     bool     // the probe came back through a name
	reason   string   // why it is not moved: one sentence; empty when moved
	evidence []string // what each name answered, when moved
}

// prove runs the proof. It answers moved only when the container served the
// token on its own port and no name this host serves it under brought the
// token back.
func (m movedSiteProber) prove(ctx context.Context, t movedSiteTarget) movedVerdict {
	not := func(format string, args ...interface{}) movedVerdict {
		return movedVerdict{reason: fmt.Sprintf(format, args...)}
	}

	tokenHex, err := m.random(12)
	if err != nil {
		return not("Could not make a probe token: %v.", err)
	}
	token := "sm-ssl-probe-" + tokenHex
	bust, err := m.random(8)
	if err != nil {
		return not("Could not make a probe token: %v.", err)
	}
	path := "/" + movedProbeFile + "?moved=" + bust

	if err := m.copyIn(ctx, t.site, movedProbeFile, []byte(token+"\n")); err != nil {
		return not("Could not put the probe into the container %s: %v.", t.site, err)
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), movedCopyTimeout)
		defer cancel()
		if err := m.copyIn(cctx, t.site, movedProbeFile, nil); err != nil {
			log.Printf("moved-site proof %s: could not empty the probe file: %v", t.site, err)
		}
	}()

	status, body, err := m.local(ctx, t.port, t.primary, path)
	if err != nil || status != http.StatusOK || strings.TrimSpace(body) != token {
		why := fmt.Sprintf("answered %d without the token", status)
		if err != nil {
			why = err.Error()
		}
		return not("The site %s did not serve the probe on its own port (%s), so this host cannot tell "+
			"where its domain goes.", t.site, why)
	}

	var evidence []string
	for i, name := range t.names() {
		found, err := m.resolve(ctx, name)
		if err != nil {
			return not("Could not look up %s (%v). A name that cannot be looked up is not proof it moved.", name, err)
		}
		if !found {
			if i == 0 {
				return not("%s does not resolve at all. That is not proof another server holds the site.", name)
			}
			evidence = append(evidence, name+": does not resolve")
			continue
		}
		status, body, err := m.remote(ctx, name, path)
		if err != nil {
			return not("https://%s did not answer (%v). A domain that cannot be reached is not proof it moved.", name, err)
		}
		if strings.Contains(body, token) {
			v := not("https://%s still reaches this site: the probe came back through it.", name)
			v.here = true
			return v
		}
		if status >= 500 {
			return not("https://%s answered %d, which may be this site failing rather than another server.", name, status)
		}
		evidence = append(evidence, fmt.Sprintf("%s: answered %d from another server", name, status))
	}
	return movedVerdict{moved: true, evidence: evidence}
}

// dockerCopyIn writes one file into the container's web root through the
// Docker daemon's archive copy. Nothing runs inside the container, and the
// destination resolves within the container's own filesystem, so a link the
// container planted cannot aim the write at the host. Empty content empties
// the file.
func dockerCopyIn(ctx context.Context, site, name string, content []byte) error {
	docker, err := exec.LookPath("docker")
	if err != nil {
		return errors.New("docker is not on this host's path")
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)),
		ModTime: time.Now(), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	if _, err := tw.Write(content); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, movedCopyTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, docker, "cp", "-", site+":"+fmt.Sprintf(movedContainerWebRoot, site))
	cmd.Stdin = &buf
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, displaySafe(string(out), 200))
	}
	return nil
}

func noRedirectClient(transport *http.Transport) *http.Client {
	return &http.Client{
		Timeout:   movedFetchTimeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func readCapped(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, movedBodyCap))
	return string(b)
}

// fetchLocal asks the container on its loopback port, the way the host's own
// proxy does: the site's name as Host, and https as the forwarded scheme.
func fetchLocal(ctx context.Context, port int, host, path string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
	if err != nil {
		return 0, "", err
	}
	req.Host = host
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := noRedirectClient(&http.Transport{Proxy: nil}).Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	return resp.StatusCode, readCapped(resp), nil
}

// fetchRemote asks the public internet, certificate checked.
func fetchRemote(ctx context.Context, name, path string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+name+path, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Cache-Control", "no-cache")
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	resp, err := noRedirectClient(transport).Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	return resp.StatusCode, readCapped(resp), nil
}

// resolveName separates "no such name" from "could not ask".
func resolveName(ctx context.Context, name string) (bool, error) {
	lctx, cancel := context.WithTimeout(ctx, movedFetchTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(lctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, nil
		}
		return false, err
	}
	return len(addrs) > 0, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
