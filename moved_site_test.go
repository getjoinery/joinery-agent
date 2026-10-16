package main

// decommission_moved_site's proof (specs/site_copy.md WP14): what it reads
// from the vhost, and that every doubt refuses.

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"joinery-agent/primitives"
)

// A vhost in the shape default_proxy_vhost.conf renders: two proxying blocks
// for the apex, and www blocks that only redirect.
const movedVhost = `
<VirtualHost *:80>
    ServerName demo.example.com
    ProxyPass / http://127.0.0.1:8081/
</VirtualHost>
<VirtualHost *:443>
    ServerName demo.example.com
    ProxyPass / http://127.0.0.1:8081/
</VirtualHost>
<VirtualHost *:443>
    ServerName www.demo.example.com
    Redirect 308 / https://demo.example.com/
</VirtualHost>
<VirtualHost *:80>
    ServerName www.demo.example.com
    RewriteRule ^(.*)$ https://demo.example.com$1 [R=308,L]
</VirtualHost>
`

func TestVhostProxyNamesTakesOnlyTheProxyingBlocks(t *testing.T) {
	port, primary, aliases, err := vhostProxyNames([]byte(movedVhost))
	if err != nil {
		t.Fatal(err)
	}
	if port != 8081 || primary != "demo.example.com" || len(aliases) != 0 {
		t.Fatalf("got port %d, primary %q, aliases %v", port, primary, aliases)
	}

	legacy := "<VirtualHost *:80>\n ServerName a.example.com\n ServerAlias www.a.example.com b.example.com\n" +
		" ProxyPass / http://127.0.0.1:8090/\n</VirtualHost>\n"
	_, primary, aliases, err = vhostProxyNames([]byte(legacy))
	if err != nil || primary != "a.example.com" || strings.Join(aliases, ",") != "www.a.example.com,b.example.com" {
		t.Fatalf("legacy aliases: %q %v %v", primary, aliases, err)
	}
}

func TestVhostProxyNamesRefusesWhatItCannotCheck(t *testing.T) {
	for name, raw := range map[string]string{
		"no proxy":     "<VirtualHost *:80>\n ServerName a.example.com\n DocumentRoot /x\n</VirtualHost>\n",
		"no name":      "<VirtualHost *:80>\n ProxyPass / http://127.0.0.1:8090/\n</VirtualHost>\n",
		"wildcard":     "<VirtualHost *:80>\n ServerName a.example.com\n ServerAlias *.example.com\n ProxyPass / http://127.0.0.1:8090/\n</VirtualHost>\n",
		"two servers":  "<VirtualHost *:80>\n ServerName a.example.com\n ProxyPass / http://127.0.0.1:8090/\n</VirtualHost>\n<VirtualHost *:443>\n ServerName b.example.com\n ProxyPass / http://127.0.0.1:8090/\n</VirtualHost>\n",
		"two ports":    "<VirtualHost *:80>\n ServerName a.example.com\n ProxyPass / http://127.0.0.1:8090/\n</VirtualHost>\n<VirtualHost *:443>\n ServerName a.example.com\n ProxyPass / http://127.0.0.1:8091/\n</VirtualHost>\n",
		"bare address": "<VirtualHost *:80>\n ServerName localhost\n ProxyPass / http://127.0.0.1:8090/\n</VirtualHost>\n",
	} {
		if _, _, _, err := vhostProxyNames([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// fakeWorld is the prober over a scripted world. served is what the container
// holds in its probe file; here says which names still reach this host.
type fakeWorld struct {
	served    string
	copies    []string
	localErr  error
	here      map[string]bool
	missing   map[string]bool
	lookupErr map[string]bool
	remoteErr map[string]bool
	status    map[string]int
	addrs     map[string][]string // a name's addresses; default 203.0.113.9
	foreign   map[string]bool     // answers without Joinery's header (an edge, a parking page)
	held      bool                // hold_container keeps the container stopped
	heldErr   error
	own       []string // this machine's addresses
	remoteAsk []string
}

func (w *fakeWorld) prober() movedSiteProber {
	n := 0
	return movedSiteProber{
		copyIn: func(_ context.Context, site, name string, content []byte) error {
			w.served = strings.TrimSpace(string(content))
			w.copies = append(w.copies, w.served)
			return nil
		},
		local: func(_ context.Context, port int, host, path string) (int, string, error) {
			if w.localErr != nil {
				return 0, "", w.localErr
			}
			if w.served == "" {
				return http.StatusNotFound, "", nil
			}
			return http.StatusOK, w.served, nil
		},
		resolve: func(_ context.Context, name string) ([]string, error) {
			if w.lookupErr[name] {
				return nil, errors.New("server misbehaving")
			}
			if w.missing[name] {
				return nil, nil
			}
			if a, ok := w.addrs[name]; ok {
				return a, nil
			}
			return []string{"203.0.113.9"}, nil
		},
		remote: func(_ context.Context, name, path string) (int, string, bool, error) {
			w.remoteAsk = append(w.remoteAsk, name)
			if !strings.Contains(path, "?moved=") {
				return 0, "", false, errors.New("no cache-busting query")
			}
			if w.remoteErr[name] {
				return 0, "", false, errors.New("timeout")
			}
			if w.here[name] {
				return http.StatusOK, w.served, true, nil
			}
			if s, ok := w.status[name]; ok {
				return s, "", !w.foreign[name], nil
			}
			return http.StatusNotFound, "", !w.foreign[name], nil
		},
		random: func(int) (string, error) {
			n++
			return strings.Repeat(string(rune('a'+n)), 24), nil
		},
		vhost: func(string) ([]byte, error) {
			return []byte("<VirtualHost *:443>\n ServerName demo.example.com\n ServerAlias old.example.com\n" +
				" ProxyPass / http://127.0.0.1:8081/\n</VirtualHost>\n"), nil
		},
		held: func(context.Context, string) (bool, error) { return w.held, w.heldErr },
		own:  func() []string { return w.own },
	}
}

func runMovedProof(t *testing.T, w *fakeWorld) error {
	t.Helper()
	statement, gate, _, err := w.prober().ceremony(context.Background(), "demo")
	if err != nil {
		t.Fatalf("ceremony: %v", err)
	}
	if statement.Primitive != "decommission_moved_site" || !strings.Contains(statement.Summary, "demo.example.com, old.example.com") {
		t.Fatalf("statement: %+v", statement)
	}
	err = gate.Require(context.Background(), 7, statement)
	if len(w.copies) != 2 || w.copies[1] != "" {
		t.Fatalf("the probe file must be placed and then emptied, got %q", w.copies)
	}
	return err
}

func refusedWith(t *testing.T, err error, want string) {
	t.Helper()
	var r *primitives.RefusalError
	if !errors.As(err, &r) {
		t.Fatalf("want a refusal mentioning %q, got %v", want, err)
	}
	if !strings.Contains(r.Reason, want) || !strings.Contains(r.Reason, "Nothing was removed") {
		t.Fatalf("refusal %q does not mention %q", r.Reason, want)
	}
}

func TestMovedProofPassesWhenEveryNameAnswersElsewhere(t *testing.T) {
	w := &fakeWorld{status: map[string]int{"old.example.com": 301}}
	if err := runMovedProof(t, w); err != nil {
		t.Fatalf("want pass, got %v", err)
	}
}

func TestMovedProofLetsAnAliasThatResolvesNowherePass(t *testing.T) {
	w := &fakeWorld{missing: map[string]bool{"old.example.com": true}}
	if err := runMovedProof(t, w); err != nil {
		t.Fatalf("want pass, got %v", err)
	}
}

func TestMovedProofRefusals(t *testing.T) {
	cases := map[string]struct {
		w    *fakeWorld
		want string
	}{
		"domain still here":     {&fakeWorld{here: map[string]bool{"demo.example.com": true}}, "still reaches this site"},
		"alias still here":      {&fakeWorld{here: map[string]bool{"old.example.com": true}}, "https://old.example.com still reaches"},
		"domain unreachable":    {&fakeWorld{remoteErr: map[string]bool{"demo.example.com": true}}, "did not answer"},
		"origin error":          {&fakeWorld{status: map[string]int{"demo.example.com": 522}}, "answered 522"},
		"domain does not exist": {&fakeWorld{missing: map[string]bool{"demo.example.com": true}}, "does not resolve at all"},
		"lookup failed":         {&fakeWorld{lookupErr: map[string]bool{"old.example.com": true}}, "Could not look up old.example.com"},
		"container silent":      {&fakeWorld{localErr: errors.New("connection refused")}, "did not serve the probe on its own port"},
		// An edge in front of a live site answers with its own page: no token,
		// below 500, and no Joinery header (reviewer1 F1).
		"edge challenge": {&fakeWorld{status: map[string]int{"demo.example.com": 403}, foreign: map[string]bool{"demo.example.com": true}}, "answered 403 without Joinery's header"},
		"edge archive":   {&fakeWorld{status: map[string]int{"old.example.com": 200}, foreign: map[string]bool{"old.example.com": true}}, "https://old.example.com answered 200 without Joinery's header"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			refusedWith(t, runMovedProof(t, c.w), c.want)
		})
	}
}

func TestMovedProofIsHostPostureOnly(t *testing.T) {
	if movedSiteProofFor(&Config{Siteless: false}) != nil || movedSiteProofFor(nil) != nil {
		t.Fatal("a machine with a site of its own must not get the proof")
	}
	if movedSiteProofFor(&Config{Siteless: true}) == nil {
		t.Fatal("a host must get the proof")
	}
}

func runMovedCheck(t *testing.T, w *fakeWorld) map[string]interface{} {
	t.Helper()
	out, err := w.prober().check(context.Background(), "demo")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(w.copies) != 2 || w.copies[1] != "" {
		t.Fatalf("the probe file must be placed and then emptied, got %q", w.copies)
	}
	return out
}

// The check is the same proof as the removal's gate, reported: what the page
// shows and what the removal would allow cannot disagree.
func TestMovedCheckReportsTheProof(t *testing.T) {
	cases := map[string]struct {
		w      *fakeWorld
		state  string
		detail string
	}{
		"moved":       {&fakeWorld{status: map[string]int{"old.example.com": 301}}, "moved", "old.example.com: answered 301 from another Joinery server"},
		"still here":  {&fakeWorld{here: map[string]bool{"demo.example.com": true}}, "here", "still reaches this site"},
		"unreachable": {&fakeWorld{remoteErr: map[string]bool{"demo.example.com": true}}, "unsure", "did not answer"},
		"silent":      {&fakeWorld{localErr: errors.New("connection refused")}, "unsure", "did not serve the probe"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			out := runMovedCheck(t, c.w)
			if out["state"] != c.state || !strings.Contains(out["detail"].(string), c.detail) {
				t.Fatalf("got %v", out)
			}
			if strings.Contains(out["detail"].(string), "Nothing was removed") {
				t.Fatalf("a check removes nothing and must not say it refused a removal: %v", out)
			}
			if names := out["names"].([]string); strings.Join(names, ",") != "demo.example.com,old.example.com" {
				t.Fatalf("names: %v", names)
			}
		})
	}
}

func TestMovedCheckSaysAbsentWithoutAVhost(t *testing.T) {
	w := &fakeWorld{}
	p := w.prober()
	p.vhost = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	out, err := p.check(context.Background(), "demo")
	if err != nil || out["state"] != "absent" || len(w.copies) != 0 {
		t.Fatalf("got %v %v, copies %q", out, err, w.copies)
	}
	if _, _, _, err := p.ceremony(context.Background(), "demo"); err == nil {
		t.Fatal("the removal must refuse a site this host has no vhost for")
	}
}

func TestMovedCheckIsHostPostureOnly(t *testing.T) {
	if movedSiteCheckFor(&Config{Siteless: false}) != nil || movedSiteCheckFor(nil) != nil {
		t.Fatal("a machine with a site of its own must not get the check")
	}
	if movedSiteCheckFor(&Config{Siteless: true}) == nil {
		t.Fatal("a host must get the check")
	}
}

// THE HELD CASE: a switch-over's old container, frozen and then stopped and
// held by hold_container, can serve no token. Its names must answer from
// another server and none may resolve to this machine; no token is placed.
func runHeldProof(t *testing.T, w *fakeWorld) error {
	t.Helper()
	w.held = true
	statement, gate, _, err := w.prober().ceremony(context.Background(), "demo")
	if err != nil {
		t.Fatalf("ceremony: %v", err)
	}
	err = gate.Require(context.Background(), 7, statement)
	if len(w.copies) != 0 {
		t.Fatalf("a held container gets no probe file, got %q", w.copies)
	}
	return err
}

func TestMovedProofOfAHeldContainerPassesWhenEveryNameAnswersElsewhere(t *testing.T) {
	w := &fakeWorld{own: []string{"198.51.100.7", "2001:db8::7"}, status: map[string]int{"old.example.com": 301}}
	if err := runHeldProof(t, w); err != nil {
		t.Fatalf("want pass, got %v", err)
	}
	if strings.Join(w.remoteAsk, ",") != "demo.example.com,old.example.com" {
		t.Fatalf("every name is asked: %v", w.remoteAsk)
	}
}

func TestMovedProofOfAHeldContainerRefusals(t *testing.T) {
	own := []string{"198.51.100.7", "2001:db8::7"}
	cases := map[string]struct {
		w    *fakeWorld
		want string
	}{
		"domain at this host, IPv4": {&fakeWorld{own: own, addrs: map[string][]string{"demo.example.com": {"198.51.100.7"}}}, "an address of this host"},
		"domain at this host, IPv6": {&fakeWorld{own: own, addrs: map[string][]string{"demo.example.com": {"203.0.113.9", "2001:db8:0:0::7"}}}, "an address of this host"},
		"mapped IPv4 of this host":  {&fakeWorld{own: own, addrs: map[string][]string{"old.example.com": {"::ffff:198.51.100.7"}}}, "old.example.com resolves to"},
		"this host's proxy, a 503":  {&fakeWorld{own: own, status: map[string]int{"demo.example.com": 503}}, "answered 503"},
		"an edge's origin error":    {&fakeWorld{own: own, status: map[string]int{"old.example.com": 521}}, "answered 521"},
		"domain unreachable":        {&fakeWorld{own: own, remoteErr: map[string]bool{"demo.example.com": true}}, "did not answer"},
		"domain does not exist":     {&fakeWorld{own: own, missing: map[string]bool{"demo.example.com": true}}, "does not resolve at all"},
		"lookup failed":             {&fakeWorld{own: own, lookupErr: map[string]bool{"old.example.com": true}}, "Could not look up old.example.com"},
		// The plane can hold a LIVE site behind a CDN: its names resolve to the
		// edge and the edge answers with its own page (reviewer1 F1).
		"edge challenge, live site": {&fakeWorld{own: own, status: map[string]int{"demo.example.com": 403}, foreign: map[string]bool{"demo.example.com": true}}, "answered 403 without Joinery's header"},
		"edge archive, live site":   {&fakeWorld{own: own, status: map[string]int{"demo.example.com": 200}, foreign: map[string]bool{"demo.example.com": true}}, "answered 200 without Joinery's header"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			refusedWith(t, runHeldProof(t, c.w), c.want)
		})
	}
}

func TestMovedProofRefusesWhenTheHoldCannotBeRead(t *testing.T) {
	w := &fakeWorld{heldErr: errors.New("permission denied")}
	statement, gate, _, err := w.prober().ceremony(context.Background(), "demo")
	if err != nil {
		t.Fatalf("ceremony: %v", err)
	}
	refusedWith(t, gate.Require(context.Background(), 7, statement), "Could not tell whether the container demo is held stopped")
	if len(w.copies) != 0 || len(w.remoteAsk) != 0 {
		t.Fatalf("nothing is placed or asked when the hold cannot be read: %q %v", w.copies, w.remoteAsk)
	}
}

func TestMovedCheckOfAHeldContainer(t *testing.T) {
	w := &fakeWorld{held: true, own: []string{"198.51.100.7"}}
	out, err := w.prober().check(context.Background(), "demo")
	if err != nil || out["state"] != "moved" || !strings.Contains(out["detail"].(string), "held stopped on this host") {
		t.Fatalf("got %v %v", out, err)
	}
	w = &fakeWorld{held: true, own: []string{"198.51.100.7"}, addrs: map[string][]string{"demo.example.com": {"198.51.100.7"}}}
	out, err = w.prober().check(context.Background(), "demo")
	if err != nil || out["state"] != "here" {
		t.Fatalf("a name at this host's address is here: %v %v", out, err)
	}
}
