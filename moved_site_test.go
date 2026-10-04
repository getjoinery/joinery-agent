package main

// decommission_moved_site's proof (specs/site_copy.md WP14): what it reads
// from the vhost, and that every doubt refuses.

import (
	"context"
	"errors"
	"net/http"
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
		resolve: func(_ context.Context, name string) (bool, error) {
			if w.lookupErr[name] {
				return false, errors.New("server misbehaving")
			}
			return !w.missing[name], nil
		},
		remote: func(_ context.Context, name, path string) (int, string, error) {
			if !strings.Contains(path, "?moved=") {
				return 0, "", errors.New("no cache-busting query")
			}
			if w.remoteErr[name] {
				return 0, "", errors.New("timeout")
			}
			if w.here[name] {
				return http.StatusOK, w.served, nil
			}
			if s, ok := w.status[name]; ok {
				return s, "", nil
			}
			return http.StatusNotFound, "", nil
		},
		random: func(int) (string, error) {
			n++
			return strings.Repeat(string(rune('a'+n)), 24), nil
		},
		vhost: func(string) ([]byte, error) {
			return []byte("<VirtualHost *:443>\n ServerName demo.example.com\n ServerAlias old.example.com\n" +
				" ProxyPass / http://127.0.0.1:8081/\n</VirtualHost>\n"), nil
		},
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
		"lookup failed":         {&fakeWorld{lookupErr: map[string]bool{"old.example.com": true}}, "could not look up old.example.com"},
		"container silent":      {&fakeWorld{localErr: errors.New("connection refused")}, "did not serve the probe on its own port"},
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
