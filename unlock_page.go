package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"joinery-agent/primitives"
	"joinery-agent/xwing"
)

// The unlock page (specs/hosted_data_promise_disk_encryption.md D2b, WP8).
//
// While the data root is locked, the web server is not running (it waits for
// joinery-data.target), so the unlock answers the machine's own ports 80 and
// 443 itself, with one page: this server is waiting to be unlocked, and a box
// for the recovery key. It uses the site's own certificate from
// /etc/letsencrypt, on the root disk, so it is ordinary https at the site's
// name and works through the Cloudflare proxy; a host serves every name it
// has a certificate for, and never a self-signed one.
//
// THE KEY STAYS IN THE BROWSER. The page works like /copy-key
// (VaultCrypto.halfOpenKeyBox): for a version-2 box (an X-Wing recovery key)
// the browser decapsulates the box's ciphertext with the pasted seed and sends
// the box's dek-scope AES key; for a version-1 box (an old X25519 key) it takes
// the X25519 of the pasted key with the box's ephemeral key. Either is a
// 32-byte value that opens the break-glass box and nothing else; this finishes
// the opening. X-Wing in the browser is the platform's vendored module
// (assets/vendor/noble/), embedded here and inlined into the page, since a
// locked machine serves nothing else; unlock_xwing_test.go holds it to the
// platform's pin. Its limit, said plainly in the spec: the
// page is served by the machine itself, so it carries the console's risk and
// no more. Where the holder is up, the unlock is the holder's.
//
// EVERY ANSWER IS 503, with Retry-After and X-Joinery-Locked: 1, so both
// uptime paths read the machine as locked, not up and not down. Tries are
// limited by the caller's address: CF-Connecting-IP only when the connection
// comes from a Cloudflare range, otherwise the connection's own.

//go:embed cloudflare_ip_ranges.txt
var embeddedCloudflareRanges string

// unlockXWingSHA256 is the platform's pin of its vendored X-Wing module
// (assets/vendor/noble/README.md); the embedded copy must be that file.
const unlockXWingSHA256 = "c755cc88401a2eda9b19fcc71f6c4d651136560c4a1108aff7fda0eb5431bb98"

//go:embed unlock_xwing.min.js
var embeddedXWing string

const (
	unlockPagePost      = "/.joinery-unlock"
	unlockPageMaxFails  = 5
	unlockPageFailSpan  = 15 * time.Minute
	unlockPageLetsEncry = "/etc/letsencrypt/live"
)

type unlockPage struct {
	u            *dataRootUnlocker
	host         string
	sealed       []byte
	alg          string // the recipient's: "xwing" for a version-2 box
	recipientPub []byte
	fingerprint  string
	cf           []*net.IPNet

	mu    sync.Mutex
	fails map[string][]time.Time
}

func newUnlockPage(u *dataRootUnlocker) (*unlockPage, error) {
	data, err := os.ReadFile(u.conf.breakGlassSidecar())
	if err != nil {
		return nil, fmt.Errorf("the break-glass copy cannot be read: %v", err)
	}
	var env sidecarEnvelope
	if err := json.Unmarshal(data, &env); err != nil || len(env.Recipients) == 0 {
		return nil, errors.New("the break-glass copy is not readable")
	}
	sealed, err := base64.StdEncoding.DecodeString(env.Recipients[0].Sealed)
	alg := env.Recipients[0].Alg
	if err != nil || len(sealed) <= 32 || (alg == sidecarAlgXWing && len(sealed) <= xwing.Overhead) {
		return nil, errors.New("the break-glass copy holds no sealed box")
	}
	pub, fpr, err := readRecipient(filepath.Join(filepath.Dir(dataRootConfPath), "data-root", "recovery_recipient"))
	if err != nil {
		return nil, err
	}
	if fpr != env.Recipients[0].Fingerprint {
		return nil, fmt.Errorf("the break-glass copy is sealed to %s, and the recovery recipient here is %s", env.Recipients[0].Fingerprint, fpr)
	}
	if (alg == sidecarAlgXWing) != (len(pub) == xwing.PublicKeyBytes) {
		return nil, errors.New("the break-glass copy and the recovery recipient here are not the same kind of key")
	}
	return &unlockPage{u: u, host: u.host, sealed: sealed, alg: alg, recipientPub: pub, fingerprint: fpr,
		cf: cloudflareRanges(), fails: map[string][]time.Time{}}, nil
}

// cloudflareRanges is the platform's own list (includes/cloudflare_ip_ranges.txt)
// from a site's tree on the root disk when there is one, else the copy built
// into this binary.
func cloudflareRanges() []*net.IPNet {
	text := embeddedCloudflareRanges
	if matches, _ := filepath.Glob("/var/www/html/*/public_html/includes/cloudflare_ip_ranges.txt"); len(matches) > 0 {
		if b, err := os.ReadFile(matches[0]); err == nil {
			text = string(b)
		}
	}
	var out []*net.IPNet
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, n, err := net.ParseCIDR(line); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// clientAddress is who is asking, read the way the platform reads it.
func (p *unlockPage) clientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	for _, n := range p.cf {
		if n.Contains(ip) {
			if cf := net.ParseIP(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); cf != nil {
				return cf.String()
			}
			break
		}
	}
	return ip.String()
}

// allowed says whether addr may try again, and how long it must wait if not.
func (p *unlockPage) allowed(addr string) (bool, time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cut := time.Now().Add(-unlockPageFailSpan)
	kept := p.fails[addr][:0]
	for _, t := range p.fails[addr] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	p.fails[addr] = kept
	if len(kept) >= unlockPageMaxFails {
		return false, time.Until(kept[0].Add(unlockPageFailSpan)).Round(time.Minute)
	}
	return true, 0
}

func (p *unlockPage) failed(addr string) {
	p.mu.Lock()
	p.fails[addr] = append(p.fails[addr], time.Now())
	p.mu.Unlock()
}

func lockedHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Joinery-Locked", "1")
	w.Header().Set("Retry-After", "60")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func (p *unlockPage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	lockedHeaders(w)
	if r.Method == http.MethodPost && r.URL.Path == unlockPagePost {
		p.answer(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
	w.WriteHeader(http.StatusServiceUnavailable)
	if r.Method == http.MethodHead {
		return
	}
	fmt.Fprint(w, p.pageHTML())
}

type unlockPageAnswer struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func (p *unlockPage) reply(w http.ResponseWriter, status int, ok bool, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(unlockPageAnswer{OK: ok, Message: msg})
}

// answer takes the browser's 32-byte value and opens the volume with it.
func (p *unlockPage) answer(w http.ResponseWriter, r *http.Request) {
	addr := p.clientAddress(r)
	if ok, wait := p.allowed(addr); !ok {
		p.reply(w, http.StatusTooManyRequests, false, fmt.Sprintf("Too many keys that did not open it from this address. Try again in %s.", wait))
		return
	}
	var in struct {
		Shared    string `json:"shared"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		p.reply(w, http.StatusBadRequest, false, "That request is not one this page sends.")
		return
	}
	shared, err1 := base64.StdEncoding.DecodeString(in.Shared)
	pub, err2 := base64.StdEncoding.DecodeString(in.PublicKey)
	if err1 != nil || err2 != nil || len(shared) != 32 || len(pub) != len(p.recipientPub) {
		p.failed(addr)
		p.reply(w, http.StatusBadRequest, false, "That request is not one this page sends.")
		return
	}
	sum := sha256.Sum256(pub)
	if hex.EncodeToString(sum[:]) != p.fingerprint {
		p.failed(addr)
		p.reply(w, http.StatusForbidden, false, "That recovery key is not the one this server's data is sealed to.")
		return
	}
	key, err := primitives.OpenRecoverySealed(p.sealed, shared, p.recipientPub)
	zero(shared)
	if err != nil || len(key) != volumeKeyBytes {
		// (a driving slot's secret, part-way through an encryption, is the
		// same length: 64 characters)
		p.failed(addr)
		unlockSay("a recovery key was given on the unlock page from %s and refused", addr)
		p.reply(w, http.StatusForbidden, false, "That key does not open this server's data.")
		return
	}
	err = p.u.openWith(key, "the recovery key, on the unlock page")
	zero(key)
	if err != nil {
		unlockSay("the unlock page's key was right, but the volume did not open: %v", err)
		p.reply(w, http.StatusInternalServerError, false, "The key is right, but the data did not open. The server's console says why.")
		return
	}
	unlockSay("unlocked from the unlock page, from %s", addr)
	p.reply(w, http.StatusOK, true, "Unlocked. The site is starting; this page will be replaced by it within a minute or two.")
}

// serve answers ports 80 and 443 until ctx ends. Without a certificate there
// is no 443: never a self-signed one, so no one learns to click through a
// warning. Port 80 sends a name with a certificate to https.
func (p *unlockPage) serve(ctx context.Context) {
	certs := loadSiteCertificates(unlockPageLetsEncry)
	var servers []*http.Server
	plain := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if certs.covers(r.Host) {
			lockedHeaders(w)
			http.Redirect(w, r, "https://"+stripPort(r.Host)+r.URL.RequestURI(), http.StatusMovedPermanently)
			return
		}
		p.ServeHTTP(w, r)
	})
	s80 := &http.Server{Addr: ":80", Handler: plain, ReadHeaderTimeout: 10 * time.Second}
	servers = append(servers, s80)
	go func() {
		if err := s80.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			unlockSay("the unlock page could not take port 80: %v", err)
		}
	}()
	if len(certs.list) > 0 {
		s443 := &http.Server{Addr: ":443", Handler: p, ReadHeaderTimeout: 10 * time.Second,
			TLSConfig: &tls.Config{GetCertificate: certs.get, MinVersion: tls.VersionTLS12}}
		servers = append(servers, s443)
		go func() {
			if err := s443.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				unlockSay("the unlock page could not take port 443: %v", err)
			}
		}()
		unlockSay("the unlock page answers on ports 80 and 443 (%d certificate(s))", len(certs.list))
	} else {
		unlockSay("the unlock page answers on port 80; there is no certificate here for 443")
	}
	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, s := range servers {
		s.Shutdown(sctx)
	}
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

type siteCertificates struct {
	list []*tls.Certificate
}

// loadSiteCertificates reads every certificate the machine has from
// Let's Encrypt's live directory.
func loadSiteCertificates(dir string) *siteCertificates {
	out := &siteCertificates{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		c, err := tls.LoadX509KeyPair(filepath.Join(dir, e.Name(), "fullchain.pem"), filepath.Join(dir, e.Name(), "privkey.pem"))
		if err != nil || c.Leaf == nil {
			continue
		}
		if time.Now().After(c.Leaf.NotAfter) {
			continue
		}
		cc := c
		out.list = append(out.list, &cc)
	}
	return out
}

func (s *siteCertificates) match(name string) *tls.Certificate {
	name = strings.ToLower(stripPort(name))
	for _, c := range s.list {
		if c.Leaf.VerifyHostname(name) == nil {
			return c
		}
	}
	return nil
}

func (s *siteCertificates) covers(host string) bool { return s.match(host) != nil }

func (s *siteCertificates) get(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := s.match(hello.ServerName); c != nil {
		return c, nil
	}
	if len(s.list) > 0 {
		return s.list[0], nil
	}
	return nil, errors.New("no certificate")
}

func (p *unlockPage) pageHTML() string {
	box := map[string]string{"fingerprint": p.fingerprint, "post": unlockPagePost}
	xw := ""
	if p.alg == sidecarAlgXWing {
		box["ciphertext"] = base64.StdEncoding.EncodeToString(p.sealed[:xwing.CiphertextBytes])
		xw = "<script>" + embeddedXWing + "</script>\n"
	} else {
		box["ephemeralPublic"] = base64.StdEncoding.EncodeToString(p.sealed[:32])
	}
	cfg, _ := json.Marshal(box)
	page := strings.Replace(unlockPageTemplate, "{{HOST}}", html.EscapeString(p.host), -1)
	page = strings.Replace(page, "{{XWING}}", xw, 1)
	return strings.Replace(page, "{{CONFIG}}", string(cfg), 1)
}

// The page: nothing about the machine beyond its name and that it is locked.
// Its script is VaultCrypto.halfOpenKeyBox's arithmetic (assets/js/vault-crypto.js).
const unlockPageTemplate = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>Waiting to be unlocked</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f5f7;color:#1d2330;margin:0;padding:16px}
main{max-width:520px;margin:10vh auto;background:#fff;border:1px solid #dde1e8;border-radius:10px;padding:28px}
h1{font-size:1.35rem;margin:0 0 .5rem}p{line-height:1.5;margin:.6rem 0}
input{width:100%;box-sizing:border-box;font:14px ui-monospace,Menlo,monospace;padding:10px;border:1px solid #b9c0cc;border-radius:6px}
button{margin-top:12px;padding:10px 18px;font-size:1rem;border:0;border-radius:6px;background:#1d4ed8;color:#fff;cursor:pointer}
button:disabled{opacity:.6}.s{margin-top:12px;font-size:.92rem}.bad{color:#b42318}.ok{color:#067647}.m{color:#5b6475;font-size:.88rem}
@media (prefers-color-scheme: dark){body{background:#12151b;color:#e6e9ef}main{background:#1b2029;border-color:#2c3340}input{background:#12151b;color:#e6e9ef;border-color:#3a4252}.m{color:#9aa3b2}}
</style></head><body><main>
<h1>This server is waiting to be unlocked</h1>
<p><strong>{{HOST}}</strong> has restarted, and its data is encrypted. It opens with the recovery key kept in your password manager.</p>
<p class="m">The key stays in this browser: only a value that opens this server's sealed key is sent. If this server has a management node, unlock it from there instead.</p>
<label for="k">Recovery key</label>
<input id="k" type="password" autocomplete="off" spellcheck="false" placeholder="44 characters of base64">
<button id="b" type="button">Unlock</button>
<div id="s" class="s" role="status"></div>
<noscript><p class="bad">This page needs JavaScript to keep the key in your browser.</p></noscript>
</main>
{{XWING}}<script>
(function(){'use strict';
var c={{CONFIG}};var subtle=window.crypto&&window.crypto.subtle;
var k=document.getElementById('k'),b=document.getElementById('b'),s=document.getElementById('s');
var PKCS8=[0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x6e,0x04,0x22,0x04,0x20];
function d(x){var t=atob(String(x).replace(/\s+/g,''));var o=new Uint8Array(t.length);for(var i=0;i<t.length;i++)o[i]=t.charCodeAt(i);return o;}
function e(x){var t='';x=new Uint8Array(x);for(var i=0;i<x.length;i++)t+=String.fromCharCode(x[i]);return btoa(t);}
function du(x){x=String(x).replace(/-/g,'+').replace(/_/g,'/');while(x.length%4)x+='=';return d(x);}
function h(x){return Array.prototype.map.call(new Uint8Array(x),function(v){return('0'+v.toString(16)).slice(-2);}).join('');}
function say(m,ok){s.textContent=m;s.className='s '+(ok?'ok':'bad');}
async function work(p){
 if(!subtle)throw new Error('This browser has no WebCrypto. Use a current Chrome, Firefox or Safari.');
 var priv;try{priv=d(p);}catch(x){throw new Error('That is not a recovery key: it is one line of base64.');}
 if(priv.length!==32)throw new Error('That is not a recovery key: expected 32 bytes, got '+priv.length+'.');
 if(c.ciphertext){
  var X=window.JoineryPQ&&window.JoineryPQ.xwing;if(!X){priv.fill(0);throw new Error('This page could not load its encryption code. Reload it.');}
  var kp=X.keygen(priv),xp=new Uint8Array(kp.publicKey);if(kp.secretKey&&kp.secretKey!==priv)kp.secretKey.fill(0);
  var xf=h(await subtle.digest('SHA-256',xp));
  if(xf!==c.fingerprint){priv.fill(0);throw new Error('That recovery key has fingerprint '+xf.slice(0,16)+', and this server is sealed to '+c.fingerprint.slice(0,16)+'.');}
  var ss=new Uint8Array(X.decapsulate(d(c.ciphertext),priv));priv.fill(0);
  var hk=await subtle.importKey('raw',ss,'HKDF',false,['deriveBits']);ss.fill(0);
  var dk=new Uint8Array(await subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:new Uint8Array(0),info:new TextEncoder().encode('joinery-seal:v2:dek')},hk,256));
  var out={shared:e(dk),public_key:e(xp)};dk.fill(0);return out;}
 var pk=new Uint8Array(48);pk.set(PKCS8,0);pk.set(priv,16);priv.fill(0);var key;
 try{key=await subtle.importKey('pkcs8',pk,{name:'X25519'},true,['deriveBits']);}catch(x){throw new Error('This browser cannot do X25519. Use a current Chrome, Firefox or Safari.');}finally{pk.fill(0);}
 var j=await subtle.exportKey('jwk',key);var pub=du(j.x);j.d='';
 var fp=h(await subtle.digest('SHA-256',pub));
 if(fp!==c.fingerprint)throw new Error('That recovery key has fingerprint '+fp.slice(0,16)+', and this server is sealed to '+c.fingerprint.slice(0,16)+'.');
 var eph=await subtle.importKey('raw',d(c.ephemeralPublic),{name:'X25519'},false,[]);
 var sh=await subtle.deriveBits({name:'X25519',public:eph},key,256);
 return{shared:e(sh),public_key:e(pub)};}
b.addEventListener('click',function(){var p=k.value.trim();if(!p){say('Paste the recovery key first.',false);return;}
 b.disabled=true;say('Working in this browser…',true);
 work(p).then(function(r){k.value='';return fetch(c.post,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(r)});})
 .then(function(resp){return resp.json();}).then(function(a){say(a.message,a.ok);if(a.ok){setTimeout(function(){location.reload();},45000);}else{b.disabled=false;}})
 .catch(function(x){say(x.message||String(x),false);b.disabled=false;});});
})();
</script></body></html>`
