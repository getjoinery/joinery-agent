package primitives

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The certificate collector answers the question the SSH job's fourth step
// asked, but as a fact about the node rather than a verdict on a job. What it
// must get right is the expiry, and which lineage Apache is actually serving.

var certRefTime = time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

// makeCert writes a fullchain.pem for one lineage. issuerCN empty means
// self-signed; otherwise a throwaway CA with that common name signs it.
func makeCert(t *testing.T, dir, lineage, issuerCN string, notAfter time.Time, dnsNames ...string) {
	t.Helper()

	leafPub, leafPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: lineage},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
	}

	parent, signer := template, leafPriv
	if issuerCN != "" {
		caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		caTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(2),
			Subject:               pkix.Name{CommonName: issuerCN},
			NotBefore:             template.NotBefore,
			NotAfter:              notAfter.Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
		if err != nil {
			t.Fatal(err)
		}
		ca, err := x509.ParseCertificate(caDER)
		if err != nil {
			t.Fatal(err)
		}
		parent, signer = ca, caPriv
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, leafPub, signer)
	if err != nil {
		t.Fatal(err)
	}

	lineageDir := filepath.Join(dir, lineage)
	if err := os.MkdirAll(lineageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(lineageDir, "fullchain.pem"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func collectCerts(t *testing.T, dir string) map[string]interface{} {
	t.Helper()
	result := map[string]interface{}{}
	collectCertificates(dir, certRefTime, result)
	return result
}

func certList(t *testing.T, result map[string]interface{}) []map[string]interface{} {
	t.Helper()
	certs, ok := result["ssl_certificates"].([]map[string]interface{})
	if !ok {
		t.Fatalf("no certificate list in %v", result)
	}
	return certs
}

func TestANodeWithNoCertbotReportsZeroRatherThanSilence(t *testing.T) {
	// Zero is an answer; a missing key is not. The plane distinguishes "this
	// node has no origin certificate" (normal behind Cloudflare) from "this
	// collector said nothing", and it can only do that if the node says zero.
	result := collectCerts(t, filepath.Join(t.TempDir(), "nothing-here"))

	if result["ssl_certificate_count"] != 0 {
		t.Errorf("expected a count of zero, got %v", result["ssl_certificate_count"])
	}
	if _, present := result["ssl_certificates_unreadable"]; present {
		t.Error("an absent directory is not an unreadable one")
	}
}

func TestADirectoryRootCannotReadIsReportedAsSuch(t *testing.T) {
	// The agent is root and this directory is root-only, so a read failure here
	// means something is wrong with the node — not that it has no certificates.
	// Rendering it as an absence would report a healthy-looking zero.
	if os.Geteuid() == 0 {
		t.Skip("running as root, which can read a 0000 directory")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Skip("cannot make an unreadable directory here")
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	result := collectCerts(t, dir)
	if result["ssl_certificates_unreadable"] != true {
		t.Error("an unreadable certificate directory must not read as zero certificates")
	}
	if _, present := result["ssl_certificate_count"]; present {
		t.Error("a count implies a successful look")
	}
}

func TestACertificateReportsWhenItRunsOut(t *testing.T) {
	dir := t.TempDir()
	makeCert(t, dir, "dev.getjoinery.com", "Let's Encrypt R3",
		certRefTime.Add(30*24*time.Hour), "dev.getjoinery.com", "www.dev.getjoinery.com")

	result := collectCerts(t, dir)
	if result["ssl_certificate_count"] != 1 {
		t.Fatalf("expected one certificate, got %v", result["ssl_certificate_count"])
	}
	cert := certList(t, result)[0]

	if cert["name"] != "dev.getjoinery.com" {
		t.Errorf("lineage name is %v", cert["name"])
	}
	if cert["expires_in_days"] != 30 {
		t.Errorf("expected 30 days remaining, got %v", cert["expires_in_days"])
	}
	if cert["expired"] != false {
		t.Error("a certificate with 30 days left is not expired")
	}
	if cert["self_signed"] != false {
		t.Error("a CA-issued certificate is not self-signed")
	}
	if cert["issuer"] != "Let's Encrypt R3" {
		t.Errorf("issuer is %v", cert["issuer"])
	}
	if result["ssl_soonest_expiry_days"] != 30 {
		t.Errorf("the rollup should carry the same number, got %v", result["ssl_soonest_expiry_days"])
	}
	if _, ok := result["ssl_soonest_expiry"].(string); !ok {
		t.Error("the rollup should carry a date as well as a count of days")
	}
}

func TestAnExpiredCertificateSaysSoRatherThanCountingDownFromZero(t *testing.T) {
	// A certificate that lapsed is still on disk and Apache is still serving
	// it, because <IfFile> only asks whether the file exists. "Expired" is the
	// state, and the day count going negative is how far past it is.
	dir := t.TempDir()
	makeCert(t, dir, "lapsed.example.com", "Let's Encrypt R3", certRefTime.Add(-3*24*time.Hour))

	cert := certList(t, collectCerts(t, dir))[0]
	if cert["expired"] != true {
		t.Error("a certificate three days past its NotAfter is expired")
	}
	if days := cert["expires_in_days"].(int); days > 0 {
		t.Errorf("an expired certificate should not report %d days remaining", days)
	}
}

func TestTheStaleLineageApacheIsStillServingIsVisible(t *testing.T) {
	// The failure the old one-domain check could not see. certbot re-issuing
	// into a fresh lineage writes {domain}-0001 and leaves the vhost pointing at
	// {domain}, so the node holds a current certificate it is not serving and a
	// stale one it is. Asked about one name, that looks fine. Listed, it does
	// not.
	dir := t.TempDir()
	makeCert(t, dir, "example.com", "Let's Encrypt R3", certRefTime.Add(5*24*time.Hour))
	makeCert(t, dir, "example.com-0001", "Let's Encrypt R3", certRefTime.Add(89*24*time.Hour))

	result := collectCerts(t, dir)
	if result["ssl_certificate_count"] != 2 {
		t.Fatalf("both lineages should be reported, got %v", result["ssl_certificate_count"])
	}

	certs := certList(t, result)
	if certs[0]["name"] != "example.com" {
		t.Errorf("soonest-to-expire should sort first, got %v", certs[0]["name"])
	}
	if result["ssl_soonest_expiry_days"] != 5 {
		t.Errorf("the rollup must be the SOONEST expiry, not any certificate's: %v", result["ssl_soonest_expiry_days"])
	}
}

func TestASelfSignedPlaceholderIsNotReportedAsWorkingTls(t *testing.T) {
	// It exists, Apache serves it, and no browser trusts it. Reported as a
	// certificate with nothing else said, it would read as "TLS is fine here".
	dir := t.TempDir()
	makeCert(t, dir, "placeholder.example.com", "", certRefTime.Add(3650*24*time.Hour))

	cert := certList(t, collectCerts(t, dir))[0]
	if cert["self_signed"] != true {
		t.Error("a certificate that issued itself is self-signed")
	}
}

func TestOneUnreadableLineageDoesNotCostTheOthers(t *testing.T) {
	// A file caught mid-renewal, or an empty lineage directory, is a reason to
	// say nothing about THAT lineage — not a reason for the node to report no
	// certificates while holding several.
	dir := t.TempDir()
	makeCert(t, dir, "good.example.com", "Let's Encrypt R3", certRefTime.Add(30*24*time.Hour))
	if err := os.MkdirAll(filepath.Join(dir, "empty.example.com"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "empty.example.com", "fullchain.pem"),
		[]byte("-----BEGIN CERTIFICATE-----\ntruncated"), 0o600); err != nil {
		t.Fatal(err)
	}

	result := collectCerts(t, dir)
	if result["ssl_certificate_count"] != 1 {
		t.Errorf("the readable lineage should still be reported, got %v", result["ssl_certificate_count"])
	}
}

func TestTheCertbotSymlinkIsFollowed(t *testing.T) {
	// live/{domain}/fullchain.pem is a symlink into ../../archive — that is how
	// certbot maintains it. Applying the probe primitives' refuse-a-symlink rule
	// here would report every certbot-managed certificate as missing. Reading a
	// root-only directory is not the same act as writing into a web-writable one.
	dir := t.TempDir()
	archive := t.TempDir()
	makeCert(t, archive, "linked.example.com", "Let's Encrypt R3", certRefTime.Add(45*24*time.Hour))

	lineage := filepath.Join(dir, "linked.example.com")
	if err := os.MkdirAll(lineage, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(archive, "linked.example.com", "fullchain.pem"),
		filepath.Join(lineage, "fullchain.pem")); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}

	result := collectCerts(t, dir)
	if result["ssl_certificate_count"] != 1 {
		t.Fatalf("the symlinked certificate should be read, got %v", result["ssl_certificate_count"])
	}
	if certList(t, result)[0]["expires_in_days"] != 45 {
		t.Error("the linked certificate's expiry should be the one reported")
	}
}

func TestAnUnusualNumberOfLineagesIsCappedAndSaysSo(t *testing.T) {
	// The result travels inside a body the plane caps. A truncated answer that
	// admits it is better than a whole one the far end refuses.
	dir := t.TempDir()
	for i := 0; i < maxReportedCertificates+5; i++ {
		makeCert(t, dir, fmt.Sprintf("site%02d.example.com", i), "Let's Encrypt R3",
			certRefTime.Add(time.Duration(30+i)*24*time.Hour))
	}

	result := collectCerts(t, dir)
	if result["ssl_certificate_count"] != maxReportedCertificates {
		t.Errorf("expected the cap, got %v", result["ssl_certificate_count"])
	}
	if result["ssl_certificates_truncated"] != true {
		t.Error("a truncated list must say it was truncated, or it reads as the whole answer")
	}
}

func TestManyNamesOnOneCertificateAreCapped(t *testing.T) {
	dir := t.TempDir()
	names := make([]string, maxReportedDomains+3)
	for i := range names {
		names[i] = fmt.Sprintf("alt%02d.example.com", i)
	}
	makeCert(t, dir, "many.example.com", "Let's Encrypt R3", certRefTime.Add(30*24*time.Hour), names...)

	cert := certList(t, collectCerts(t, dir))[0]
	got := cert["domains"].([]string)
	if len(got) != maxReportedDomains {
		t.Errorf("expected %d names, got %d", maxReportedDomains, len(got))
	}
	if cert["domains_truncated"] != true {
		t.Error("the truncation should be stated")
	}
}

func TestCheckStatusStillTakesNoParameters(t *testing.T) {
	// The collector grew; the vocabulary must not have.
	p, ok := Lookup("check_status")
	if !ok {
		t.Fatal("check_status should be registered")
	}
	if len(p.Params) != 0 {
		t.Errorf("check_status declares %d parameter(s); it takes none", len(p.Params))
	}
	if _, err := Validate(p.Params, map[string]interface{}{"domain": "example.com"}); err == nil {
		t.Error("check_status must not have gained a domain parameter — the node enumerates, " +
			"it is not told which name to look for")
	}
}

// A machine with no database at all is not a machine whose database is down,
// and check_status must not say it is.
//
// ExecEnv.DB carries that distinction: nil means "there is nothing here to
// ask", a set provider that fails means "there is something here and it is
// broken". Conflating them would make every siteless machine — a relay, a
// Docker host — report a PostgreSQL fault on every status check, which is a
// false alarm on a machine that was never going to have a database (spec A13).
func TestNoDatabaseIsNotABrokenDatabase(t *testing.T) {
	root := t.TempDir()

	absent, err := runCheckStatus(context.Background(),
		&ExecEnv{SiteRoot: root, WebRoot: root, DB: nil}, Params{})
	if err != nil {
		t.Fatalf("a machine with no database still has a health report: %v", err)
	}
	if _, said := absent["postgres_status"]; said {
		t.Errorf("a machine with no database reported postgres_status=%v; it should say nothing about a database it does not have",
			absent["postgres_status"])
	}

	broken, err := runCheckStatus(context.Background(),
		&ExecEnv{SiteRoot: root, WebRoot: root, DB: func() (*sql.DB, error) {
			return nil, errors.New("connection refused")
		}}, Params{})
	if err != nil {
		t.Fatalf("an unreachable database is a finding, not an error: %v", err)
	}
	if broken["postgres_status"] != "not accepting connections" {
		t.Errorf("a node whose database is down should report it, got %v", broken["postgres_status"])
	}
}
