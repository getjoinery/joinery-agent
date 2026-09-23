package redact

import (
	"strings"
	"testing"
)

// Rule 2 of specs/agent_recipes_and_vocabulary.md: the redactor carries the
// configuration shape with a test for each file file_head may read. Each case
// is that file's own syntax, with a planted credential where the file could
// hold one, and the lines a diagnosis needs, which must pass untouched.
var configFiles = map[string][]struct{ in, want string }{
	"fail2ban jail.local / jail.d/*.local": {
		{"[sshd]", "[sshd]"},
		{"enabled = true", "enabled = true"},
		{"bantime  = 1h", "bantime  = 1h"},
		{"ignoreip = 127.0.0.1/8 203.0.113.5", "ignoreip = 127.0.0.1/8 203.0.113.5"},
		{"destemail = ops@example.com", "destemail = <email>@example.com"},
	},
	"apache {site}.conf / -le-ssl.conf / apache2.conf / mpm_event.conf / joinery-remoteip.conf": {
		{"<VirtualHost 69.164.209.253:80>", "<VirtualHost 69.164.209.253:80>"},
		{"        ServerName dev.getjoinery.com", "        ServerName dev.getjoinery.com"},
		{"        SSLCertificateKeyFile /etc/letsencrypt/live/x/privkey.pem", "        SSLCertificateKeyFile /etc/letsencrypt/live/x/privkey.pem"},
		{"    ProxyPass / http://127.0.0.1:8081/", "    ProxyPass / http://127.0.0.1:8081/"},
		{"    RemoteIPTrustedProxy 173.245.48.0/20", "    RemoteIPTrustedProxy 173.245.48.0/20"},
		{"    SetEnv DB_PASSWORD hunter2", "    SetEnv DB_PASSWORD ********"},
		{"    MaxRequestWorkers 150", "    MaxRequestWorkers 150"},
		{"    ServerAdmin webmaster@example.com", "    ServerAdmin <email>@example.com"},
		{"    ProxyPass /x http://user:hunter2@10.0.0.2/", "    ProxyPass /x http://user:********@10.0.0.2/"},
	},
	"php.ini": {
		{"memory_limit = 256M", "memory_limit = 256M"},
		{"mysqli.default_pw =", "mysqli.default_pw"},
		{"session.save_path = \"/var/lib/php/sessions\"", "session.save_path = \"/var/lib/php/sessions\""},
		{";upload_max_filesize = 2M", ";upload_max_filesize = 2M"},
	},
	"journald size-limit.conf / logrotate / cron.d": {
		{"SystemMaxUse=500M", "SystemMaxUse=500M"},
		{"    rotate 14", "    rotate 14"},
		{"*/5 * * * * www-data php /var/www/html/x/public_html/utils/cron.php", "*/5 * * * * www-data php /var/www/html/x/public_html/utils/cron.php"},
		{"MAILTO=root@example.com", "MAILTO=<email>@example.com"},
	},
	"apt 20auto-upgrades / 50unattended-upgrades": {
		{`APT::Periodic::Unattended-Upgrade "1";`, `APT::Periodic::Unattended-Upgrade "1";`},
		{`Unattended-Upgrade::Mail "admin@example.com";`, `Unattended-Upgrade::Mail "<email>@example.com";`},
	},
	"docker daemon.json": {
		{`  "log-driver": "json-file",`, `  "log-driver": "json-file",`},
		{`  "registry-token": "abc",`, `  "registry-token"`},
	},
	"sysctl 99-security.conf": {
		{"net.ipv4.tcp_syncookies = 1", "net.ipv4.tcp_syncookies = 1"},
	},
	"postfix main.cf / master.cf": {
		{"myhostname = mail.example.com", "myhostname = mail.example.com"},
		{"mynetworks = 127.0.0.0/8 [::1]/128", "mynetworks = 127.0.0.0/8 [::1]/128"},
		{"smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd", "smtp_sasl_password_maps"},
		{"virtual_alias_maps = pgsql:/etc/postfix/joinery-domains.cf", "virtual_alias_maps = pgsql:/etc/postfix/joinery-domains.cf"},
		{"smtp      inet  n       -       y       -       -       smtpd", "smtp      inet  n       -       y       -       -       smtpd"},
		{"  -o smtpd_sasl_auth_enable=yes", "  -o smtpd_sasl_auth_enable=yes"},
		{"  -o smtp_sasl_password=hunter2", "  -o smtp_sasl_password=********"},
	},
	"opendkim.conf / opendmarc.conf": {
		{"KeyTable        refile:/etc/opendkim/key.table", "KeyTable        refile:/etc/opendkim/key.table"},
		{"Socket          inet:8891@localhost", "Socket          inet:8891@localhost"},
		{"AuthservID      mail.example.com", "AuthservID      mail.example.com"},
	},
	"rspamd local.d actions / classifier-bayes / milter_headers / redis / worker-proxy": {
		{"reject = 15;", "reject = 15;"},
		{`servers = "127.0.0.1:6379";`, `servers = "127.0.0.1:6379";`},
		{`password = "hunter2";`, "password"},
		{`  password: "hunter2"`, "  password"},
		{`# password = "old";`, "# password"},
		{`bind_socket = "localhost:11332";`, `bind_socket = "localhost:11332";`},
		{`  "token": "abc"`, `  "token"`},
	},
}

func TestConfigShapeForEveryReadableFile(t *testing.T) {
	for file, cases := range configFiles {
		for _, c := range cases {
			if got := Config(c.in); got != c.want {
				t.Errorf("%s: Config(%q) = %q, want %q", file, c.in, got, c.want)
			}
		}
	}
}

// Whatever the separator or the quoting, a secret key's value never survives.
// Review B1/B2 (2026-09-23): a second setting on one line, a `key = "value"`
// separator, and the secret-key names the whole-line rule knows (api keys,
// application keys, fail2ban's cfapikey) are all masked mid-line.
func TestConfigMasksEverySecretPairOnALine(t *testing.T) {
	for _, line := range []string{
		`hosts = "127.0.0.1:6379"; password = "hunter2"`,
		`servers = "a"; password: hunter2`,
		`SetEnv STRIPE_API_KEY hunter2`,
		`SetEnv B2_APPLICATION_KEY hunter2`,
		`action = cloudflare[cfuser="joe", cfapikey="hunter2"]`,
		`action = blocklist_de[email="a@b", apikey="hunter2", service=ssh]`,
		`action = x[cftoken=hunter2]`,
		`opt = 1, private_key = hunter2`,
		`db_pw hunter2`,
	} {
		got := Config(line)
		if strings.Contains(got, "hunter2") {
			t.Errorf("Config(%q) = %q carries the value", line, got)
		}
	}
	if got := Config(`action = cloudflare[cfuser="joe"]`); !strings.Contains(got, "cloudflare") {
		t.Errorf("a non-secret pair must stay readable, got %q", got)
	}
}

// A secret named mid-line, after a directive, never carries its value either.
func TestConfigMasksASecretLaterInTheLine(t *testing.T) {
	for _, line := range []string{
		"SetEnv DB_PASSWORD hunter2",
		"PassEnv x; SetEnv API_TOKEN=hunter2",
		"  -o smtp_sasl_password=hunter2",
		"Header set X-Secret \"hunter2\"",
	} {
		if strings.Contains(Config(line), "hunter2") {
			t.Errorf("Config(%q) = %q carries the value", line, Config(line))
		}
	}
}

func TestConfigNeverReturnsASecretValue(t *testing.T) {
	for _, sep := range []string{"=", " = ", ": ", ":", " ", "\t", "  =  "} {
		for _, key := range []string{"password", "Password", "db_password", "api_token", "client_secret", "SSLPassPhrase", "private_key", "secret_key", "api_key", "\"password\"", "'token'"} {
			for _, val := range []string{"hunter2", "\"hunter2\"", "'hunter2'", "hunter2;", "{hunter2}"} {
				line := key + sep + val
				if strings.Contains(Config(line), "hunter2") {
					t.Errorf("Config(%q) = %q carries the value", line, Config(line))
				}
			}
		}
	}
}
