package primitives

import (
	"context"
	"strings"
	"time"
)

// site_certificate_stage {action: stage|clear, name, domain}: one of this host's
// site containers' certificate, handed to the site's copy
// (specs/site_copy_anything_to_anything.md D4).
//
// A container site's certificate lineage lives on its host, which ends TLS for
// it. The copy's export is made by the site's own agent inside the container
// (copy_export), and its host bundle (copy_host.go) reads the container's
// /etc/letsencrypt, which holds none, so the copy started on a self-signed
// certificate. For the export's span the host stages the site's own lineage
// into the container: the export then carries it as it carries a bare-metal
// site's, sealed to the copy, signed by the site's agent and approved by the
// site's owner on its own Backups page. Nothing new is trusted on the copy.
//
//   - stage copies every lineage on the host whose certificate names the
//     site's domain or its www. and nothing else: the live links, the archive
//     files they point at and the renewal conf, without its account line.
//     The ACME account is the host's, shared by every site there, and never
//     leaves it; the copy issues under its own. A lineage naming the site
//     beside any other name is refused.
//   - clear removes from the container exactly what stage wrote (the host
//     records it), so the key does not stay in the container's layer.
//
// A SCRIPT WORD: maintenance_scripts/sysadmin_tools/site_certificate_stage.sh,
// verified against the signed manifest (on a host, the support bundle's), with
// an argv composed here from validated values.
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word? Put
// a site's own certificate and key inside that site's own container, root-owned
// and 0600, where its owner could put them anyway. It cannot read them: the
// word reports only what it staged, by name. It cannot hand one site's key to
// another's container: the script stages a lineage only when every name it
// covers is the given domain or its www., and only when that domain is the one
// the host itself serves the named container at (the host's vhost for it, else
// the DOMAIN_NAME the host gave the container), so naming site A's container
// with site B's domain stages nothing. Accepted.
//
// What it cannot do:
//
//   - Move the host's ACME account, or any DNS-01 credential, anywhere.
//   - Name a container that is not one of this host's Joinery sites (the
//     script's own_container test, as site_quiet_host's).
//   - Write outside the container's /etc/letsencrypt, or anything but the
//     named lineages.
func init() {
	Register(Primitive{
		Name:        "site_certificate_stage",
		Class:       ClassOperate,
		Machine:     true,
		Description: "Stage one of this host's site containers' own certificate inside the container for its copy's export (stage: the lineage naming only the site's domain and www., without the host's ACME account), or remove what was staged (clear).",
		Params: []ParamSpec{
			{Name: "action", Type: ParamEnum, Required: true, Values: []string{"stage", "clear"}},
			{Name: "name", Type: ParamString, Required: true, MaxLen: 50, Pattern: holdContainerName},
			{Name: "domain", Type: ParamString, MaxLen: 253, Pattern: certificateDomainPattern},
		},
		Script: &ScriptSpec{
			Interpreter: "/bin/bash",
			ScriptPath:  siteCertificateStageScript,
			ArgsFrom:    siteCertificateStageArgv,
		},
		// Each engine call runs under a minute; a site has one or two lineages.
		Timeout: 3 * time.Minute,
	})
}

const siteCertificateStageScript = "maintenance_scripts/sysadmin_tools/site_certificate_stage.sh"

func siteCertificateStageArgv(_ context.Context, _ *ExecEnv, p Params) ([]string, error) {
	name := p.String("name")
	domain := strings.ToLower(p.String("domain"))
	if p.String("action") == "clear" {
		if domain != "" {
			return nil, refusedf("site_certificate_stage: clear takes no domain")
		}
		return []string{"clear", name}, nil
	}
	if domain == "" {
		return nil, refusedf("site_certificate_stage: stage names the site's domain")
	}
	return []string{"stage", name, domain}, nil
}
