package primitives

import (
	"regexp"
	"time"
)

// publish_upgrade: build, sign and record this management node's release from
// its own tree — the core archive, every theme and plugin archive, the agent
// bundle, and the signed manifests every node verifies its scripts against.
//
// This is the one operate primitive that only ever runs on a management node,
// and it exists so that a publish is a job of the plane's OWN agent rather than
// of a plane-local queue (specs/agent_local_queue_retirement.md, G1). The
// plane pairs to itself like any other node; the Publish form dispatches this
// to that node; the agent verifies publish_upgrade.php against the release
// manifest and runs it as root. The fleet trust root — config/agent_signing_key
// — is 600 root:root on a publishing box, so root inside this primitive is the
// only reader it has, and there is no longer a database-writable queue through
// which a root process could be asked to read it.
//
// TWO PARAMETERS, both of which are what the operator typed on the form. The
// version is required rather than auto-detected here because publish_upgrade.php
// reads its first argument as a version only when it LOOKS like one, and the
// second as the notes; with the version always present, argv is unambiguous and
// release notes that happen to read "1.2" cannot be taken for a number. The
// publisher itself still decides whether this box may mint that number
// (DeploymentHelper::mayMintReleaseVersion) and refuses a duplicate or a
// downgrade, so the vocabulary bounds the shape and the script keeps the rules.
//
// The notes are bounded and free-form: they travel as one argv element, never
// through a shell, so there is nothing to escape.
func init() {
	Register(Primitive{
		Name:        "publish_upgrade",
		Class:       ClassOperate,
		Description: "Build and sign this management node's release archives from its own tree.",
		Params: []ParamSpec{
			{Name: "version", Type: ParamString, Required: true, MaxLen: 32, Pattern: releaseVersionPattern},
			{Name: "notes", Type: ParamString, Required: true, MaxLen: publishNotesMaxLen},
		},
		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",
			// Ships with the server_manager plugin; verified against the site
			// root's manifest, which covers every plugin file, before it runs.
			ScriptPath: publishScript,
			Args:       []string{"{version}", "{notes}"},
		},
		// A publish gates on the deploy-tier tests, cross-compiles the agent
		// for two architectures when its source moved, builds the relay
		// sealer, tars a 47 MB core archive and every theme and plugin, and
		// signs each manifest. Observed runs are a minute or two; the agent
		// rebuild is the part that can be ten. The plane's claim budget
		// (ManagementJob::PRIMITIVE_CLAIM_BUDGETS) stays above this, and
		// primitive_transport_parity_test fails the build if it does not.
		Timeout: 20 * time.Minute,
	})
}

// publishScript is the platform publisher, site-root relative. A constant so
// the test asserts the string the registration uses rather than a copy of it.
const publishScript = "public_html/plugins/server_manager/includes/publish_upgrade.php"

// publishNotesMaxLen bounds the release notes. The form's textarea has no
// ceiling of its own; this is generous for notes and far below the params
// byte cap the plane and node both enforce.
const publishNotesMaxLen = 4000

// releaseVersionPattern is the full three-part release number and nothing
// else — no "v", no two-part form, no suffix. publish_upgrade.php accepts a
// two-part number at the CLI and fills the patch itself, but a job should say
// exactly what it is publishing.
var releaseVersionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
