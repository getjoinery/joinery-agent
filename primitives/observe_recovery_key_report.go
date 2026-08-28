package primitives

// recovery_key_report: which backup recovery key this node holds.
//
// It exists because of a hole this transport had and could not see. Every backup
// of a node is gated on backup_recovery_state (RecoveryKeyFleet), and that fact
// comes from BackupRecoveryKey::key_report() — a PHP call the agent has no way
// to make. So a primitive check_status reported everything EXCEPT the one field
// backups depend on, and because the plane replaced the stored status blob
// wholesale, running one deleted the answer. Backups then refused fleet-wide
// with "not known yet", the nightly run included.
//
// The plane now carries unmeasured fields forward instead of deleting them, but
// carried is not measured: a node whose recovery key actually changed would go
// unnoticed for as long as only primitives ran. This primitive closes that by
// letting the node answer the question itself.
//
// IT INVOKES THE NODE'S OWN SHIPPED SCRIPT rather than reimplementing the
// classification in Go. set_recovery_key.php is reports-only by design (v2.0
// removed writing: a recovery key that arrives from outside cannot be verified
// by the site receiving it), it is listed in the signed release manifest, and
// the plane already parses its RECOVERY_KEY= line from the SSH path. A Go copy
// of "what counts as proven" would be a second definition of the one thing that
// decides whether a backup can be opened, and the two would drift.
//
// OBSERVE, not operate: --report writes nothing. The script's own header is the
// authority on that, and its write path no longer exists.
func init() {
	Register(Primitive{
		Name:        "recovery_key_report",
		Class:       ClassObserve,
		Description: "Which backup recovery key this node holds, from the node's own reporting tool.",
		Params:      nil,
		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",
			ScriptPath:  "maintenance_scripts/sysadmin_tools/set_recovery_key.php",
			// --report is the only mode this primitive may ask for. It is a
			// literal, not a parameter: a mode the plane could choose is a mode
			// a compromised plane could choose, and the other modes are gone
			// precisely because writing this key from outside is not safe.
			Args: []string{"--report"},
		},
	})
}
