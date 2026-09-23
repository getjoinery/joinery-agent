package primitives

import (
	"encoding/json"
	"regexp"
	"time"
)

// restore_objects: bring a backup's offloaded files home, one page at a time.
//
// WHY THIS EXISTS. A file the site offloaded to its file bucket is in no
// archive: the backup holds it once, on the shelf under objects/{epoch}/,
// encrypted under an epoch key and named by the run's index. restore_chain
// puts the archives and the database back; this puts those files back where
// the site expects them — the ones the file bucket cannot serve (missing) or
// every one of them (all) — after the database is loaded, because the row is
// what says where each file belongs and how big it is
// (specs/implemented/backup_offloaded_files.md § Restore).
//
// PAGED, AND THE PLANE DRIVES THE LOOP. A presigned link is a few hundred
// bytes and a job is bounded, so a store of ten thousand files is many small
// jobs. The first job carries no object links: it is a SURVEY, and the node
// answers with the names it would bring home (RESTORE_OBJECTS_WANT, capped).
// The plane signs a page of links from that answer and sends it here; the
// result of each page is what issues the next. A page names only what the
// index marks stored — the node refuses anything else as a request that does
// not match the run.
//
// ClassOperate, and the classification is doing real work. The script
// overwrites nothing (a file already at the placement is adopted when it
// matches its row, refused by name when it does not) and deletes nothing in
// any bucket; a row is set to local only once its bytes are in place and
// checked. That is exactly the shape of the drain flow the platform already
// runs unattended as a scheduled task, so a page needs no approval and the
// plane's loop needs none either.
//
// NO KEY CROSSES: each epoch's envelope arrives by link and opens with this
// machine's own config/backup_site_key. NO BUCKET CREDENTIAL CROSSES: links,
// one object each, expiring. There is no parameter below through which
// either could arrive. The index itself is fetched by link and checked
// against this node's upload ledger before anything else is trusted.
func init() {
	Register(Primitive{
		Name:        "restore_objects",
		Class:       ClassOperate,
		Description: "Bring one page of a backup's offloaded files home from the shelf, or survey which ones need bringing.",
		Params: []ParamSpec{
			// The chain, by id — the same pattern stage_chain binds, for the
			// same reason: it becomes a directory name on the node.
			{Name: "chain_id", Type: ParamString, Required: true, MaxLen: 64,
				Pattern: regexp.MustCompile(`^chain-[0-9_]+$`)},

			// Which shelf the chain came from, which decides which ledger
			// the index is checked against.
			{Name: "profile", Type: ParamEnum, Required: true,
				Values: []string{"site", "manager"}},

			// The run whose index names the files. Required, unlike
			// stage_chain's: the index is one artifact of one run, and the
			// node does not read the manifest here to pick a newest.
			{Name: "seq", Type: ParamInt, Required: true, Min: 0, Max: 100000},

			// missing brings home only what the file bucket cannot serve;
			// all brings every offloaded file home.
			{Name: "mode", Type: ParamEnum, Required: true,
				Values: []string{"missing", "all"}},

			// The run's index, by signed link. Fetched first and
			// ledger-checked: it is what every object is verified against.
			{Name: "index_url", Type: ParamString, Required: true, MaxLen: 2048,
				Pattern: signedURLPattern},

			// The epoch envelopes the page's objects are sealed under, keyed
			// by epoch id (backup_run's map, same bounds), and the page
			// itself, keyed by the object's bare name in the index and
			// bounded at one page. Both absent on a survey.
			{Name: "epoch_envelope_urls", Type: ParamMap,
				MaxEntries: 64, MaxKeyLen: 32, MaxLen: 2048,
				KeyPattern: epochIDPattern,
				Pattern:    signedURLPattern},
			{Name: "object_urls", Type: ParamMap,
				MaxEntries: restoreObjectsPageMax, MaxKeyLen: 255, MaxLen: 2048,
				KeyPattern: backupFileName,
				Pattern:    signedURLPattern},
		},
		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",
			ScriptPath:  "public_html/utils/restore_objects.php",
			Args:        nil,
			StdinFrom:   restoreObjectsConfig,
		},
		// A page is at most a job's worth of links, fetched and decrypted one
		// at a time; a survey is one index and a HEAD per offloaded file. Two
		// hours bounds a page of large files on a slow link and still bounds
		// one that has hung.
		Timeout: 2 * time.Hour,
	})
}

// restoreObjectsPageMax is the most objects one page may name:
// BackupStaging::MAX_OBJECT_LINKS, byte for byte. The plane fills a page to
// the job's byte ceiling, which is reached well before this count.
const restoreObjectsPageMax = 150

// restoreObjectsConfig renders the script's configuration from validated params.
func restoreObjectsConfig(params Params) (string, error) {
	config := map[string]interface{}{
		"chain_id":  params.String("chain_id"),
		"profile":   params.String("profile"),
		"seq":       params.Int("seq"),
		"mode":      params.String("mode"),
		"index_url": params.String("index_url"),
	}
	// Absent means a survey; the script answers with what it would bring
	// home rather than bringing anything.
	if params.Has("epoch_envelope_urls") {
		config["epoch_envelope_urls"] = params.Map("epoch_envelope_urls")
	}
	if params.Has("object_urls") {
		config["object_urls"] = params.Map("object_urls")
	}

	body, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
