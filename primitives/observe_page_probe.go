package primitives

import (
	"regexp"
	"time"
)

// page_probe {page, viewer}: render one of the node's own pages as a
// throwaway viewer and report facts about the render, never the render.
//
// specs/agent_recipes_and_vocabulary.md, Settled 2026-09-23. What runs is
// public_html/utils/page_probe.php, verified against the signed release
// manifest, with two argv elements validated here: the platform script
// re-validates both, and refuses a page that is not on the node's own list
// (its admin menu entries and public views) or that acts on arrival
// (PageProbe::REFUSED_PAGES).
//
// HOSTILE-CALLER REVIEW (rule 5).
//
// What is the worst a compromised management node can do with this word?
// Learn how one of the node's own pages renders: its status, size, timing,
// query count, memory, the file:line of any PHP warning, which theme or
// plugin assets fail, whether it has a header, main and footer, how many
// forms, and a hash of its tag tree. Size, query count and memory on an admin
// page loosely track how many rows the site holds; the owner accepted that
// aggregate. No row, no text, no HTML crosses.
//
// What it cannot do:
//
//   - Name a URL. `page` is a path of lowercase letters, digits, dashes,
//     underscores and slashes with no query string, and the node refuses one
//     that is not its own page.
//   - Render a page that acts on arrival (a sign-out, an OAuth return, a
//     wizard step): the node's compiled list refuses those.
//   - Borrow an account. The viewer is a throwaway user the node makes for
//     this one run and permanently deletes before the word returns; its
//     session lives for one request from this machine, with no cookie, and
//     cannot persist anything a user could ask for.
//   - Read a warning's text, which can carry a row's value: type and
//     file:line only.
//
// OBSERVE: it changes nothing a person would see. The throwaway user exists
// for the seconds of one render and is gone when the word returns; a probe
// that could not finish its cleanup says so, and the next probe sweeps it.
func init() {
	Register(Primitive{
		Name:        "page_probe",
		Class:       ClassObserve,
		Description: "Render one of the site's own pages as a throwaway anonymous, member or admin viewer and report status, size, timing, query count, memory, warning locations, failing assets, landmarks and a structure hash; never the page's text.",
		Params: []ParamSpec{
			{Name: "page", Type: ParamString, Required: true, MaxLen: 201, Pattern: pageProbePage},
			{Name: "viewer", Type: ParamEnum, Required: true, Values: []string{"anonymous", "member", "admin"}},
		},
		Script: &ScriptSpec{
			Interpreter: "/usr/bin/php",
			ScriptPath:  pageProbeScript,
			Args:        []string{"{page}", "{viewer}"},
			StdinFrom:   nil,
		},
		Timeout: 3 * time.Minute,
	})
}

// pageProbePage is a site path with no query string, no empty segment and no
// more than six segments, as PageProbe accepts.
var pageProbePage = regexp.MustCompile(`^/([a-z0-9_-]{1,80}(/[a-z0-9_-]{1,80}){0,5})?$`)

const pageProbeScript = "public_html/utils/page_probe.php"
