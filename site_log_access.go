package main

// Whether one container site on this host allows log access: that site's own
// agent_log_access switch, read from that site's own database. A word that
// reads one co-resident site (site_converger) asks this instead of the host,
// because the site's owner, not the host's, decides who reads that site
// (primitives/log_access.go).
//
// The site is located exactly as a decommission locates its victim
// (victim.go): the host-owned vhost names the published ports, and the site's
// config volume holds its database credential, read without following a link
// and held in memory only. Nothing runs inside the container.
//
// Fail closed, as on the site itself: a row that is missing reads OFF, and a
// database that does not answer is a refusal that says so.

import (
	"context"
	"regexp"

	"joinery-agent/primitives"
)

var siteLogAccessName = regexp.MustCompile(`^[a-z0-9_-]{1,50}$`)

// siteLogAccess is ExecEnv.SiteLogAccess on every machine. A var so a test can
// stand in for the container site.
var siteLogAccess = func(ctx context.Context, site string) (bool, error) {
	// Belt to the validator's braces: nothing below composes a path from a
	// name this did not accept.
	if !siteLogAccessName.MatchString(site) {
		return false, &primitives.RefusalError{Reason: "the site name is not one this host composes paths from"}
	}
	db, _, err := openVictimDB(ctx, site, "it cannot say whether its owner allows log access, and nothing of it is read")
	if err != nil {
		return false, err
	}
	defer db.Close()
	value, err := victimSettings{db: db, ctx: ctx}.Read(primitives.SettingLogAccess)
	if err != nil {
		return false, err
	}
	return primitives.SettingOn(value), nil
}
