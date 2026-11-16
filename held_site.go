package main

// The host's gate for decommission_held_site (specs/hosting_paid_launch.md
// B1): a container site on this host may be removed without its operator's
// approval once this host has held it stopped for HeldSiteMinAge.
//
// WHY THE HOST AND NOT THE PLANE. The approval on an ordinary removal exists
// so that the management node alone cannot destroy a site. A management node
// can stop and hold any container (hold_container), but the hold's time is
// this host's own record, written when the hold began and kept by a second
// stop (hold_container.sh), so a plane cannot make a site it stopped today
// look like one stopped two months ago. Its worst is to hold a site and wait
// the whole time out, during which the site's owner, the hold and the hosting
// banner all say so.
//
// THE CHECK, in order. Every doubt refuses:
//
//  1. The site has a vhost on this host (the same read as the moved proof),
//     so it is one of this host's own container sites.
//  2. Its hold exists, and its modification time is at least HeldSiteMinAge
//     ago and not in the future.
//  3. The engine reports the container not running.
//
// Both are checked when the statement is composed and again at the gate, the
// moment before the teardown runs.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"joinery-agent/primitives"
)

// heldSiteProber is the gate's reach into the host, as fields so the tests can
// stand in for the hold file, the engine and the clock.
type heldSiteProber struct {
	// locate reads the site's vhost (movedSiteProber.locate).
	locate func(site string) (movedSiteTarget, error)
	// holdTime is when the hold on the site began: its file's modification
	// time; os.ErrNotExist when the site is not held.
	holdTime func(site string) (time.Time, error)
	// stopped says the engine reports the container not running, with the
	// hold in place (heldStopped).
	stopped func(ctx context.Context, site string) (bool, error)
	now     func() time.Time
}

// heldSiteProofFor gates the check on posture, as movedSiteProofFor does.
func heldSiteProofFor(cfg *Config) func(context.Context, string) (primitives.ApprovalStatement, primitives.ApprovalGate, func(), error) {
	if cfg == nil || !cfg.Siteless {
		return nil
	}
	return defaultHeldSiteProber().ceremony
}

func defaultHeldSiteProber() heldSiteProber {
	moved := defaultMovedSiteProber()
	return heldSiteProber{
		locate: moved.locate,
		holdTime: func(site string) (time.Time, error) {
			fi, err := os.Stat(fmt.Sprintf(movedHeldPattern, site))
			if err != nil {
				return time.Time{}, err
			}
			return fi.ModTime(), nil
		},
		stopped: heldStopped,
		now:     time.Now,
	}
}

func (h heldSiteProber) ceremony(ctx context.Context, site string) (primitives.ApprovalStatement, primitives.ApprovalGate, func(), error) {
	none := primitives.ApprovalStatement{}
	t, err := h.locate(site)
	if err != nil {
		if errors.Is(err, errNoVhost) {
			return none, nil, nil, &primitives.RefusalError{Reason: strings.TrimPrefix(err.Error(), errNoVhost.Error()+": ")}
		}
		return none, nil, nil, err
	}
	since, why := h.check(ctx, site)
	if why != "" {
		return none, nil, nil, &primitives.RefusalError{Reason: why + " Nothing was removed."}
	}
	statement := primitives.ApprovalStatement{
		Primitive: "decommission_held_site",
		Summary: "This permanently DESTROYS the site " + site + " on this host — its container, database, " +
			"uploaded files and configuration. This host has held it stopped since " + since.UTC().Format("2006-01-02") +
			". Only what its offsite backups still hold survives.",
		Facts: []primitives.ApprovalFact{
			{Label: "Site", Value: site},
			{Label: "Names this host serves it under", Value: strings.Join(t.names(), ", ")},
			{Label: "Held stopped since", Value: since.UTC().Format(time.RFC3339)},
			{Label: "Stands in for the site's approval", Value: "this host's own hold, standing at least 55 days"},
		},
	}
	return statement, &heldSiteGate{prober: h, site: site}, nil, nil
}

// check answers when the hold began, or why the site may not be removed.
func (h heldSiteProber) check(ctx context.Context, site string) (time.Time, string) {
	since, err := h.holdTime(site)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return time.Time{}, "This host does not hold " + site + " stopped, so it is not a held site."
		}
		return time.Time{}, fmt.Sprintf("The hold on %s could not be read (%v).", site, err)
	}
	now := h.now()
	if since.After(now) {
		return time.Time{}, "The hold on " + site + " is dated in the future, so its age cannot be trusted."
	}
	if age := now.Sub(since); age < primitives.HeldSiteMinAge {
		return time.Time{}, fmt.Sprintf("This host has held %s stopped for %d days, since %s; it removes a held site only after %d.",
			site, int(age/(24*time.Hour)), since.UTC().Format("2006-01-02"), int(primitives.HeldSiteMinAge/(24*time.Hour)))
	}
	stopped, err := h.stopped(ctx, site)
	if err != nil {
		return time.Time{}, fmt.Sprintf("Could not tell whether the container %s is stopped (%v).", site, err)
	}
	if !stopped {
		return time.Time{}, "The container " + site + " is running, so it is not held stopped."
	}
	return since, ""
}

type heldSiteGate struct {
	prober heldSiteProber
	site   string
}

func (g *heldSiteGate) Require(ctx context.Context, jobID int64, _ primitives.ApprovalStatement) error {
	since, why := g.prober.check(ctx, g.site)
	if why != "" {
		return &primitives.RefusalError{Reason: why + " Nothing was removed."}
	}
	log.Printf("decommission_held_site %s (job %d): held stopped since %s", g.site, jobID, since.UTC().Format(time.RFC3339))
	return nil
}
