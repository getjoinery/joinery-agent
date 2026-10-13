package main

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"joinery-agent/primitives"
)

// A site node never converges on a bundle: it has no bundle (SiteRoot wins)
// and its path trigger does this job. The guard is the first line.
func TestBundleConvergeIsForSitelessMachinesOnly(t *testing.T) {
	var lock sync.Mutex
	convergeAfterBundle(&Config{Siteless: false, SiteRoot: "/var/www/html/site"}, nil, &lock)
	if !lock.TryLock() {
		t.Fatal("a site config should return before touching the lock")
	}
	lock.Unlock()
	convergeAfterBundle(nil, nil, &lock)
	if !lock.TryLock() {
		t.Fatal("a nil config should return before touching the lock")
	}
	lock.Unlock()
}

// A running job wins: the converge never waits for the lock, and never runs
// under a lock it did not take.
func TestBundleConvergeYieldsToARunningJob(t *testing.T) {
	var lock sync.Mutex
	lock.Lock()
	defer lock.Unlock()
	done := make(chan struct{})
	var err error
	go func() {
		err = convergeAfterBundle(&Config{Siteless: true, PolicyPath: "/nonexistent/policy"}, nil, &lock)
		close(done)
	}()
	<-done // returned while the lock was held, without blocking
	if err == nil {
		t.Fatal("a converge that did not run must say so")
	}
}

// joinery-agent bundle install fails when the converge did not run, so the
// converge returns why: here, no tree to verify the runner against.
func TestBundleConvergeSaysWhyItDidNotRun(t *testing.T) {
	var lock sync.Mutex
	t.Setenv("AGENT_TOOL_ROOT", filepath.Join(t.TempDir(), "tree"))
	err := convergeAfterBundle(&Config{Siteless: true, PolicyPath: "/nonexistent/policy"}, nil, &lock)
	if err == nil || !strings.Contains(err.Error(), "host_converge") {
		t.Fatalf("a converge that did not run must say why, got %v", err)
	}
	if err := convergeAfterBundle(&Config{Siteless: false}, nil, &lock); err != nil {
		t.Fatalf("a site machine has nothing to converge, which is not a failure: %v", err)
	}
}

// The word it runs is the one the plane and the recipe run, with the bound
// the word declares: minutes, because the runner may wait ten for its lock.
func TestBundleConvergeRunsTheHostConvergeWordWithItsOwnTimeout(t *testing.T) {
	word, ok := primitives.Lookup("host_converge")
	if !ok {
		t.Fatal("host_converge should be registered")
	}
	if word.Timeout < bundleConvergeTimeoutFloor {
		t.Fatalf("host_converge's timeout %v is under the %v floor the bundle converge relies on", word.Timeout, bundleConvergeTimeoutFloor)
	}
	if word.Class != primitives.ClassOperate {
		t.Fatalf("the bundle converge runs an operate word, not %s", word.Class)
	}
}
