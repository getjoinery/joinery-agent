package main

import (
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
	go func() {
		convergeAfterBundle(&Config{Siteless: true, PolicyPath: "/nonexistent/policy"}, nil, &lock)
		close(done)
	}()
	<-done // returned while the lock was held, without blocking
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
