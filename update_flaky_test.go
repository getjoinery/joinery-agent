package main

import (
	"errors"
	"io"
	"testing"
)

// flakySource fails Open a set number of times, then behaves like the real
// source underneath it — a publish mid-swap, a request that timed out.
type flakySource struct {
	inner    artifactSource
	failures int
	opens    int
}

func (f *flakySource) Manifest() ([]byte, error) { return f.inner.Manifest() }
func (f *flakySource) Describe() string          { return "flaky " + f.inner.Describe() }
func (f *flakySource) Open(platform string, entry distBinary) (io.ReadCloser, error) {
	f.opens++
	if f.opens <= f.failures {
		return nil, errors.New("context canceled")
	}
	return f.inner.Open(platform, entry)
}

// A fetch that fails on the way is not a verdict on the artifact: the next
// check tries again, and the same unchanged manifest is then applied.
func TestATransientFetchFailureIsRetriedNotRefused(t *testing.T) {
	e := newTestUpdaterEnv(t, "0.3.0")
	e.writeDist(t, "0.3.1", []byte("NEW-BINARY"), nil)
	e.u.source = &flakySource{inner: localDirSource{dir: e.distDir}, failures: 1}

	if e.u.CheckAndApply() {
		t.Fatal("applied an update whose fetch failed")
	}
	if _, state := e.u.HeartbeatInfo(); state != updateStateFetchFailed {
		t.Fatalf("state = %q, want %q", state, updateStateFetchFailed)
	}
	if e.installedContent(t) != "OLD-BINARY" {
		t.Fatal("binary changed after a failed fetch")
	}
	// Same manifest, next check: the fetch works now and the update lands.
	if !e.u.CheckAndApply() {
		t.Fatal("an unchanged manifest was not retried after a transient fetch failure")
	}
	if e.installedContent(t) != "NEW-BINARY" {
		t.Fatal("the retried update was not installed")
	}
}
