package main

import "testing"

func TestReportsContainer(t *testing.T) {
	old := runsInContainer
	defer func() { runsInContainer = old }()

	runsInContainer = func() bool { return true }
	if !reportsContainer(true) {
		t.Fatal("a site agent in a container must say so")
	}
	if reportsContainer(false) {
		t.Fatal("a machine with no site says nothing, even inside a container")
	}
	runsInContainer = func() bool { return false }
	if reportsContainer(true) {
		t.Fatal("a site agent outside a container must not say so")
	}
}
