package main

import "testing"

// webDir is read as the site reads it: the host, without a scheme or a
// trailing slash.
func TestSiteDomainFromWebDir(t *testing.T) {
	for in, want := range map[string]string{
		"copytest.example.com":          "copytest.example.com",
		"https://copytest.example.com/": "copytest.example.com",
		"HTTP://copytest.example.com":   "copytest.example.com",
		" copytest.example.com ":        "copytest.example.com",
		"":                              "",
	} {
		if got := siteDomainFromWebDir(in); got != want {
			t.Errorf("siteDomainFromWebDir(%q) = %q, want %q", in, got, want)
		}
	}
}
