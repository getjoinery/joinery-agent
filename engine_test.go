package main

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// engineFixture points the engine's paths at a scratch directory: current is
// made a link only when link is true, and podman is written with mode.
func engineFixture(t *testing.T, link bool, podmanMode os.FileMode) (dir string) {
	t.Helper()
	dir = t.TempDir()
	savedCurrent, savedPodman := siteEngineCurrent, siteEnginePodman
	t.Cleanup(func() { siteEngineCurrent, siteEnginePodman = savedCurrent, savedPodman })
	siteEngineCurrent, siteEnginePodman = filepath.Join(dir, "current"), filepath.Join(dir, "podman")
	if link {
		if err := os.Mkdir(filepath.Join(dir, "6.1.4-aaaaaaaaaaaa"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("6.1.4-aaaaaaaaaaaa", siteEngineCurrent); err != nil {
			t.Fatal(err)
		}
	}
	if podmanMode != 0 {
		if err := os.WriteFile(siteEnginePodman, []byte("#!/bin/sh\nexit 0\n"), podmanMode); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestSiteEngineIsNamedAsTheHelperNamesIt: the agent names the engine with
// _site_engine.sh's rule (specs/site_container_engine.md D7, reviewer2 R1/R7).
func TestSiteEngineIsNamedAsTheHelperNamesIt(t *testing.T) {
	engineFixture(t, true, 0o755)
	if name, bin, err := siteEngine(); err != nil || name != "podman" || bin != siteEnginePodman {
		t.Fatalf("installed and usable: podman, got %q %q %v", name, bin, err)
	}

	engineFixture(t, true, 0o644)
	if _, _, err := siteEngine(); err == nil || !strings.Contains(err.Error(), "missing or not executable") {
		t.Fatalf("installed with podman not executable: refused, never docker, got %v", err)
	}
	engineFixture(t, true, 0)
	if _, _, err := siteEngine(); err == nil {
		t.Fatal("installed with no podman at all: refused")
	}

	// A dangling link is still the engine's: the link is what says so.
	d := engineFixture(t, true, 0o755)
	if err := os.Remove(filepath.Join(d, "6.1.4-aaaaaaaaaaaa")); err != nil {
		t.Fatal(err)
	}
	if name, _, err := siteEngine(); err != nil || name != "podman" {
		t.Fatalf("a dangling current link is the site engine's: %q %v", name, err)
	}

	// Anything else at current (a folder a broken converge left) makes the host
	// the engine's and is refused, never read as Docker (reviewer2 T4).
	d = engineFixture(t, false, 0o755)
	if err := os.Mkdir(siteEngineCurrent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "docker"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", d)
	if _, _, err := siteEngine(); err == nil || !strings.Contains(err.Error(), "is not a link") {
		t.Fatalf("a current that is not a link is refused, even with a docker on PATH: %v", err)
	}

	dir := engineFixture(t, false, 0o755)
	t.Setenv("PATH", dir)
	if _, _, err := siteEngine(); err == nil || !strings.Contains(err.Error(), "docker is not on this host's path") {
		t.Fatalf("no engine link and no docker: refused, got %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if name, bin, err := siteEngine(); err != nil || name != "docker" || bin != filepath.Join(dir, "docker") {
		t.Fatalf("no engine link: docker, got %q %q %v", name, bin, err)
	}
}

// TestCopyInGoesToTheSiteEngine: the moved-site token reaches a site on the
// site container engine through podman's archive copy, the same tar on stdin.
func TestCopyInGoesToTheSiteEngine(t *testing.T) {
	dir := engineFixture(t, true, 0)
	log := filepath.Join(dir, "calls")
	got := filepath.Join(dir, "stdin.tar")
	stub := "#!/bin/sh\necho \"$*\" > '" + log + "'\n/bin/cat > '" + got + "'\n"
	if err := os.WriteFile(siteEnginePodman, []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir) // and no docker
	if err := engineCopyIn(context.Background(), "sa", "token.txt", []byte("abc")); err != nil {
		t.Fatalf("copy-in through podman: %v", err)
	}
	calls, _ := os.ReadFile(log)
	if want := "cp - sa:/var/www/html/sa/public_html"; strings.TrimSpace(string(calls)) != want {
		t.Fatalf("podman was asked %q, want %q", calls, want)
	}
	raw, _ := os.ReadFile(got)
	tr := tar.NewReader(bytes.NewReader(raw))
	h, err := tr.Next()
	if err != nil || h.Name != "token.txt" {
		t.Fatalf("the archive carries the one file: %v %+v", err, h)
	}
	if body, _ := io.ReadAll(tr); string(body) != "abc" {
		t.Fatalf("the file's content: %q", body)
	}
}

// engineLiterals are the string literals in a Go source that name an engine's
// binary (docker or podman, bare or as a path, alone or opening a command) or
// a container marker, each as "LINE: VALUE". Comments are not literals.
func engineLiterals(t *testing.T, name string, src []byte) (engines, markers []string) {
	t.Helper()
	engineLit := regexp.MustCompile(`^(\S*/)?(docker|podman)(\s|$)`)
	markerLit := regexp.MustCompile(`\.(dockerenv|containerenv)$`)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		v, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		at := fmt.Sprintf("%d: %s", fset.Position(lit.Pos()).Line, v)
		if engineLit.MatchString(v) {
			engines = append(engines, at)
		}
		if markerLit.MatchString(v) {
			markers = append(markers, at)
		}
		return true
	})
	return engines, markers
}

// TestNoEngineIsNamedOutsideItsOneRule reads every string literal in the
// agent's own sources: only engine.go names an engine's binary, and only
// primitives/container.go a container marker, so a Podman site or host is
// never taken for something else (reviewer2 T2).
func TestNoEngineIsNamedOutsideItsOneRule(t *testing.T) {
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && (path == "testdata" || strings.HasPrefix(path, ".git")) {
			return filepath.SkipDir
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		engines, markers := engineLiterals(t, path, src)
		if len(engines) > 0 && path != "engine.go" {
			t.Errorf("%s names an engine itself (%v); ask siteEngine (engine.go)", path, engines)
		}
		if len(markers) > 0 && path != filepath.Join("primitives", "container.go") {
			t.Errorf("%s names a container marker itself (%v); use primitives.RunsInContainer", path, markers)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestTheScanSeesEachWayToNameAnEngine: every way reviewer2 found past the
// earlier, text-based scan is caught, and a comment is not.
func TestTheScanSeesEachWayToNameAnEngine(t *testing.T) {
	src := `package x

import (
	"context"
	"os/exec"
	"path/filepath"
)

const tool = "docker"

// A comment that says docker and /.dockerenv is not a literal.
func f() {
	exec.Command("bash", "-c", "docker ps")
	exec.Command("/usr/bin/docker", "ps")
	exec.CommandContext(context.Background(), "docker", "ps")
	exec.LookPath("podman")
	exec.Command("/usr/local/bin/podman", "ps")
	exec.Command(tool, "ps")
	_ = filepath.Join("/", ".dockerenv")
	_ = "/run/.containerenv"
}
`
	engines, markers := engineLiterals(t, "x.go", []byte(src))
	if len(engines) != 6 {
		t.Fatalf("each engine literal is seen, not a comment: %d %v", len(engines), engines)
	}
	if len(markers) != 2 {
		t.Fatalf("each marker literal is seen, not a comment: %d %v", len(markers), markers)
	}
}
