// Package testutil: golden files, temporary git repos and fake binaries.
package testutil

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// Golden compares got with testdata/<name>; `go test -update` rewrites it.
func Golden(t testing.TB, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("golden %s: %v (run with -update)", p, err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("golden %s mismatch\n--- want\n%s\n--- got\n%s", p, want, got)
	}
}

// RepoRoot returns the module root (directory holding go.mod).
func RepoRoot(t testing.TB) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// Fixture returns the absolute path of testdata/<name> at the repo root.
func Fixture(t testing.TB, name string) string {
	t.Helper()
	return filepath.Join(RepoRoot(t), "testdata", name)
}

// GitRepo creates a temp git repo with files committed on branch main.
func GitRepo(t testing.TB, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for p, c := range files {
		dst := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	Git(t, dir, "init", "-q", "-b", "main")
	Git(t, dir, "add", "-A")
	Git(t, dir, "-c", "user.name=rr-test", "-c", "user.email=rr@test", "commit", "-q", "--allow-empty", "-m", "init")
	return dir
}

// CopyFixture copies testdata/<name> into a fresh git repo.
func CopyFixture(t testing.TB, name string) string {
	t.Helper()
	src := Fixture(t, name)
	files := map[string]string{}
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		files[rel] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return GitRepo(t, files)
}

// Git runs git in dir and returns stdout.
func Git(t testing.TB, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return string(out)
}

// FakeBin writes an executable shell script named name and prepends its dir to PATH.
func FakeBin(t testing.TB, name, script string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return p
}
