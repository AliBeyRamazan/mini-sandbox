package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNormalizeRunArgsAllowsFlagsAfterSample(t *testing.T) {
	got := normalizeRunArgs([]string{"./sample", "--network", "--timeout", "20", "--reports-dir=out"})
	want := []string{"--network", "--timeout", "20", "--reports-dir=out", "./sample"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeRunArgs() = %#v, want %#v", got, want)
	}
}

func TestExtractSyscalls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "strace.log")
	content := "123 12:00:00.000000 execve(\"/sample/input\", [\"/sample/input\"], 0x0) = 0\n" +
		"123 12:00:00.000001 openat(AT_FDCWD, \"/etc/ld.so.cache\", O_RDONLY) = 3\n" +
		"123 12:00:00.000002 openat(AT_FDCWD, \"/tmp/x\", O_RDONLY) = -1 ENOENT\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got := extractSyscalls(path)
	if len(got) < 2 {
		t.Fatalf("expected at least two syscalls, got %#v", got)
	}
	if got[0] != (syscallCount{Syscall: "openat", Count: 2}) {
		t.Fatalf("top syscall = %#v, want openat count 2", got[0])
	}
}
