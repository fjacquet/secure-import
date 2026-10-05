package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func exec(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestUsageErrorsExitWithTwo(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no args", nil, "-i/--input is required"},
		{"bad action", []string{"-i", "a", "-o", "b", "-a", "explode"}, "unknown action"},
		{"bad format", []string{"-i", "a", "-o", "b", "-a", "status", "-f", "xml"}, "format must be csv or json"},
		{"bad platform", []string{"-i", "a", "-o", "b", "-a", "status", "--platform", "hp"}, "unknown platform"},
		{"bad method", []string{"-i", "a", "-o", "b", "-a", "status", "--method", "x"}, "method must be"},
		{"import needs file", []string{"-i", "a", "-o", "b", "-a", "db_import"}, "db_import requires --cert-file"},
		{"delete needs uri", []string{"-i", "a", "-o", "b", "-a", "db_delete"}, "db_delete requires --cert-uri"},
		{"export needs both", []string{"-i", "a", "-o", "b", "-a", "db_export", "--cert-uri", "/x"}, "db_export requires --cert-uri and --cert-file"},
		{"bad concurrency", []string{"-i", "a", "-o", "b", "-a", "status", "--concurrency", "0"}, "concurrency must be positive"},
	}
	for _, tc := range cases {
		code, _, stderr := exec(t, tc.args...)
		if code != 2 || !strings.Contains(stderr, tc.want) {
			t.Errorf("%s: code = %d, stderr = %q, want 2 and %q", tc.name, code, stderr, tc.want)
		}
	}
}

func TestHelpExitsZeroAndMentionsUnvalidatedPlatforms(t *testing.T) {
	code, _, stderr := exec(t, "-h")
	if code != 0 || !strings.Contains(stderr, "not validated on hardware") {
		t.Errorf("code = %d, stderr = %q", code, stderr)
	}
}

func TestMissingInputFileExitsWithTwo(t *testing.T) {
	code, _, stderr := exec(t, "-i", filepath.Join(t.TempDir(), "absent.csv"), "-o", filepath.Join(t.TempDir(), "o.csv"), "-a", "status")
	if code != 2 || !strings.Contains(stderr, "absent.csv") {
		t.Errorf("code = %d, stderr = %q", code, stderr)
	}
}

// An unreachable host is a failed row, exit code 1, and the output file is still written.
func TestUnreachableHostGivesExitOneAndOutputFile(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.csv")
	if err := os.WriteFile(in, []byte("start_ip,end_ip,username,password\n127.0.0.1,127.0.0.1,root,pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.csv")
	code, stdout, _ := exec(t, "-i", in, "-o", out, "-a", "status", "--timeout", "1s", "--concurrency", "1")
	if code != 1 || !strings.Contains(stdout, "1 failed") {
		t.Errorf("code = %d, stdout = %q", code, stdout)
	}
	b, err := os.ReadFile(out)
	if err != nil || !strings.HasPrefix(string(b), "IP Address,Action,Name,") || !strings.Contains(string(b), "127.0.0.1") {
		t.Errorf("output = %q, err = %v", b, err)
	}
	if strings.Contains(string(b), "pw\n") {
		t.Error("the password must not appear in the output")
	}
}
