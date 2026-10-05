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
		{"reset needs a type", []string{"-i", "a", "-o", "b", "-a", "reset_keys", "--confirm"}, "reset_keys requires --reset-type"},
		{"reset type is checked", []string{"-i", "a", "-o", "b", "-a", "reset_keys", "--reset-type", "Nuke", "--confirm"}, "reset-type must be"},
		{"reset needs confirm (db only)", []string{"-i", "a", "-o", "b", "-a", "reset_keys", "--reset-type", "ResetDB"}, "requires --confirm"},
		{"reset needs confirm", []string{"-i", "a", "-o", "b", "-a", "reset_keys", "--reset-type", "DeleteAllKeys"}, "requires --confirm"},
		{"bad concurrency", []string{"-i", "a", "-o", "b", "-a", "status", "--concurrency", "0"}, "concurrency must be positive"},
	}
	for _, tc := range cases {
		code, _, stderr := exec(t, tc.args...)
		if code != 2 || !strings.Contains(stderr, tc.want) {
			t.Errorf("%s: code = %d, stderr = %q, want 2 and %q", tc.name, code, stderr, tc.want)
		}
	}
}

func TestHelpExitsZeroAndPointsToProbe(t *testing.T) {
	code, stdout, _ := exec(t, "-h")
	if code != 0 || !strings.Contains(stdout, "-a probe") || strings.Contains(stdout, "not validated") {
		t.Errorf("code = %d, stdout = %q", code, stdout)
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

func TestEmptyInventoryExitsWithTwo(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.csv")
	_ = os.WriteFile(in, []byte("start_ip,end_ip,username,password\n"), 0o600)
	code, _, stderr := exec(t, "-i", in, "-o", filepath.Join(dir, "o.csv"), "-a", "status")
	if code != 2 || !strings.Contains(stderr, "no hosts") {
		t.Errorf("code = %d, stderr = %q", code, stderr)
	}
}

func TestBadRowDoesNotAbortTheRun(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.csv")
	_ = os.WriteFile(in, []byte("start_ip,end_ip,username,password\nnope,,u,p\n127.0.0.1,,root,pw\n"), 0o600)
	out := filepath.Join(dir, "o.csv")
	code, _, stderr := exec(t, "-i", in, "-o", out, "-a", "status", "--timeout", "1s")
	b, _ := os.ReadFile(out)
	if code != 1 || !strings.Contains(stderr, "row 1") || !strings.Contains(string(b), "127.0.0.1") {
		t.Errorf("code = %d, stderr = %q, out = %q", code, stderr, b)
	}
}

func TestWarnsWhenTLSVerificationIsOff(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.csv")
	_ = os.WriteFile(in, []byte("start_ip,end_ip,username,password\n127.0.0.1,,root,pw\n"), 0o600)
	_, _, stderr := exec(t, "-i", in, "-o", filepath.Join(dir, "o.csv"), "-a", "status", "--timeout", "1s")
	if !strings.Contains(stderr, "TLS verification is disabled") {
		t.Errorf("stderr = %q", stderr)
	}
	_, _, stderr = exec(t, "-i", in, "-o", filepath.Join(dir, "o.csv"), "-a", "status", "--timeout", "1s", "--verify-tls")
	if strings.Contains(stderr, "TLS verification is disabled") {
		t.Errorf("no warning expected with --verify-tls, stderr = %q", stderr)
	}
}

func TestProbeIsAnActionAndWritesChecksAndDump(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.csv")
	_ = os.WriteFile(in, []byte("start_ip,end_ip,username,password\n127.0.0.1,,root,pw\n"), 0o600)
	out, dump := filepath.Join(dir, "o.csv"), filepath.Join(dir, "dump.json")
	code, _, _ := exec(t, "-i", in, "-o", out, "-a", "probe", "--probe-dump", dump, "--timeout", "1s", "--retries", "0")
	b, _ := os.ReadFile(out)
	if code != 1 || !strings.HasPrefix(string(b), "IP Address,Platform,Check,Status,Detail") || !strings.Contains(string(b), "FAIL") {
		t.Errorf("code = %d, out = %q", code, b)
	}
	if fi, err := os.Stat(dump); err != nil || fi.Size() == 0 {
		t.Errorf("dump: %v", err)
	}
}

func TestVersionFlagPrintsVersionAndExitsZero(t *testing.T) {
	code, stdout, _ := exec(t, "--version")
	if code != 0 || !strings.HasPrefix(stdout, "sbmgr ") || !strings.Contains(stdout, version) {
		t.Errorf("code = %d, stdout = %q", code, stdout)
	}
}

func TestHelpListsEachOptionOnceWithItsShortForm(t *testing.T) {
	_, stdout, _ := exec(t, "-h")
	if !strings.Contains(stdout, "-i, --input") || strings.Contains(stdout, " -input string") {
		t.Errorf("help:\n%s", stdout)
	}
}

func TestCompletionScriptsAreGenerated(t *testing.T) {
	for _, sh := range []string{"bash", "zsh", "fish", "powershell"} {
		code, stdout, _ := exec(t, "completion", sh)
		if code != 0 || !strings.Contains(stdout, "sbmgr") {
			t.Errorf("%s: code = %d, stdout has %d bytes", sh, code, len(stdout))
		}
	}
}

func TestFlagValuesAreCompleted(t *testing.T) {
	cases := []struct{ flag, want string }{
		{"-a", "db_import"}, {"-a", "probe"}, {"--platform", "supermicro"},
		{"--method", "standard"}, {"--reset-type", "ResetDB"}, {"-f", "json"},
	}
	for _, tc := range cases {
		_, stdout, _ := exec(t, "__complete", tc.flag, "")
		if !strings.Contains(stdout, tc.want) {
			t.Errorf("completion of %s lacks %s: %q", tc.flag, tc.want, stdout)
		}
	}
}

func TestVersionSubcommand(t *testing.T) {
	code, stdout, _ := exec(t, "version")
	if code != 0 || !strings.HasPrefix(stdout, "sbmgr ") {
		t.Errorf("code = %d, stdout = %q", code, stdout)
	}
}
