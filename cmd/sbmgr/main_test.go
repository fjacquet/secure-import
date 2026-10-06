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
		{"no args", nil, "a command is required"},
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
	if code != 0 || !strings.Contains(stdout, "sbmgr probe") || strings.Contains(stdout, "not validated") {
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
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"-a"}, "db_import"}, {[]string{"-a"}, "probe"}, {[]string{"--platform"}, "supermicro"},
		{[]string{"--method"}, "standard"}, {[]string{"reset-keys", "--reset-type"}, "ResetDB"}, {[]string{"-f"}, "json"},
	}
	for _, tc := range cases {
		_, stdout, _ := exec(t, append([]string{"__complete"}, append(tc.args, "")...)...)
		if !strings.Contains(stdout, tc.want) {
			t.Errorf("completion of %v lacks %s: %q", tc.args, tc.want, stdout)
		}
	}
}

func TestVersionSubcommand(t *testing.T) {
	code, stdout, _ := exec(t, "version")
	if code != 0 || !strings.HasPrefix(stdout, "sbmgr ") {
		t.Errorf("code = %d, stdout = %q", code, stdout)
	}
}

func TestDatabaseFlagValidationAndCompletion(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"unknown database", []string{"-i", "a", "-o", "b", "-a", "db_list", "--database", "dbr"}, "database must be one of"},
		{"signature needs dbx", []string{"-i", "a", "-o", "b", "-a", "db_import", "--database", "db", "--signature", sha}, "only applies to db_import with --database dbx"},
		{"signature length", []string{"-i", "a", "-o", "b", "-a", "db_import", "--database", "dbx", "--signature", "abc"}, "64 hexadecimal"},
		{"signature xor cert", []string{"-i", "a", "-o", "b", "-a", "db_import", "--database", "dbx", "--signature", sha, "--cert-file", "c"}, "not both"},
		{"dbx needs a signature", []string{"-i", "a", "-o", "b", "-a", "db_import", "--database", "dbx", "--cert-file", "c"}, "needs --signature"},
		{"per-database reset types", []string{"-i", "a", "-o", "b", "-a", "reset_keys", "--database", "db", "--reset-type", "DeletePK", "--confirm"}, "must be ResetAllKeysToDefault or DeleteAllKeys"},
	}
	for _, tc := range cases {
		code, _, stderr := exec(t, tc.args...)
		if code != 2 || !strings.Contains(stderr, tc.want) {
			t.Errorf("%s: code = %d, stderr = %q, want 2 and %q", tc.name, code, stderr, tc.want)
		}
	}
	_, stdout, _ := exec(t, "__complete", "db", "list", "--database", "")
	for _, db := range []string{"db", "KEK", "PK", "dbx"} {
		if !strings.Contains(stdout, db) {
			t.Errorf("--database completion lacks %s: %q", db, stdout)
		}
	}
}

func TestProbeDumpOnlyWithProbeAndNeverCostsTheResults(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.csv")
	_ = os.WriteFile(in, []byte("start_ip,end_ip,username,password\n127.0.0.1,,root,pw\n"), 0o600)
	code, _, stderr := exec(t, "-i", in, "-o", filepath.Join(dir, "o.csv"), "-a", "status", "--probe-dump", filepath.Join(dir, "d.json"))
	if code != 2 || !strings.Contains(stderr, "--probe-dump only applies to -a probe") {
		t.Errorf("code = %d, stderr = %q", code, stderr)
	}
	out := filepath.Join(dir, "o2.csv")
	code, _, _ = exec(t, "-i", in, "-o", out, "-a", "probe", "--probe-dump", filepath.Join(dir, "no-such-dir", "d.json"), "--timeout", "1s", "--retries", "0")
	if _, err := os.Stat(out); err != nil {
		t.Errorf("a bad dump path must not lose the results file (exit %d): %v", code, err)
	}
}

func TestSignatureOwnerNeedsASignature(t *testing.T) {
	code, _, stderr := exec(t, "-i", "a", "-o", "b", "-a", "db_import", "--database", "dbx", "--cert-file", "c", "--signature-owner", "g")
	if code != 2 || !strings.Contains(stderr, "--signature-owner") {
		t.Errorf("code = %d, stderr = %q", code, stderr)
	}
}

// ---- subcommands (ADR 0011)

// csvWith writes a one-host CSV and returns the paths used by the command-line tests.
func csvWith(t *testing.T) (in, out string) {
	t.Helper()
	dir := t.TempDir()
	in = filepath.Join(dir, "in.csv")
	_ = os.WriteFile(in, []byte("start_ip,end_ip,username,password\n127.0.0.1,,root,pw\n"), 0o600)
	return in, filepath.Join(dir, "out.csv")
}

func TestEveryActionIsASubcommand(t *testing.T) {
	cases := []struct {
		args   []string
		action string // the report's Action column
	}{
		{[]string{"status"}, "status"}, {[]string{"enable"}, "enable"}, {[]string{"disable"}, "disable"},
		{[]string{"policy", "custom"}, "set_policy_custom"}, {[]string{"policy", "standard"}, "set_policy_standard"},
		{[]string{"db", "list"}, "db_list"}, {[]string{"db", "import", "--cert-file", "c.der"}, "db_import"},
		{[]string{"db", "export", "--cert-uri", "/redfish/v1/x/Certificates/1", "--cert-file", "o.der"}, "db_export"},
		{[]string{"db", "delete", "--cert-uri", "/redfish/v1/x/Certificates/1"}, "db_delete"},
		{[]string{"reset-keys", "--reset-type", "ResetDB", "--dry-run"}, "reset_keys"},
		{[]string{"probe"}, "Check,Status"},
	}
	for _, tc := range cases {
		in, out := csvWith(t)
		args := append(append([]string{}, tc.args...), "-i", in, "-o", out, "--timeout", "1s", "--retries", "0")
		code, _, stderr := exec(t, args...)
		b, _ := os.ReadFile(out)
		if code != 1 || !strings.Contains(string(b), tc.action) || strings.Contains(stderr, "deprecated") {
			t.Errorf("%v: code = %d, stderr = %q, out = %q", tc.args, code, stderr, b)
		}
	}
}

func TestDashAStillWorksButIsDeprecated(t *testing.T) {
	in, out := csvWith(t)
	code, _, stderr := exec(t, "-i", in, "-o", out, "-a", "db_list", "--timeout", "1s", "--retries", "0")
	if code != 1 || !strings.Contains(stderr, "deprecated") || !strings.Contains(stderr, "sbmgr db list") {
		t.Errorf("code = %d, stderr = %q", code, stderr)
	}
	if b, _ := os.ReadFile(out); !strings.Contains(string(b), "db_list") {
		t.Errorf("out = %q", b)
	}
}

func TestSubcommandFlagsBelongToTheirCommand(t *testing.T) {
	cases := []struct{ args []string }{
		{[]string{"status", "--cert-file", "x"}}, {[]string{"probe", "--confirm"}},
		{[]string{"db", "list", "--probe-dump", "x"}}, {[]string{"enable", "--reset-type", "ResetDB"}},
	}
	for _, tc := range cases {
		code, _, stderr := exec(t, tc.args...)
		if code != 2 || !strings.Contains(stderr, "unknown flag") {
			t.Errorf("%v: code = %d, stderr = %q", tc.args, code, stderr)
		}
	}
}

func TestSubcommandValidationKeepsTheSameMessages(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"status"}, "-i/--input is required"},
		{[]string{"db", "import", "-i", "a", "-o", "b"}, "db_import requires --cert-file"},
		{[]string{"db", "delete", "-i", "a", "-o", "b"}, "db_delete requires --cert-uri"},
		{[]string{"reset-keys", "-i", "a", "-o", "b"}, "reset_keys requires --reset-type"},
		{[]string{"db", "import", "-i", "a", "-o", "b", "--database", "dbx", "--cert-file", "c"}, "needs --signature"},
	}
	for _, tc := range cases {
		code, _, stderr := exec(t, tc.args...)
		if code != 2 || !strings.Contains(stderr, tc.want) {
			t.Errorf("%v: code = %d, stderr = %q, want 2 and %q", tc.args, code, stderr, tc.want)
		}
	}
}

func TestHelpShowsCommandGroupsAndCompletionKnowsTheTree(t *testing.T) {
	_, stdout, _ := exec(t, "-h")
	for _, want := range []string{"Secure Boot", "Certificate databases", "Diagnostics", "db ", "policy ", "reset-keys", "probe"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("help lacks %q:\n%s", want, stdout)
		}
	}
	_, comp, _ := exec(t, "__complete", "db", "")
	for _, sub := range []string{"list", "import", "export", "delete"} {
		if !strings.Contains(comp, sub) {
			t.Errorf("`db` completion lacks %s: %q", sub, comp)
		}
	}
	_, comp, _ = exec(t, "__complete", "db", "list", "--database", "")
	if !strings.Contains(comp, "KEK") {
		t.Errorf("--database completion under db list: %q", comp)
	}
	_, comp, _ = exec(t, "__complete", "reset-keys", "--reset-type", "")
	if !strings.Contains(comp, "ResetDB") {
		t.Errorf("--reset-type completion: %q", comp)
	}
}

// ---- audit log

func TestLogFileRecordsTheRunWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.csv")
	if err := os.WriteFile(in, []byte("start_ip,end_ip,username,password\n127.0.0.1,,root,S3cretPW-xyz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "audit.log")
	code, _, stderr := exec(t, "status", "-i", in, "-o", filepath.Join(dir, "o.csv"), "--timeout", "1s", "--concurrency", "1", "--log-file", logPath)
	if code != 1 {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(b)
	for _, want := range []string{`"msg":"run start"`, `"msg":"host result"`, `"msg":"run end"`, `"run_id":"`, `"ip":"127.0.0.1"`,
		`"action":"status"`, `"input_sha256":"`, `"succeeded":0`, `"failed":1`} {
		if !strings.Contains(log, want) {
			t.Errorf("log lacks %s:\n%s", want, log)
		}
	}
	if strings.Contains(log, "S3cretPW-xyz") || strings.Contains(stderr, "S3cretPW-xyz") {
		t.Error("the password leaked")
	}
	if st, _ := os.Stat(logPath); st.Mode().Perm() != 0o600 {
		t.Errorf("log mode = %v", st.Mode().Perm())
	}
}

func TestLogFileThatCannotBeOpenedExitsWithTwo(t *testing.T) {
	in, out := csvWith(t)
	code, _, stderr := exec(t, "status", "-i", in, "-o", out, "--log-file", filepath.Join(t.TempDir(), "no", "such", "dir", "x.log"))
	if code != 2 || !strings.Contains(stderr, "log") {
		t.Errorf("code = %d, stderr = %q", code, stderr)
	}
}
