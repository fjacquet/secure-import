package inventory

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExpand(t *testing.T) {
	cases := []struct {
		name, start, end string
		want             []string
		wantErr          string
	}{
		{"single", "10.0.0.5", "10.0.0.5", []string{"10.0.0.5"}, ""},
		{"empty end is single", "10.0.0.5", "", []string{"10.0.0.5"}, ""},
		{"last octet", "10.0.0.5", "10.0.0.7", []string{"10.0.0.5", "10.0.0.6", "10.0.0.7"}, ""},
		{"crosses a /24", "10.0.0.254", "10.0.1.1", []string{"10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"}, ""},
		{"cidr /30 drops network and broadcast", "10.0.0.0/30", "", []string{"10.0.0.1", "10.0.0.2"}, ""},
		{"cidr /31 keeps both", "10.0.0.0/31", "", []string{"10.0.0.0", "10.0.0.1"}, ""},
		{"end before start", "10.0.0.9", "10.0.0.1", nil, "before"},
		{"range too large", "10.0.0.0", "10.1.0.0", nil, "exceeds"},
		{"cidr too large", "10.0.0.0/8", "", nil, "exceeds"},
		{"cidr with end_ip", "10.0.0.0/30", "10.0.0.2", nil, "end_ip must be empty"},
		{"bad ip", "10.0.0.x", "", nil, "invalid start_ip"},
		{"ipv6 rejected", "::1", "", nil, "invalid start_ip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Expand(tc.start, tc.end)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "nodes.csv")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadHandlesBOMCRLFBlankLinesAndSpaces(t *testing.T) {
	p := writeTemp(t, "\xef\xbb\xbfStart_IP,end_ip,username,password\r\n10.0.0.1,10.0.0.1,root,pa ss\r\n\r\n10.0.0.2, 10.0.0.4 ,admin,x\r\n")
	rows, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	if rows[0].Password != "pa ss" {
		t.Errorf("password = %q, want %q", rows[0].Password, "pa ss")
	}
	if rows[1].End != "10.0.0.4" {
		t.Errorf("end = %q, want trimmed 10.0.0.4", rows[1].End)
	}
}

func TestReadErrors(t *testing.T) {
	if _, err := Read(writeTemp(t, "start_ip,end_ip,username\n1.1.1.1,1.1.1.1,root\n")); err == nil || !strings.Contains(err.Error(), `missing column "password"`) {
		t.Errorf("missing column: err = %v", err)
	}
	if _, err := Read(writeTemp(t, "start_ip,end_ip,username,password\n1.1.1.1,root\n")); err == nil {
		t.Error("short row: want error")
	}
	if _, err := Read(filepath.Join(t.TempDir(), "absent.csv")); err == nil {
		t.Error("absent file: want error")
	}
}

func TestHostsReportsRowNumber(t *testing.T) {
	_, err := Hosts([]Row{{"10.0.0.1", "", "u", "p"}, {"10.0.0.9", "10.0.0.1", "u", "p"}})
	if err == nil || !strings.Contains(err.Error(), "row 2") {
		t.Fatalf("err = %v, want mention of row 2", err)
	}
	hosts, err := Hosts([]Row{{"10.0.0.1", "10.0.0.2", "u", "p"}})
	if err != nil || len(hosts) != 2 || hosts[1].IP != "10.0.0.2" || hosts[1].Username != "u" {
		t.Fatalf("hosts = %+v, err = %v", hosts, err)
	}
}

func TestPermissionWarning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions only")
	}
	p := writeTemp(t, "x")
	if w := PermissionWarning(p); w != "" {
		t.Errorf("0600 file: warning = %q, want none", w)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if w := PermissionWarning(p); !strings.Contains(w, "readable by other users") {
		t.Errorf("0644 file: warning = %q", w)
	}
}
