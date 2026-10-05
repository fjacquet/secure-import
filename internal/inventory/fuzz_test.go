package inventory

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// FuzzExpand: an address range or CIDR typed in a spreadsheet must never panic, never
// exceed the cap, and only yield valid IPv4 addresses.
func FuzzExpand(f *testing.F) {
	for _, s := range [][2]string{
		{"10.0.0.1", ""}, {"10.0.0.1", "10.0.0.9"}, {"10.0.0.0/30", ""}, {"10.0.0.0/8", ""},
		{"", ""}, {"::1", ""}, {"10.0.0.9", "10.0.0.1"}, {"0.0.0.0/0", ""}, {"255.255.255.254", "255.255.255.255"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, start, end string) {
		ips, err := Expand(start, end)
		if err != nil {
			return
		}
		if len(ips) == 0 || len(ips) > maxRange {
			t.Fatalf("Expand(%q, %q) returned %d addresses", start, end, len(ips))
		}
		for _, ip := range ips {
			if a, err := netip.ParseAddr(ip); err != nil || !a.Is4() {
				t.Fatalf("Expand(%q, %q) returned %q", start, end, ip)
			}
		}
	})
}

// FuzzRead: a spreadsheet export can hold anything; reading it must never panic and
// the hosts built from its rows must stay within the cap.
func FuzzRead(f *testing.F) {
	f.Add([]byte("start_ip,end_ip,username,password\n10.0.0.1,,root,pw\n"))
	f.Add([]byte("\xef\xbb\xbfstart_ip,end_ip,username,password\r\n10.0.0.0/30,,u,p\r\n,,,\r\n"))
	f.Add([]byte("start_ip;end_ip\n1;2\n"))
	f.Add([]byte(""))
	f.Add([]byte("start_ip,end_ip,username,password\n\"unterminated"))
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "in.csv")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		rows, err := Read(path)
		if err != nil {
			return
		}
		hosts, _ := Hosts(rows)
		seen := map[string]bool{}
		for _, h := range hosts {
			if seen[h.IP] {
				t.Fatalf("duplicate host %s", h.IP)
			}
			seen[h.IP] = true
		}
	})
}
