// Package inventory reads the input CSV and expands IP ranges into hosts.
package inventory

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strings"
)

// maxRange caps how many addresses one row may expand to.
const maxRange = 4096

// Row is one CSV line: a single IP, a range or a CIDR with shared credentials.
type Row struct{ Start, End, Username, Password string }

// Host is one BMC to process.
type Host struct{ IP, Username, Password string }

// Expand returns the IPv4 addresses between start and end (inclusive). An empty
// end means a single address; a CIDR in start (with empty end) expands to its
// host addresses, excluding network and broadcast for prefixes up to /30.
func Expand(start, end string) ([]string, error) {
	start, end = strings.TrimSpace(start), strings.TrimSpace(end)
	if strings.Contains(start, "/") {
		if end != "" {
			return nil, fmt.Errorf("%q: end_ip must be empty when start_ip is a CIDR", start)
		}
		return expandCIDR(start)
	}
	a, err := netip.ParseAddr(start)
	if err != nil || !a.Is4() {
		return nil, fmt.Errorf("invalid start_ip %q", start)
	}
	if end == "" {
		end = start
	}
	b, err := netip.ParseAddr(end)
	if err != nil || !b.Is4() {
		return nil, fmt.Errorf("invalid end_ip %q", end)
	}
	if b.Less(a) {
		return nil, fmt.Errorf("end_ip %s is before start_ip %s", end, start)
	}
	var out []string
	for ip := a; ; ip = ip.Next() {
		if len(out) >= maxRange {
			return nil, fmt.Errorf("range %s-%s exceeds %d addresses", start, end, maxRange)
		}
		out = append(out, ip.String())
		if ip == b {
			break
		}
	}
	return out, nil
}

func expandCIDR(s string) ([]string, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() {
		return nil, fmt.Errorf("invalid CIDR %q", s)
	}
	p = p.Masked()
	if 1<<(32-p.Bits()) > maxRange {
		return nil, fmt.Errorf("CIDR %s exceeds %d addresses", s, maxRange)
	}
	var out []string
	for ip := p.Addr(); p.Contains(ip); ip = ip.Next() {
		out = append(out, ip.String())
	}
	if p.Bits() <= 30 {
		out = out[1 : len(out)-1]
	}
	return out, nil
}

// Read parses the input CSV (header: start_ip,end_ip,username,password).
// A UTF-8 BOM, CRLF line endings and blank lines are tolerated.
func Read(path string) ([]Row, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1 // short rows are padded, see get below
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("%s: reading header: %w", path, err)
	}
	idx := map[string]int{}
	for i, h := range header {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	for _, k := range []string{"start_ip", "end_ip", "username", "password"} {
		if _, ok := idx[k]; !ok {
			return nil, fmt.Errorf("%s: missing column %q", path, k)
		}
	}
	var rows []Row
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		field := func(k string) string {
			if i := idx[k]; i < len(rec) {
				return rec[i]
			}
			return ""
		}
		row := Row{
			Start:    strings.TrimSpace(field("start_ip")),
			End:      strings.TrimSpace(field("end_ip")),
			Username: strings.TrimSpace(field("username")),
			Password: field("password"), // passwords are kept verbatim
		}
		if row == (Row{}) { // blank or ",,," line (e.g. a trailing spreadsheet row)
			continue
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// Hosts flattens rows into one Host per address. An address that appears twice
// keeps its first credentials, so a BMC is never handled by two workers. Invalid
// rows do not stop the others: the hosts of the valid rows are returned together
// with an error that lists every invalid row.
func Hosts(rows []Row) ([]Host, error) {
	var out []Host
	var errs []error
	seen := map[string]bool{}
	for i, row := range rows {
		ips, err := Expand(row.Start, row.End)
		if err != nil {
			errs = append(errs, fmt.Errorf("row %d: %w", i+1, err))
			continue
		}
		for _, ip := range ips {
			if seen[ip] {
				continue
			}
			seen[ip] = true
			out = append(out, Host{IP: ip, Username: row.Username, Password: row.Password})
		}
	}
	return out, errors.Join(errs...)
}

// PermissionWarning returns a message when the file holding passwords is
// readable by group or others (POSIX only), else "".
func PermissionWarning(path string) string {
	if runtime.GOOS == "windows" {
		return ""
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm()&0o077 == 0 {
		return ""
	}
	return fmt.Sprintf("%s contains passwords and is readable by other users (mode %04o); consider chmod 600", path, fi.Mode().Perm())
}
