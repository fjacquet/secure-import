# sbmgr Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `sbmgr`, a single-binary Go CLI that manages Secure Boot and the UEFI `db` certificate store over Redfish on a fleet of BMCs (Dell iDRAC9/iDRAC10, HPE iLO, Lenovo XCC, Supermicro).

**Architecture:** A common Redfish client (sessions, link discovery, ExtendedInfo parsing, task polling) sits under one `Platform` driver per vendor. An `actions` orchestrator turns the nine CLI actions into driver calls and a `report.Result`; a worker pool runs it per host; `report` writes CSV (same columns as the Python script) or JSON.

**Tech Stack:** Go 1.27 (installed: go1.27.1), standard library only, module name `sbmgr`.

**Spec:** `docs/superpowers/specs/2026-10-05-secure-boot-manager-go-design.md` (ADRs in `docs/adr/`).

**Commits:** every commit ends with the trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Commands below use two `-m` flags to add it.

## Global Constraints

- Go 1.27, standard library only, no third-party dependency.
- Success is decided by each driver from `@Message.ExtendedInfo`, never by HTTP status alone (ADR 0004).
- No hardcoded Redfish URIs on the nominal path: start at `/redfish/v1/` and follow `@odata.id` (ADR 0002); a hardcoded path is only a last-resort fallback.
- Secrets (passwords, tokens) are never logged and never written to output.
- CSV output keeps the Python columns in the same order, plus a final `Platform` column.
  Secure Boot columns: `IP Address, Action, Name, Description, Current Status, Current Boot, Current Mode, Current Policy, New Policy, Certificates URI, New Status, Success, Change Message, Error, Platform`.
  DB columns: `IP Address, Action, Success, Message, Error, Certificate Count, Platform`.
- Exit codes: 0 all hosts succeeded, 1 at least one host failed, 2 usage error.
- Pending BIOS changes are reported as `<Status> (Pending - Reboot Required)`; the tool never reboots a server.
- TLS is not verified by default (self-signed BMCs); `--verify-tls` and `--ca-file` enable verification.
- Every Redfish session opened is closed (`DELETE`); Supermicro documents a 16-session limit per BMC.
- Formatting: if `gofmt -l` lists a file, run `gofmt -w` on it and re-run the step; test files use aligned structs that gofmt may re-space.
- Drivers not validated on hardware (iDRAC10, iLO, Lenovo, Supermicro) must say so in `--help` output.

## Review Focus

Inputs and conditions the spec implies but that no happy-path test covers; each has a test in the task that owns the code.

1. CSV with BOM, CRLF line endings, blank lines, spaces around fields and a password containing a space (Task 2).
2. IP range with `end_ip` before `start_ip`, a range that crosses a /24, and a huge range or CIDR that must error, not hang or allocate millions of addresses (Task 2).
3. One BMC unreachable or erroring must not stop the others, and every host still gets a result row, in input order (Task 14).
4. Session leak: every host that logged in gets exactly one session `DELETE`, even when the action fails (Task 14).
5. Certificate file missing, empty, DER instead of PEM, or larger than the device limit (Tasks 6, 9).

## File Structure

```
go.mod                               module sbmgr, go 1.27
Makefile                             build, test, vet, check, build-all
cmd/sbmgr/main.go                    flags, wiring, exit codes
cmd/sbmgr/main_test.go               usage/validation tests
internal/inventory/inventory.go      CSV rows, IP expansion, permission warning
internal/redfish/client.go           HTTP client, sessions, discovery, PATCH/ETag, upload
internal/redfish/messages.go         ExtendedInfo parsing, success patterns
internal/redfish/tasks.go            task monitor polling
internal/redfish/path.go             MSYS path sanitising
internal/platform/platform.go        Platform interface, shared types, action names
internal/report/report.go            Result, CSV and JSON writers
internal/stdsb/stdsb.go              standard SecureBoot helper, PEM conversion
internal/stdsb/driver.go             generic driver (iLO, Supermicro)
internal/dell/driver.go              iDRAC9/iDRAC10 status, enable/disable, policy
internal/dell/certs.go               iDRAC DB certificate operations
internal/lenovo/driver.go            Lenovo XCC driver
internal/detect/detect.go            platform detection and driver factory
internal/actions/actions.go          action orchestration -> report.Result
internal/runner/runner.go            worker pool, session lifecycle
internal/testbmc/testbmc.go          fake BMC for tests
```

---

### Task 1: Project scaffold

**Files:**
- Create: `go.mod`, `Makefile`, `cmd/sbmgr/main.go`
- Modify: `.gitignore`

**Interfaces:**
- Produces: module `sbmgr`; `make build|test|vet|check|build-all`.

- [ ] **Step 1: Create `go.mod`**

```
module sbmgr

go 1.27
```

- [ ] **Step 2: Create `cmd/sbmgr/main.go` (temporary stub, replaced in Task 15)**

```go
package main

import "fmt"

func main() { fmt.Println("sbmgr") }
```

- [ ] **Step 3: Create `Makefile`** (the `build-all` recipe lines below must be indented with a real TAB character)

```make
BIN := bin/sbmgr

.PHONY: build test vet check build-all clean

build: ; go build -o $(BIN) ./cmd/sbmgr
test: ; go test ./...
vet: ; go vet ./...
check: ; @test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
build-all:
	@for t in linux/amd64 linux/arm64 windows/amd64 darwin/arm64 darwin/amd64; do \
		os=$${t%/*}; arch=$${t#*/}; ext=""; [ $$os = windows ] && ext=".exe"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags="-s -w" -o bin/sbmgr-$$os-$$arch$$ext ./cmd/sbmgr || exit 1; \
		echo "built bin/sbmgr-$$os-$$arch$$ext"; \
	done
clean: ; rm -rf bin
```

- [ ] **Step 4: Ignore build output**

Append `bin/` as a new line at the end of `.gitignore`.

- [ ] **Step 5: Verify**

Run: `cd /Users/fjacquet/Projects/secure-import && go build ./... && go vet ./... && make check`
Expected: no output, exit 0.

- [ ] **Step 6: Commit**

```bash
git add go.mod Makefile cmd .gitignore
git commit -m "chore: scaffold Go module and Makefile" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Inventory (CSV and IP expansion)

**Files:**
- Create: `internal/inventory/inventory.go`
- Test: `internal/inventory/inventory_test.go`

**Interfaces:**
- Produces:
  - `type Row struct{ Start, End, Username, Password string }`
  - `type Host struct{ IP, Username, Password string }`
  - `func Expand(start, end string) ([]string, error)`
  - `func Read(path string) ([]Row, error)`
  - `func Hosts(rows []Row) ([]Host, error)`
  - `func PermissionWarning(path string) string`

- [ ] **Step 1: Write the failing tests**

```go
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
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/inventory/`
Expected: FAIL (`undefined: Expand`).

- [ ] **Step 3: Implement `internal/inventory/inventory.go`**

```go
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
		get := func(k string) string { return strings.TrimSpace(rec[idx[k]]) }
		rows = append(rows, Row{
			Start:    get("start_ip"),
			End:      get("end_ip"),
			Username: get("username"),
			Password: rec[idx["password"]], // passwords are kept verbatim
		})
	}
	return rows, nil
}

// Hosts flattens rows into one Host per address.
func Hosts(rows []Row) ([]Host, error) {
	var out []Host
	for i, row := range rows {
		ips, err := Expand(row.Start, row.End)
		if err != nil {
			return nil, fmt.Errorf("row %d: %w", i+1, err)
		}
		for _, ip := range ips {
			out = append(out, Host{IP: ip, Username: row.Username, Password: row.Password})
		}
	}
	return out, nil
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
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/inventory/ && gofmt -l internal/inventory`
Expected: `ok` and no gofmt output.

- [ ] **Step 5: Commit**

```bash
git add internal/inventory
git commit -m "feat(inventory): read CSV and expand IP ranges and CIDRs" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Fake BMC and Redfish client core

**Files:**
- Create: `internal/testbmc/testbmc.go`
- Create: `internal/redfish/client.go`, `internal/redfish/path.go`
- Test: `internal/redfish/client_test.go`

**Interfaces:**
- Produces (`testbmc`):
  - `func New(t testing.TB) *Server` (embeds `*httptest.Server`; `s.URL` is `http://127.0.0.1:port`)
  - `func (s *Server) Handle(method, path string, h http.HandlerFunc)`
  - `func (s *Server) JSON(method, path string, status int, body any)`
  - `func (s *Server) JSONH(method, path string, status int, hdr map[string]string, body any)`
  - `func (s *Server) Requests() []Req`, `func (s *Server) Count(method, path string) int`
  - `func (s *Server) Redfish(vendor, systemID, managerModel, firmware string)` (root, sessions, one system, one BMC manager)
  - `func (s *Server) StdSecureBoot(sys string, enable bool, mode string, dbCerts int)`
  - `func Link(path string) map[string]string`, `func WriteJSON(w http.ResponseWriter, status int, body any)`
  - `type Req struct{ Method, Path, RawQuery, Body string; Header http.Header }`
- Produces (`redfish`):
  - `type Options struct{ Timeout, TaskTimeout, PollInterval time.Duration; VerifyTLS bool; CAFile string; NoWait bool }`
  - `type Link struct{ ODataID string }`; `type Root struct{ Vendor, Product string; Links struct{Sessions Link}; Systems, Managers Link }`
  - `type Response struct{ Status int; Header http.Header; Body []byte }`; `type HTTPError struct{ Status int; Body string }`
  - `func New(host, user, pass string, opts Options) (*Client, error)` (`host` is `1.2.3.4`, `host:port`, or a full `http(s)://` URL)
  - `func (c *Client) Login(ctx) error`, `Logout(ctx)`, `Root(ctx) (*Root, error)`
  - `func (c *Client) Do(ctx, method, path string, header http.Header, body []byte) (*Response, error)` (non-2xx returns the `*Response` **and** a `*HTTPError`)
  - `func (c *Client) GetJSON(ctx, path string, out any) error`
  - `func (c *Client) SendJSON(ctx, method, path string, payload any) (*Response, error)`
  - `func (c *Client) Patch(ctx, path string, payload any) (*Response, error)` (retries once with `If-Match` on 428)
  - `func (c *Client) Upload(ctx, path, field, filename string, data []byte) (*Response, error)`
  - `func (c *Client) Members(ctx, path string) ([]Link, error)`, `SystemPath(ctx) (string, error)`, `Manager(ctx) (ManagerInfo, error)`, `NoWait() bool`
  - `type ManagerInfo struct{ Model, FirmwareVersion string }`; `func SanitizePath(p string) string`

- [ ] **Step 1: Create the fake BMC `internal/testbmc/testbmc.go`**

```go
// Package testbmc is a minimal fake Redfish BMC for tests.
package testbmc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Req is one recorded request.
type Req struct {
	Method, Path, RawQuery, Body string
	Header                       http.Header
}

// Server is a fake BMC. Unknown routes answer 404 with a Redfish error body.
type Server struct {
	*httptest.Server
	mu     sync.Mutex
	routes map[string]http.HandlerFunc
	reqs   []Req
}

// New starts a fake BMC closed automatically at test end.
func New(t testing.TB) *Server {
	s := &Server{routes: map[string]http.HandlerFunc{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.reqs = append(s.reqs, Req{r.Method, r.URL.Path, r.URL.RawQuery, string(body), r.Header.Clone()})
	h := s.routes[r.Method+" "+r.URL.Path]
	s.mu.Unlock()
	if h == nil {
		WriteJSON(w, 404, map[string]any{"error": map[string]any{
			"code": "Base.1.12.ResourceMissingAtURI", "message": "no route " + r.Method + " " + r.URL.Path}})
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	h(w, r)
}

// Handle registers (or replaces) the handler for a method and exact path.
func (s *Server) Handle(method, path string, h http.HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes[method+" "+path] = h
}

// JSON registers a fixed JSON answer.
func (s *Server) JSON(method, path string, status int, body any) {
	s.JSONH(method, path, status, nil, body)
}

// JSONH registers a fixed JSON answer with extra response headers.
func (s *Server) JSONH(method, path string, status int, hdr map[string]string, body any) {
	s.Handle(method, path, func(w http.ResponseWriter, _ *http.Request) {
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		WriteJSON(w, status, body)
	})
}

// Requests returns a copy of all requests received so far.
func (s *Server) Requests() []Req {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Req(nil), s.reqs...)
}

// Count returns how many requests matched method and path.
func (s *Server) Count(method, path string) int {
	n := 0
	for _, r := range s.Requests() {
		if r.Method == method && r.Path == path {
			n++
		}
	}
	return n
}

// WriteJSON writes a JSON body with the given status (no body when nil).
func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

// Link builds an {"@odata.id": path} object.
func Link(path string) map[string]string { return map[string]string{"@odata.id": path} }

// Redfish registers the service root, session endpoints, one system and one BMC manager.
func (s *Server) Redfish(vendor, systemID, managerModel, firmware string) {
	s.JSON("GET", "/redfish/v1/", 200, map[string]any{
		"Vendor": vendor, "Product": "Test BMC",
		"Links":    map[string]any{"Sessions": Link("/redfish/v1/SessionService/Sessions")},
		"Systems":  Link("/redfish/v1/Systems"),
		"Managers": Link("/redfish/v1/Managers"),
	})
	s.JSONH("POST", "/redfish/v1/SessionService/Sessions", 201,
		map[string]string{"X-Auth-Token": "tok", "Location": "/redfish/v1/SessionService/Sessions/1"}, map[string]any{})
	s.JSON("DELETE", "/redfish/v1/SessionService/Sessions/1", 204, nil)
	s.JSON("GET", "/redfish/v1/Systems", 200, map[string]any{"Members": []any{Link("/redfish/v1/Systems/" + systemID)}})
	s.JSON("GET", "/redfish/v1/Managers", 200, map[string]any{"Members": []any{Link("/redfish/v1/Managers/BMC")}})
	s.JSON("GET", "/redfish/v1/Managers/BMC", 200, map[string]any{
		"ManagerType": "BMC", "Model": managerModel, "FirmwareVersion": firmware})
}

// StdSecureBoot registers a DMTF-standard SecureBoot tree under system sys:
// system -> SecureBoot -> SecureBootDatabases -> db -> Certificates (dbCerts members).
func (s *Server) StdSecureBoot(sys string, enable bool, mode string, dbCerts int) {
	base := "/redfish/v1/Systems/" + sys
	sb := base + "/SecureBoot"
	dbs := sb + "/SecureBootDatabases"
	s.JSON("GET", base, 200, map[string]any{"SecureBoot": Link(sb), "Bios": Link(base + "/Bios")})
	s.JSON("GET", sb, 200, map[string]any{
		"Name": "Secure Boot", "Description": "UEFI Secure Boot Configuration",
		"SecureBootEnable": enable, "SecureBootCurrentBoot": "Disabled", "SecureBootMode": mode,
		"SecureBootDatabases": Link(dbs),
	})
	s.JSON("GET", dbs, 200, map[string]any{"Members": []any{
		Link(dbs + "/PK"), Link(dbs + "/KEK"), Link(dbs + "/db"), Link(dbs + "/dbx")}})
	s.JSON("GET", dbs+"/db", 200, map[string]any{"Certificates": Link(dbs + "/db/Certificates")})
	members := []any{}
	for i := 1; i <= dbCerts; i++ {
		members = append(members, Link(fmt.Sprintf("%s/db/Certificates/%d", dbs, i)))
	}
	s.JSON("GET", dbs+"/db/Certificates", 200, map[string]any{"Members": members})
}
```

- [ ] **Step 2: Write the failing client tests `internal/redfish/client_test.go`**

```go
package redfish

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"sbmgr/internal/testbmc"
)

func newClient(t *testing.T, s *testbmc.Server, opts Options) *Client {
	t.Helper()
	c, err := New(s.URL, "root", "pw", opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoginUsesSessionTokenAndLogoutDeletesSession(t *testing.T) {
	s := testbmc.New(t)
	s.Redfish("Dell", "S1", "16G", "7.0.0.0")
	c := newClient(t, s, Options{})
	ctx := context.Background()
	if err := c.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(ctx, http.MethodGet, "/redfish/v1/Systems", nil, nil); err != nil {
		t.Fatal(err)
	}
	reqs := s.Requests()
	for _, r := range reqs {
		if r.Method == "POST" && r.Header.Get("Authorization") != "" {
			t.Error("session creation must not carry Basic credentials")
		}
	}
	last := reqs[len(reqs)-1]
	if last.Header.Get("X-Auth-Token") != "tok" || last.Header.Get("Authorization") != "" {
		t.Errorf("after login want X-Auth-Token only, got headers %v", last.Header)
	}
	c.Logout(ctx)
	if n := s.Count("DELETE", "/redfish/v1/SessionService/Sessions/1"); n != 1 {
		t.Errorf("session DELETE count = %d, want 1", n)
	}
}

func TestLoginFallsBackToBasic(t *testing.T) {
	s := testbmc.New(t)
	s.Redfish("Dell", "S1", "16G", "7.0.0.0")
	s.JSON("POST", "/redfish/v1/SessionService/Sessions", 404, nil)
	c := newClient(t, s, Options{})
	ctx := context.Background()
	if err := c.Login(ctx); err != nil {
		t.Fatalf("Login should fall back to Basic, got %v", err)
	}
	if _, err := c.Do(ctx, http.MethodGet, "/redfish/v1/Systems", nil, nil); err != nil {
		t.Fatal(err)
	}
	reqs := s.Requests()
	if got := reqs[len(reqs)-1].Header.Get("Authorization"); !strings.HasPrefix(got, "Basic ") {
		t.Errorf("Authorization = %q, want Basic", got)
	}
	c.Logout(ctx)
	if n := s.Count("DELETE", "/redfish/v1/SessionService/Sessions/1"); n != 0 {
		t.Errorf("no session was opened, DELETE count = %d", n)
	}
}

func TestDoReturnsHTTPErrorWithBody(t *testing.T) {
	s := testbmc.New(t)
	s.JSON("GET", "/x", 500, map[string]string{"error": "boom"})
	c := newClient(t, s, Options{})
	resp, err := c.Do(context.Background(), http.MethodGet, "/x", nil, nil)
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 500 || !strings.Contains(he.Error(), "boom") {
		t.Fatalf("err = %v, want HTTPError 500 containing boom", err)
	}
	if resp == nil || resp.Status != 500 {
		t.Errorf("response should accompany the error, got %+v", resp)
	}
}

func TestPatchRetriesWithETagOn428(t *testing.T) {
	s := testbmc.New(t)
	var patches atomic.Int32
	s.Handle("PATCH", "/x", func(w http.ResponseWriter, r *http.Request) {
		patches.Add(1)
		if r.Header.Get("If-Match") != `"abc"` {
			testbmc.WriteJSON(w, 428, nil)
			return
		}
		testbmc.WriteJSON(w, 200, map[string]any{})
	})
	s.Handle("GET", "/x", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"abc"`)
		testbmc.WriteJSON(w, 200, map[string]any{})
	})
	c := newClient(t, s, Options{})
	if _, err := c.Patch(context.Background(), "/x", map[string]bool{"a": true}); err != nil {
		t.Fatal(err)
	}
	if patches.Load() != 2 {
		t.Errorf("PATCH attempts = %d, want 2", patches.Load())
	}
}

func TestUploadSendsMultipartFileField(t *testing.T) {
	s := testbmc.New(t)
	got := make(chan [2]string, 1)
	s.Handle("POST", "/up", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			testbmc.WriteJSON(w, 400, nil)
			return
		}
		f, h, err := r.FormFile("file")
		if err != nil {
			testbmc.WriteJSON(w, 400, nil)
			return
		}
		b, _ := io.ReadAll(f)
		got <- [2]string{h.Filename, string(b)}
		testbmc.WriteJSON(w, 200, map[string]any{})
	})
	c := newClient(t, s, Options{})
	if _, err := c.Upload(context.Background(), "/up", "file", "cert.der", []byte("DER")); err != nil {
		t.Fatal(err)
	}
	if v := <-got; v[0] != "cert.der" || v[1] != "DER" {
		t.Errorf("got %v", v)
	}
}

func TestAbsoluteURLIsRewrittenToBaseHost(t *testing.T) {
	s := testbmc.New(t)
	s.Redfish("Dell", "S1", "16G", "7.0.0.0")
	c := newClient(t, s, Options{})
	if _, err := c.Do(context.Background(), http.MethodGet, "https://evil.example/redfish/v1/Systems", nil, nil); err != nil {
		t.Fatalf("absolute URL must be sent to the BMC host, got %v", err)
	}
}

func TestSystemPathAndManager(t *testing.T) {
	s := testbmc.New(t)
	s.Redfish("Dell", "System.Embedded.1", "17G Monolithic", "1.30.60.50")
	c := newClient(t, s, Options{})
	ctx := context.Background()
	sys, err := c.SystemPath(ctx)
	if err != nil || sys != "/redfish/v1/Systems/System.Embedded.1" {
		t.Fatalf("SystemPath = %q, %v", sys, err)
	}
	m, err := c.Manager(ctx)
	if err != nil || m.Model != "17G Monolithic" || m.FirmwareVersion != "1.30.60.50" {
		t.Fatalf("Manager = %+v, %v", m, err)
	}
}

func TestSanitizePath(t *testing.T) {
	cases := map[string]string{
		"":              "",
		"/redfish/v1/x": "/redfish/v1/x",
		"redfish/v1/x":  "/redfish/v1/x",
		"C:/Program Files/Git/redfish/v1/Systems/S/SecureBoot/Certificates/DB/Cust.7": "/redfish/v1/Systems/S/SecureBoot/Certificates/DB/Cust.7",
		`C:\Program Files\Git\redfish\v1\x`:                                           "/redfish/v1/x",
	}
	for in, want := range cases {
		if got := SanitizePath(in); got != want {
			t.Errorf("SanitizePath(%q) = %q, want %q", in, got, want)
		}
	}
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/redfish/`
Expected: FAIL (`undefined: New`).

- [ ] **Step 4: Implement `internal/redfish/path.go`**

```go
package redfish

import (
	"regexp"
	"strings"
)

var msysRe = regexp.MustCompile(`^[A-Za-z]:[/\\].*?[/\\](redfish[/\\].*)$`)

// SanitizePath reverses the MSYS/Git Bash conversion of "/redfish/..." arguments
// into "C:/Program Files/Git/redfish/..." and guarantees a leading slash.
func SanitizePath(p string) string {
	if p == "" {
		return p
	}
	if m := msysRe.FindStringSubmatch(p); m != nil {
		p = "/" + strings.ReplaceAll(m[1], `\`, "/")
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}
```

- [ ] **Step 5: Implement `internal/redfish/client.go`**

```go
// Package redfish is a small Redfish (DMTF DSP0266) HTTP client: sessions,
// link discovery, PATCH with ETag retry, multipart upload, ExtendedInfo
// parsing and task monitoring.
package redfish

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"strings"
	"time"
)

const rootPath = "/redfish/v1/"

// Options tunes a Client. Zero values select the defaults noted below.
type Options struct {
	Timeout      time.Duration // per request, default 30s
	TaskTimeout  time.Duration // task polling budget, default 120s
	PollInterval time.Duration // task polling interval, default 2s
	VerifyTLS    bool          // false: accept self-signed BMC certificates
	CAFile       string        // PEM bundle; implies verification
	NoWait       bool          // do not follow asynchronous tasks
}

// Link is a Redfish {"@odata.id": ...} reference.
type Link struct {
	ODataID string `json:"@odata.id"`
}

// Root is the part of the service root the tool needs.
type Root struct {
	Vendor  string `json:"Vendor"`
	Product string `json:"Product"`
	Links   struct {
		Sessions Link `json:"Sessions"`
	} `json:"Links"`
	Systems  Link `json:"Systems"`
	Managers Link `json:"Managers"`
}

// ManagerInfo describes the BMC itself.
type ManagerInfo struct{ Model, FirmwareVersion string }

// Response is a completed HTTP exchange.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// HTTPError is returned for any status other than 200, 201, 202 or 204.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, e.Body) }

// Client talks to one BMC. It is not safe for concurrent use.
type Client struct {
	base, user, pass string
	opts             Options
	hc               *http.Client
	token, session   string
	root             *Root
	system           string
}

// New builds a client. host may be "1.2.3.4", "1.2.3.4:8443" or a full URL.
func New(host, user, pass string, opts Options) (*Client, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.TaskTimeout == 0 {
		opts.TaskTimeout = 120 * time.Second
	}
	if opts.PollInterval == 0 {
		opts.PollInterval = 2 * time.Second
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: !opts.VerifyTLS && opts.CAFile == ""} //nolint:gosec // BMCs are self-signed; opt-in verification
	if opts.CAFile != "" {
		pem, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificate found in %s", opts.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	base := host
	if !strings.Contains(host, "://") {
		base = "https://" + host
	}
	return &Client{
		base: strings.TrimRight(base, "/"), user: user, pass: pass, opts: opts,
		hc: &http.Client{Transport: tr, Timeout: opts.Timeout},
	}, nil
}

// NoWait reports whether asynchronous tasks must not be followed.
func (c *Client) NoWait() bool { return c.opts.NoWait }

// resolve turns a path or absolute URL into a URL on this client's BMC.
// An absolute URL is rewritten to its path so tokens never leave the BMC host.
func (c *Client) resolve(path string) string {
	if strings.Contains(path, "://") {
		if u, err := url.Parse(path); err == nil {
			path = u.RequestURI()
		}
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return c.base + path
}

// Do sends a request with the session token (or Basic credentials). Non-2xx
// answers return both the Response and an *HTTPError.
func (c *Client) Do(ctx context.Context, method, path string, header http.Header, body []byte) (*Response, error) {
	return c.do(ctx, method, path, header, body, true)
}

func (c *Client) do(ctx context.Context, method, path string, header http.Header, body []byte, auth bool) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.resolve(path), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	for k, vs := range header {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if auth {
		if c.token != "" {
			req.Header.Set("X-Auth-Token", c.token)
		} else {
			req.SetBasicAuth(c.user, c.pass)
		}
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	r := &Response{Status: resp.StatusCode, Header: resp.Header, Body: data}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent:
		return r, nil
	}
	return r, &HTTPError{Status: resp.StatusCode, Body: string(data)}
}

// GetJSON GETs path and decodes the JSON body into out.
func (c *Client) GetJSON(ctx context.Context, path string, out any) error {
	resp, err := c.Do(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(resp.Body, out); err != nil {
		return fmt.Errorf("JSON decode error: %w", err)
	}
	return nil
}

// SendJSON sends payload as JSON with the given method.
func (c *Client) SendJSON(ctx context.Context, method, path string, payload any) (*Response, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return c.Do(ctx, method, path, http.Header{"Content-Type": {"application/json"}}, b)
}

// Patch sends a JSON PATCH; on 428 Precondition Required it re-reads the
// resource, takes its ETag and retries once with If-Match.
func (c *Client) Patch(ctx context.Context, path string, payload any) (*Response, error) {
	resp, err := c.SendJSON(ctx, http.MethodPatch, path, payload)
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusPreconditionRequired {
		return resp, err
	}
	get, gerr := c.Do(ctx, http.MethodGet, path, nil, nil)
	if gerr != nil || get.Header.Get("ETag") == "" {
		return resp, err
	}
	b, _ := json.Marshal(payload)
	return c.Do(ctx, http.MethodPatch, path, http.Header{
		"Content-Type": {"application/json"}, "If-Match": {get.Header.Get("ETag")}}, b)
}

// Upload POSTs data as a multipart/form-data file part named field.
func (c *Client) Upload(ctx context.Context, path, field, filename string, data []byte) (*Response, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q; filename=%q`, field, filename))
	h.Set("Content-Type", "application/octet-stream")
	part, err := mw.CreatePart(h)
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(data); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	return c.Do(ctx, http.MethodPost, path, http.Header{"Content-Type": {mw.FormDataContentType()}}, buf.Bytes())
}

// Root returns the (cached) service root.
func (c *Client) Root(ctx context.Context) (*Root, error) {
	if c.root != nil {
		return c.root, nil
	}
	var r Root
	if err := c.GetJSON(ctx, rootPath, &r); err != nil {
		return nil, fmt.Errorf("service root: %w", err)
	}
	c.root = &r
	return c.root, nil
}

// Login opens a Redfish session. When the BMC refuses sessions (401, 403, 404,
// 405) the client stays on HTTP Basic and Login returns nil.
func (c *Client) Login(ctx context.Context) error {
	root, err := c.Root(ctx)
	if err != nil {
		return err
	}
	sessions := root.Links.Sessions.ODataID
	if sessions == "" {
		sessions = "/redfish/v1/SessionService/Sessions" // last-resort fallback
	}
	payload, err := json.Marshal(map[string]string{"UserName": c.user, "Password": c.pass})
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodPost, sessions, http.Header{"Content-Type": {"application/json"}}, payload, false)
	if err != nil {
		var he *HTTPError
		if errors.As(err, &he) {
			switch he.Status {
			case 401, 403, 404, 405:
				return nil
			}
		}
		return err
	}
	if tok := resp.Header.Get("X-Auth-Token"); tok != "" {
		c.token = tok
		c.session = resp.Header.Get("Location")
	}
	return nil
}

// Logout closes the session opened by Login, if any. Errors are ignored.
func (c *Client) Logout(ctx context.Context) {
	if c.session == "" {
		return
	}
	_, _ = c.do(ctx, http.MethodDelete, c.session, nil, nil, true)
	c.token, c.session = "", ""
}

type collection struct {
	Members []Link `json:"Members"`
}

// Members lists the members of a Redfish collection.
func (c *Client) Members(ctx context.Context, path string) ([]Link, error) {
	var col collection
	if err := c.GetJSON(ctx, path, &col); err != nil {
		return nil, err
	}
	return col.Members, nil
}

// SystemPath returns the URI of the first computer system, discovered from the root.
func (c *Client) SystemPath(ctx context.Context) (string, error) {
	if c.system != "" {
		return c.system, nil
	}
	root, err := c.Root(ctx)
	if err != nil {
		return "", err
	}
	coll := root.Systems.ODataID
	if coll == "" {
		coll = "/redfish/v1/Systems" // last-resort fallback
	}
	members, err := c.Members(ctx, coll)
	if err != nil {
		return "", fmt.Errorf("systems: %w", err)
	}
	if len(members) == 0 || members[0].ODataID == "" {
		return "", errors.New("no computer system found")
	}
	c.system = members[0].ODataID
	return c.system, nil
}

// Manager returns the BMC manager's model and firmware version.
func (c *Client) Manager(ctx context.Context) (ManagerInfo, error) {
	root, err := c.Root(ctx)
	if err != nil {
		return ManagerInfo{}, err
	}
	coll := root.Managers.ODataID
	if coll == "" {
		coll = "/redfish/v1/Managers" // last-resort fallback
	}
	members, err := c.Members(ctx, coll)
	if err != nil {
		return ManagerInfo{}, fmt.Errorf("managers: %w", err)
	}
	var first *ManagerInfo
	for _, m := range members {
		var doc struct {
			ManagerType     string `json:"ManagerType"`
			Model           string `json:"Model"`
			FirmwareVersion string `json:"FirmwareVersion"`
		}
		if err := c.GetJSON(ctx, m.ODataID, &doc); err != nil {
			continue
		}
		info := ManagerInfo{Model: doc.Model, FirmwareVersion: doc.FirmwareVersion}
		if doc.ManagerType == "BMC" {
			return info, nil
		}
		if first == nil {
			first = &info
		}
	}
	if first != nil {
		return *first, nil
	}
	return ManagerInfo{}, errors.New("no manager found")
}
```

- [ ] **Step 6: Run to verify pass**

Run: `go test ./internal/redfish/ && go vet ./internal/... && gofmt -l internal`
Expected: `ok`, no vet output, no gofmt output.

- [ ] **Step 7: Commit**

```bash
git add internal/testbmc internal/redfish
git commit -m "feat(redfish): client with sessions, link discovery, ETag retry and upload" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 4: ExtendedInfo parsing and task monitoring

**Files:**
- Create: `internal/redfish/messages.go`, `internal/redfish/tasks.go`
- Test: `internal/redfish/messages_test.go`, `internal/redfish/tasks_test.go`

**Interfaces:**
- Consumes: `Client.Do`, `Client.opts` from Task 3.
- Produces:
  - `type Message struct{ ID, Text, Severity, Resolution string }`
  - `func ParseMessages(body []byte) []Message` (handles top-level and `error` envelopes)
  - `func IsSuccessID(id string) bool` (pattern only), `func IsSuccess(m Message) bool` (pattern and severity not `Critical`), `func NeedsReboot(msgs []Message) bool`, `func Summarize(msgs []Message) string`
  - `type Outcome int` with `OutcomeScheduled`, `OutcomeCompleted`, `OutcomeFailed`
  - `type TaskResult struct{ Outcome Outcome; State, Status, Detail string }`
  - `func (c *Client) WaitTask(ctx context.Context, location string) (TaskResult, error)`

- [ ] **Step 1: Write the failing message tests `internal/redfish/messages_test.go`**

```go
package redfish

import "testing"

func TestParseMessagesTopLevelAndErrorEnvelope(t *testing.T) {
	ok := []byte(`{"@Message.ExtendedInfo":[{"MessageId":"Base.1.12.Success","Message":"The request completed successfully.","Severity":"OK","Resolution":"None"},{"MessageId":"IDRAC.2.9.SYS430","Message":"done","Severity":"OK","Resolution":"Restart the server."}]}`)
	msgs := ParseMessages(ok)
	if len(msgs) != 2 || msgs[1].ID != "IDRAC.2.9.SYS430" || msgs[1].Resolution != "Restart the server." {
		t.Fatalf("msgs = %+v", msgs)
	}
	bad := []byte(`{"error":{"@Message.ExtendedInfo":[{"MessageId":"IDRAC.2.9.SYS011","Message":"Pending configuration values are already committed","Severity":"Warning"}]}}`)
	if msgs := ParseMessages(bad); len(msgs) != 1 || msgs[0].ID != "IDRAC.2.9.SYS011" {
		t.Fatalf("error envelope: msgs = %+v", msgs)
	}
	for _, in := range []string{"", "not json", "{}"} {
		if msgs := ParseMessages([]byte(in)); len(msgs) != 0 {
			t.Errorf("ParseMessages(%q) = %+v, want none", in, msgs)
		}
	}
}

func TestIsSuccessIDIsVersionAgnosticAndCaseInsensitive(t *testing.T) {
	yes := []string{"Base.1.0.Success", "Base.1.12.Success", "IDRAC.2.9.SYS430", "iDRAC.1.6.SYS413", "iDRAC.1.6.SYS431", "Bios.1.0.BiosPropertyModified", "base.1.5.success"}
	no := []string{"Base.1.12.ResourceMissingAtURI", "IDRAC.2.9.SYS011", "Base.Success", ""}
	for _, id := range yes {
		if !IsSuccessID(id) {
			t.Errorf("IsSuccessID(%q) = false, want true", id)
		}
	}
	for _, id := range no {
		if IsSuccessID(id) {
			t.Errorf("IsSuccessID(%q) = true, want false", id)
		}
	}
}

// IDRAC.2.9.SYS403 ("resource not found", Critical) matches the SYS4xx success
// pattern, so severity must be part of the verdict. The Python script missed this.
func TestIsSuccessRequiresANonCriticalSeverity(t *testing.T) {
	cases := []struct {
		m    Message
		want bool
	}{
		{Message{ID: "IDRAC.2.9.SYS430", Severity: "OK"}, true},
		{Message{ID: "IDRAC.2.9.SYS430"}, true},
		{Message{ID: "Base.1.12.Success", Severity: "OK"}, true},
		{Message{ID: "IDRAC.2.9.SYS403", Severity: "Critical"}, false},
		{Message{ID: "IDRAC.2.9.SYS403", Severity: "critical"}, false},
		{Message{ID: "Base.1.12.ResourceMissingAtURI", Severity: "Critical"}, false},
	}
	for _, tc := range cases {
		if got := IsSuccess(tc.m); got != tc.want {
			t.Errorf("IsSuccess(%+v) = %v, want %v", tc.m, got, tc.want)
		}
	}
}

func TestNeedsRebootAndSummarize(t *testing.T) {
	msgs := []Message{{Text: "ok", Severity: "OK", Resolution: "None"}, {Text: "x", Severity: "Warning", Resolution: "Reboot the computer system."}}
	if !NeedsReboot(msgs) {
		t.Error("NeedsReboot = false, want true (Resolution mentions Reboot)")
	}
	if NeedsReboot(msgs[:1]) {
		t.Error("NeedsReboot = true, want false")
	}
	if got := Summarize(msgs); got != "OK: ok; Warning: x" {
		t.Errorf("Summarize = %q", got)
	}
}
```

- [ ] **Step 2: Write the failing task tests `internal/redfish/tasks_test.go`**

```go
package redfish

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sbmgr/internal/testbmc"
)

func taskClient(t *testing.T, s *testbmc.Server) *Client {
	t.Helper()
	c, err := New(s.URL, "u", "p", Options{PollInterval: 5 * time.Millisecond, TaskTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestWaitTaskScheduledStopsAtFirstPoll(t *testing.T) {
	s := testbmc.New(t)
	s.JSON("GET", "/redfish/v1/TaskService/Tasks/JID_1", 200, map[string]any{"TaskState": "New", "TaskStatus": "OK", "Name": "Config"})
	res, err := taskClient(t, s).WaitTask(context.Background(), "/redfish/v1/TaskService/Tasks/JID_1")
	if err != nil || res.Outcome != OutcomeScheduled {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if !strings.Contains(res.Detail, "State: New, Status: OK, Name: Config") {
		t.Errorf("detail = %q", res.Detail)
	}
}

func TestWaitTaskFollowsOpaqueLocationUntilCompleted(t *testing.T) {
	s := testbmc.New(t)
	var calls atomic.Int32
	s.Handle("GET", "/redfish/v1/TaskService/TaskMonitors/abc", func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			testbmc.WriteJSON(w, 200, map[string]any{"TaskState": "Running"})
			return
		}
		testbmc.WriteJSON(w, 200, map[string]any{"TaskState": "Completed", "TaskStatus": "OK"})
	})
	res, err := taskClient(t, s).WaitTask(context.Background(), "/redfish/v1/TaskService/TaskMonitors/abc")
	if err != nil || res.Outcome != OutcomeCompleted || calls.Load() != 2 {
		t.Fatalf("res = %+v, err = %v, calls = %d", res, err, calls.Load())
	}
}

func TestWaitTaskFailureAndTimeout(t *testing.T) {
	s := testbmc.New(t)
	s.JSON("GET", "/t/failed", 200, map[string]any{"TaskState": "Exception", "TaskStatus": "Critical", "Name": "N"})
	if res, err := taskClient(t, s).WaitTask(context.Background(), "/t/failed"); err != nil || res.Outcome != OutcomeFailed {
		t.Errorf("failed task: res = %+v, err = %v", res, err)
	}
	s.JSON("GET", "/t/stuck", 200, map[string]any{"TaskState": "Running"})
	if _, err := taskClient(t, s).WaitTask(context.Background(), "/t/stuck"); err == nil || !strings.Contains(err.Error(), "still") {
		t.Errorf("stuck task: err = %v, want timeout error", err)
	}
	if _, err := taskClient(t, s).WaitTask(context.Background(), "/t/missing"); err == nil || !strings.Contains(err.Error(), "failed to get task status") {
		t.Errorf("missing task: err = %v", err)
	}
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/redfish/`
Expected: FAIL (`undefined: ParseMessages`, `undefined: Outcome...`).

- [ ] **Step 4: Implement `internal/redfish/messages.go`**

```go
package redfish

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Message is one @Message.ExtendedInfo entry.
type Message struct{ ID, Text, Severity, Resolution string }

type rawMessage struct {
	MessageID  string `json:"MessageId"`
	Message    string `json:"Message"`
	Severity   string `json:"Severity"`
	Resolution string `json:"Resolution"`
}

// ParseMessages extracts ExtendedInfo from a body, either at the top level or
// inside an {"error": {...}} envelope. Unparseable bodies yield no messages.
func ParseMessages(body []byte) []Message {
	var doc struct {
		Info  []rawMessage `json:"@Message.ExtendedInfo"`
		Error struct {
			Info []rawMessage `json:"@Message.ExtendedInfo"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	var out []Message
	for _, m := range append(doc.Info, doc.Error.Info...) {
		out = append(out, Message{ID: m.MessageID, Text: m.Message, Severity: m.Severity, Resolution: m.Resolution})
	}
	return out
}

// Success MessageIds vary with firmware (Base.1.0 vs Base.1.12, iDRAC.1.6 vs
// IDRAC.2.9), so they are matched by pattern, ignoring case and version.
var successPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^Base\.\d+\.\d+\.Success$`),
	regexp.MustCompile(`(?i)^i?DRAC\.\d+\.\d+\.SYS4\d+$`),
	regexp.MustCompile(`(?i)^Bios\.\d+\.\d+\.BiosPropertyModified$`),
}

// IsSuccessID reports whether a MessageId is a known success code.
func IsSuccessID(id string) bool {
	for _, re := range successPatterns {
		if re.MatchString(id) {
			return true
		}
	}
	return false
}

// IsSuccess reports whether a message is a success: its MessageId matches a known
// success pattern and its severity is not Critical. The SYS4xx pattern also matches
// error codes such as IDRAC.2.9.SYS403 ("resource not found", Critical), so the
// severity is needed to tell them apart.
func IsSuccess(m Message) bool {
	return IsSuccessID(m.ID) && !strings.EqualFold(m.Severity, "Critical")
}

// NeedsReboot reports whether any message says a restart or reboot is needed.
func NeedsReboot(msgs []Message) bool {
	for _, m := range msgs {
		s := strings.ToLower(m.Resolution + " " + m.Text)
		if strings.Contains(s, "restart") || strings.Contains(s, "reboot") {
			return true
		}
	}
	return false
}

// Summarize renders messages as "Severity: Text; Severity: Text".
func Summarize(msgs []Message) string {
	parts := make([]string, len(msgs))
	for i, m := range msgs {
		parts[i] = m.Severity + ": " + m.Text
	}
	return strings.Join(parts, "; ")
}
```

- [ ] **Step 5: Implement `internal/redfish/tasks.go`**

```go
package redfish

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Outcome is the verdict of a task poll.
type Outcome int

const (
	// OutcomeScheduled: accepted and waiting (typically for a reboot).
	OutcomeScheduled Outcome = iota + 1
	// OutcomeCompleted: finished successfully.
	OutcomeCompleted
	// OutcomeFailed: ended in an error state.
	OutcomeFailed
)

// TaskResult describes the last observed task state.
type TaskResult struct {
	Outcome       Outcome
	State, Status string
	Detail        string
}

// WaitTask polls a task monitor URI (taken verbatim from a Location header)
// until the task is scheduled, completed or failed, honouring Retry-After.
// "New"/"Scheduled" with status OK is success-pending: BIOS changes wait for
// the next reboot, so the task never leaves that state by itself.
func (c *Client) WaitTask(ctx context.Context, location string) (TaskResult, error) {
	deadline := time.Now().Add(c.opts.TaskTimeout)
	for {
		resp, err := c.Do(ctx, http.MethodGet, location, nil, nil)
		if err != nil {
			return TaskResult{}, fmt.Errorf("failed to get task status: %w", err)
		}
		var t struct {
			TaskState  string `json:"TaskState"`
			TaskStatus string `json:"TaskStatus"`
			Name       string `json:"Name"`
			Oem        struct {
				Dell struct {
					Message  string `json:"Message"`
					JobState string `json:"JobState"`
					JobType  string `json:"JobType"`
				} `json:"Dell"`
			} `json:"Oem"`
		}
		if len(bytes.TrimSpace(resp.Body)) > 0 {
			if err := json.Unmarshal(resp.Body, &t); err != nil {
				return TaskResult{}, fmt.Errorf("failed to parse task status response: %w", err)
			}
		}
		res := TaskResult{State: t.TaskState, Status: t.TaskStatus,
			Detail: fmt.Sprintf("State: %s, Status: %s, Name: %s", t.TaskState, t.TaskStatus, t.Name)}
		if d := t.Oem.Dell; d.JobState != "" {
			res.Detail += fmt.Sprintf(". Messages: Dell.%s.%s: %s", d.JobType, d.JobState, d.Message)
		}
		switch t.TaskState {
		case "New", "Scheduled":
			res.Outcome = OutcomeScheduled
			if t.TaskStatus != "OK" {
				res.Outcome = OutcomeFailed
			}
			return res, nil
		case "Completed":
			res.Outcome = OutcomeCompleted
			if t.TaskStatus != "" && t.TaskStatus != "OK" {
				res.Outcome = OutcomeFailed
			}
			return res, nil
		case "Exception", "Killed", "Cancelled", "Interrupted":
			res.Outcome = OutcomeFailed
			return res, nil
		}
		wait := c.opts.PollInterval
		if ra, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && ra > 0 {
			wait = time.Duration(ra) * time.Second
		}
		if time.Now().Add(wait).After(deadline) {
			return res, fmt.Errorf("task still %q after %s", res.State, c.opts.TaskTimeout)
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(wait):
		}
	}
}
```

- [ ] **Step 6: Run to verify pass**

Run: `go test ./internal/redfish/ && gofmt -l internal/redfish`
Expected: `ok`, no gofmt output.

- [ ] **Step 7: Commit**

```bash
git add internal/redfish
git commit -m "feat(redfish): parse ExtendedInfo and poll task monitors" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Platform contract and report writers

**Files:**
- Create: `internal/platform/platform.go`, `internal/report/report.go`
- Test: `internal/platform/platform_test.go`, `internal/report/report_test.go`

**Interfaces:**
- Produces (`platform`):
  - action constants `ActionStatus`, `ActionEnable`, `ActionDisable`, `ActionPolicyCustom`, `ActionPolicyStandard`, `ActionDBList`, `ActionDBImport`, `ActionDBExport`, `ActionDBDelete`; `var AllActions []string`; `func IsDBAction(a string) bool`
  - `var ErrUnsupported error`
  - `type Status struct{ Name, Description string; Enabled bool; CurrentBoot, Mode, Policy, PendingPolicy, CertificatesURI string }`
  - `type Change struct{ Message string; RebootRequired bool; Location, JobID string }`; `type Cert struct{ URI string }`
  - `type Platform interface{ Name() string; Supports(action string) bool; Status(ctx) (Status, error); SetSecureBoot(ctx, bool) (Change, error); SetPolicy(ctx, string) (Change, error); DBList(ctx) ([]Cert, error); DBImport(ctx, file string) (Change, error); DBExport(ctx, uri, file string) (Change, error); DBDelete(ctx, uri string) (Change, error) }`
  - `type Unsupported struct{}` (embeddable; every method except `Name`, `Supports`, `Status` returns `ErrUnsupported`)
  - `func PendingStatus(target string, reboot bool) string`
- Produces (`report`):
  - `type Result struct{ IP, Action, Platform, Name, Description, CurrentStatus, CurrentBoot, CurrentMode, CurrentPolicy, NewPolicy, CertificatesURI, NewStatus string; Success bool; ChangeMessage, Message, Error string; CertCount int }`
  - `func New(ip, action, platform string) Result` (Python defaults: `Unknown`, `N/A`)
  - `func WriteCSV(w io.Writer, action string, results []Result) error`, `func WriteJSON(w io.Writer, results []Result) error`

- [ ] **Step 1: Write the failing platform tests in `internal/platform/platform_test.go`**

```go
package platform

import (
	"context"
	"errors"
	"testing"
)

func TestIsDBAction(t *testing.T) {
	for _, a := range AllActions {
		want := a == ActionDBList || a == ActionDBImport || a == ActionDBExport || a == ActionDBDelete
		if IsDBAction(a) != want {
			t.Errorf("IsDBAction(%q) = %v, want %v", a, !want, want)
		}
	}
	if len(AllActions) != 9 {
		t.Errorf("AllActions has %d entries, want 9", len(AllActions))
	}
}

func TestUnsupportedReturnsErrUnsupported(t *testing.T) {
	var u Unsupported
	ctx := context.Background()
	if _, err := u.SetSecureBoot(ctx, true); !errors.Is(err, ErrUnsupported) {
		t.Errorf("SetSecureBoot: %v", err)
	}
	if _, err := u.SetPolicy(ctx, "Custom"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("SetPolicy: %v", err)
	}
	if _, err := u.DBList(ctx); !errors.Is(err, ErrUnsupported) {
		t.Errorf("DBList: %v", err)
	}
	if _, err := u.DBImport(ctx, "f"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("DBImport: %v", err)
	}
	if _, err := u.DBExport(ctx, "u", "f"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("DBExport: %v", err)
	}
	if _, err := u.DBDelete(ctx, "u"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("DBDelete: %v", err)
	}
}

func TestPendingStatus(t *testing.T) {
	if got := PendingStatus("Enabled", true); got != "Enabled (Pending - Reboot Required)" {
		t.Errorf("got %q", got)
	}
	if got := PendingStatus("Disabled", false); got != "Disabled" {
		t.Errorf("got %q", got)
	}
}
```

- [ ] **Step 2: Write the failing report tests in `internal/report/report_test.go`**

```go
package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteCSVSecureBootColumnsMatchPython(t *testing.T) {
	r := New("10.0.0.1", "status", "idrac9")
	r.Success, r.Name, r.CurrentStatus, r.NewStatus = true, "Sec", "Enabled", "Enabled"
	var buf bytes.Buffer
	if err := WriteCSV(&buf, "status", []Result{r}); err != nil {
		t.Fatal(err)
	}
	want := "IP Address,Action,Name,Description,Current Status,Current Boot,Current Mode,Current Policy,New Policy,Certificates URI,New Status,Success,Change Message,Error,Platform\n" +
		"10.0.0.1,status,Sec,,Enabled,Unknown,Unknown,Unknown,Unknown,N/A,Enabled,Yes,,,idrac9\n"
	if buf.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestWriteCSVDBColumnsAndQuoting(t *testing.T) {
	r := New("10.0.0.2", "db_list", "ilo")
	r.Success, r.Message, r.CertCount = true, "Found 2, ok", 2
	f := New("10.0.0.3", "db_list", "")
	f.Error = "HTTP 401: nope"
	var buf bytes.Buffer
	if err := WriteCSV(&buf, "db_list", []Result{r, f}); err != nil {
		t.Fatal(err)
	}
	want := "IP Address,Action,Success,Message,Error,Certificate Count,Platform\n" +
		`10.0.0.2,db_list,Yes,"Found 2, ok",,2,ilo` + "\n" +
		"10.0.0.3,db_list,No,,HTTP 401: nope,0,\n"
	if buf.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestWriteJSONRoundTripsAndNeverEmitsPasswords(t *testing.T) {
	r := New("10.0.0.1", "status", "lenovo")
	r.Success = true
	var buf bytes.Buffer
	if err := WriteJSON(&buf, []Result{r}); err != nil {
		t.Fatal(err)
	}
	var back []Result
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil || len(back) != 1 || back[0].IP != "10.0.0.1" || !back[0].Success {
		t.Fatalf("round trip failed: %v %+v", err, back)
	}
	if strings.Contains(strings.ToLower(buf.String()), "password") {
		t.Error("JSON output must not contain a password field")
	}
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/platform/ ./internal/report/`
Expected: FAIL (`undefined: AllActions`, `undefined: New`).

- [ ] **Step 4: Implement `internal/platform/platform.go`**

```go
// Package platform defines the vendor-neutral driver contract.
package platform

import (
	"context"
	"errors"
	"strings"
)

// Action names, as given to -a.
const (
	ActionStatus         = "status"
	ActionEnable         = "enable"
	ActionDisable        = "disable"
	ActionPolicyCustom   = "set_policy_custom"
	ActionPolicyStandard = "set_policy_standard"
	ActionDBList         = "db_list"
	ActionDBImport       = "db_import"
	ActionDBExport       = "db_export"
	ActionDBDelete       = "db_delete"
)

// AllActions lists every action the CLI accepts.
var AllActions = []string{
	ActionStatus, ActionEnable, ActionDisable, ActionPolicyCustom, ActionPolicyStandard,
	ActionDBList, ActionDBImport, ActionDBExport, ActionDBDelete,
}

// IsDBAction reports whether the action targets the certificate store.
func IsDBAction(a string) bool { return strings.HasPrefix(a, "db_") }

// ErrUnsupported is returned by a driver for an action it does not implement.
var ErrUnsupported = errors.New("action not supported")

// Status is the Secure Boot state of one BMC.
type Status struct {
	Name, Description string
	Enabled           bool
	CurrentBoot, Mode string
	// Policy is the applied SecureBootPolicy ("N/A" where the platform has none);
	// PendingPolicy is a different value staged for the next reboot, or "".
	Policy, PendingPolicy string
	CertificatesURI       string
}

// Change describes an accepted modification.
type Change struct {
	Message         string
	RebootRequired  bool
	Location, JobID string
}

// Cert identifies one certificate in a store.
type Cert struct{ URI string }

// Platform is one vendor driver bound to one BMC.
type Platform interface {
	Name() string
	Supports(action string) bool
	Status(ctx context.Context) (Status, error)
	SetSecureBoot(ctx context.Context, enable bool) (Change, error)
	SetPolicy(ctx context.Context, policy string) (Change, error)
	DBList(ctx context.Context) ([]Cert, error)
	DBImport(ctx context.Context, file string) (Change, error)
	DBExport(ctx context.Context, uri, file string) (Change, error)
	DBDelete(ctx context.Context, uri string) (Change, error)
}

// Unsupported is embedded by drivers; it answers ErrUnsupported for everything
// except Name, Supports and Status, which every driver implements itself.
type Unsupported struct{}

func (Unsupported) SetSecureBoot(context.Context, bool) (Change, error) {
	return Change{}, ErrUnsupported
}
func (Unsupported) SetPolicy(context.Context, string) (Change, error) {
	return Change{}, ErrUnsupported
}
func (Unsupported) DBList(context.Context) ([]Cert, error) { return nil, ErrUnsupported }
func (Unsupported) DBImport(context.Context, string) (Change, error) {
	return Change{}, ErrUnsupported
}
func (Unsupported) DBExport(context.Context, string, string) (Change, error) {
	return Change{}, ErrUnsupported
}
func (Unsupported) DBDelete(context.Context, string) (Change, error) {
	return Change{}, ErrUnsupported
}

// PendingStatus renders "<target> (Pending - Reboot Required)" when a reboot is needed.
func PendingStatus(target string, reboot bool) string {
	if reboot {
		return target + " (Pending - Reboot Required)"
	}
	return target
}
```

- [ ] **Step 5: Implement `internal/report/report.go`**

```go
// Package report holds per-host results and writes them as CSV or JSON.
package report

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"
	"strings"
)

// Result is the outcome of one action on one host.
type Result struct {
	IP              string `json:"ip"`
	Action          string `json:"action"`
	Platform        string `json:"platform"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	CurrentStatus   string `json:"current_status"`
	CurrentBoot     string `json:"current_boot"`
	CurrentMode     string `json:"current_mode"`
	CurrentPolicy   string `json:"current_policy"`
	NewPolicy       string `json:"new_policy"`
	CertificatesURI string `json:"certificates_uri"`
	NewStatus       string `json:"new_status"`
	Success         bool   `json:"success"`
	ChangeMessage   string `json:"change_message"`
	Message         string `json:"message"`
	Error           string `json:"error"`
	CertCount       int    `json:"certificate_count"`
}

// New returns a Result carrying the same defaults as the Python script.
func New(ip, action, platform string) Result {
	return Result{
		IP: ip, Action: action, Platform: platform,
		Name: "Unknown", CurrentStatus: "Unknown", CurrentBoot: "Unknown", CurrentMode: "Unknown",
		CurrentPolicy: "Unknown", NewPolicy: "Unknown", CertificatesURI: "N/A", NewStatus: "Unknown",
	}
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// WriteCSV writes results with the Python column layout (DB layout for db_*
// actions) plus a final Platform column.
func WriteCSV(w io.Writer, action string, results []Result) error {
	cw := csv.NewWriter(w)
	if strings.HasPrefix(action, "db_") {
		_ = cw.Write([]string{"IP Address", "Action", "Success", "Message", "Error", "Certificate Count", "Platform"})
		for _, r := range results {
			_ = cw.Write([]string{r.IP, r.Action, yesNo(r.Success), r.Message, r.Error, strconv.Itoa(r.CertCount), r.Platform})
		}
	} else {
		_ = cw.Write([]string{"IP Address", "Action", "Name", "Description", "Current Status", "Current Boot",
			"Current Mode", "Current Policy", "New Policy", "Certificates URI", "New Status", "Success",
			"Change Message", "Error", "Platform"})
		for _, r := range results {
			_ = cw.Write([]string{r.IP, r.Action, r.Name, r.Description, r.CurrentStatus, r.CurrentBoot,
				r.CurrentMode, r.CurrentPolicy, r.NewPolicy, r.CertificatesURI, r.NewStatus, yesNo(r.Success),
				r.ChangeMessage, r.Error, r.Platform})
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteJSON writes results as an indented JSON array.
func WriteJSON(w io.Writer, results []Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}
```

- [ ] **Step 6: Run to verify pass**

Run: `go test ./internal/platform/ ./internal/report/ && gofmt -l internal`
Expected: `ok` for both, no gofmt output.

- [ ] **Step 7: Commit**

```bash
git add internal/platform internal/report
git commit -m "feat: platform contract and CSV/JSON report writers" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Standard SecureBoot helper and generic driver (iLO, Supermicro)

**Files:**
- Create: `internal/stdsb/stdsb.go`, `internal/stdsb/driver.go`
- Test: `internal/stdsb/stdsb_test.go`, `internal/stdsb/driver_test.go`

**Interfaces:**
- Consumes: `redfish.Client` (Tasks 3-4), `platform` (Task 5), `testbmc.StdSecureBoot` (Task 3).
- Produces:
  - `type Doc struct{ Name, Description string; SecureBootEnable bool; SecureBootCurrentBoot, SecureBootMode string; SecureBootDatabases redfish.Link; Oem struct{ Dell struct{ Certificates redfish.Link } } }`
  - `type Helper struct{ C *redfish.Client }` with `Path(ctx) (string, error)`, `Get(ctx) (Doc, error)`, `Status(ctx) (platform.Status, error)` (policy `N/A`), `SetEnable(ctx, bool) (*redfish.Response, error)`, `DBPath(ctx, id string) (string, error)`, `DBCerts(ctx, id string) ([]platform.Cert, error)`, `ImportPEM(ctx, id string, pem []byte) (*redfish.Response, error)`
  - `func ToPEM(data []byte) ([]byte, error)`, `func DERLen(pemBytes []byte) int`
  - `type Driver struct{ platform.Unsupported; H Helper; ... }`, `func NewDriver(name string, c *redfish.Client, maxCertBytes int) *Driver` implementing `Name`, `Supports` (status, enable, disable, db_list, db_import, db_delete), `Status`, `SetSecureBoot`, `DBList`, `DBImport`, `DBDelete`.

- [ ] **Step 1: Write the failing helper tests `internal/stdsb/stdsb_test.go`**

```go
package stdsb

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestToPEMConvertsDERAndPassesPEMThrough(t *testing.T) {
	der := testCertDER(t)
	got, err := ToPEM(der)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(got)
	if block == nil || block.Type != "CERTIFICATE" || string(block.Bytes) != string(der) {
		t.Fatalf("DER was not converted to an equivalent PEM: %q", got)
	}
	again, err := ToPEM(got)
	if err != nil || string(again) != string(got) {
		t.Errorf("PEM input must pass through unchanged, err = %v", err)
	}
	if DERLen(got) != len(der) {
		t.Errorf("DERLen = %d, want %d", DERLen(got), len(der))
	}
}

func TestToPEMRejectsGarbageAndEmpty(t *testing.T) {
	for _, in := range [][]byte{[]byte("garbage"), nil} {
		if _, err := ToPEM(in); err == nil || !strings.Contains(err.Error(), "not a PEM or DER certificate") {
			t.Errorf("ToPEM(%q) err = %v", in, err)
		}
	}
}
```

- [ ] **Step 2: Write the failing driver tests `internal/stdsb/driver_test.go`**

```go
package stdsb

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
	"sbmgr/internal/testbmc"
)

const (
	sys = "/redfish/v1/Systems/1"
	dbs = sys + "/SecureBoot/SecureBootDatabases"
)

func newFake(t *testing.T, maxCert int) (*testbmc.Server, *Driver) {
	t.Helper()
	s := testbmc.New(t)
	s.Redfish("HPE", "1", "iLO 6", "1.62")
	s.StdSecureBoot("1", false, "SetupMode", 2)
	c, err := redfish.New(s.URL, "admin", "pw", redfish.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return s, NewDriver("ilo", c, maxCert)
}

func writeFile(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cert.bin")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStatusMapsDocAndReportsNoPolicy(t *testing.T) {
	_, d := newFake(t, 0)
	st, err := d.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Enabled || st.Mode != "SetupMode" || st.Policy != "N/A" || st.Name != "Secure Boot" {
		t.Errorf("status = %+v", st)
	}
}

func TestSetSecureBootPatchesAndMarksRebootRequired(t *testing.T) {
	s, d := newFake(t, 0)
	s.JSON("PATCH", sys+"/SecureBoot", 200, map[string]any{})
	ch, err := d.SetSecureBoot(context.Background(), true)
	if err != nil || !ch.RebootRequired {
		t.Fatalf("ch = %+v, err = %v", ch, err)
	}
	var patch string
	for _, r := range s.Requests() {
		if r.Method == "PATCH" {
			patch = r.Body
		}
	}
	if strings.TrimSpace(patch) != `{"SecureBootEnable":true}` {
		t.Errorf("PATCH body = %q", patch)
	}
}

func TestDBListCountsCertificates(t *testing.T) {
	_, d := newFake(t, 0)
	certs, err := d.DBList(context.Background())
	if err != nil || len(certs) != 2 || certs[0].URI != dbs+"/db/Certificates/1" {
		t.Fatalf("certs = %+v, err = %v", certs, err)
	}
}

func TestDBImportConvertsDERToPEMJSON(t *testing.T) {
	s, d := newFake(t, 0)
	s.JSON("POST", dbs+"/db/Certificates", 201, map[string]any{})
	ch, err := d.DBImport(context.Background(), writeFile(t, testCertDER(t)))
	if err != nil || !strings.Contains(ch.Message, "Certificate import successful") {
		t.Fatalf("ch = %+v, err = %v", ch, err)
	}
	var posted struct{ CertificateString, CertificateType string }
	for _, r := range s.Requests() {
		if r.Method == "POST" {
			if err := json.Unmarshal([]byte(r.Body), &posted); err != nil {
				t.Fatal(err)
			}
		}
	}
	if posted.CertificateType != "PEM" || !strings.Contains(posted.CertificateString, "BEGIN CERTIFICATE") {
		t.Errorf("posted = %+v", posted)
	}
}

func TestDBImportRejectsMissingEmptyAndOversizedFiles(t *testing.T) {
	s, d := newFake(t, 10) // tiny device limit
	ctx := context.Background()
	if _, err := d.DBImport(ctx, filepath.Join(t.TempDir(), "absent")); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("missing: err = %v", err)
	}
	if _, err := d.DBImport(ctx, writeFile(t, nil)); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty: err = %v", err)
	}
	if _, err := d.DBImport(ctx, writeFile(t, testCertDER(t))); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("oversized: err = %v", err)
	}
	if n := s.Count("POST", dbs+"/db/Certificates"); n != 0 {
		t.Errorf("rejected files must not be POSTed, got %d POSTs", n)
	}
}

func TestDBDeleteAndUnsupportedActions(t *testing.T) {
	s, d := newFake(t, 0)
	s.JSON("DELETE", dbs+"/db/Certificates/1", 204, nil)
	if _, err := d.DBDelete(context.Background(), dbs+"/db/Certificates/1"); err != nil {
		t.Fatal(err)
	}
	if s.Count("DELETE", dbs+"/db/Certificates/1") != 1 {
		t.Error("DELETE was not sent")
	}
	if d.Supports(platform.ActionPolicyCustom) || d.Supports(platform.ActionDBExport) || !d.Supports(platform.ActionDBImport) {
		t.Error("Supports() does not match the driver's actions")
	}
	if _, err := d.SetPolicy(context.Background(), "Custom"); !errors.Is(err, platform.ErrUnsupported) {
		t.Errorf("SetPolicy err = %v", err)
	}
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./internal/stdsb/`
Expected: FAIL (`undefined: ToPEM`, `undefined: NewDriver`).

- [ ] **Step 4: Implement `internal/stdsb/stdsb.go`**

```go
// Package stdsb implements the DMTF-standard SecureBoot resources (SecureBoot,
// SecureBootDatabases) shared by several vendors, plus a generic driver.
package stdsb

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"

	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
)

// Doc is the SecureBoot resource.
type Doc struct {
	Name                  string       `json:"Name"`
	Description           string       `json:"Description"`
	SecureBootEnable      bool         `json:"SecureBootEnable"`
	SecureBootCurrentBoot string       `json:"SecureBootCurrentBoot"`
	SecureBootMode        string       `json:"SecureBootMode"`
	SecureBootDatabases   redfish.Link `json:"SecureBootDatabases"`
	Oem                   struct {
		Dell struct {
			Certificates redfish.Link `json:"Certificates"`
		} `json:"Dell"`
	} `json:"Oem"`
}

// Helper reads and writes the SecureBoot tree of one BMC.
type Helper struct {
	C      *redfish.Client
	sbPath string
}

// Path returns the SecureBoot URI, discovered from the computer system.
func (h *Helper) Path(ctx context.Context) (string, error) {
	if h.sbPath != "" {
		return h.sbPath, nil
	}
	sys, err := h.C.SystemPath(ctx)
	if err != nil {
		return "", err
	}
	var doc struct {
		SecureBoot redfish.Link `json:"SecureBoot"`
	}
	if err := h.C.GetJSON(ctx, sys, &doc); err != nil {
		return "", fmt.Errorf("system: %w", err)
	}
	h.sbPath = doc.SecureBoot.ODataID
	if h.sbPath == "" {
		h.sbPath = sys + "/SecureBoot" // last-resort fallback
	}
	return h.sbPath, nil
}

// Get reads the SecureBoot resource.
func (h *Helper) Get(ctx context.Context) (Doc, error) {
	p, err := h.Path(ctx)
	if err != nil {
		return Doc{}, err
	}
	var doc Doc
	if err := h.C.GetJSON(ctx, p, &doc); err != nil {
		return Doc{}, err
	}
	return doc, nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// Status maps the SecureBoot resource to a platform.Status (Policy "N/A").
func (h *Helper) Status(ctx context.Context) (platform.Status, error) {
	doc, err := h.Get(ctx)
	if err != nil {
		return platform.Status{}, err
	}
	return platform.Status{
		Name: doc.Name, Description: doc.Description, Enabled: doc.SecureBootEnable,
		CurrentBoot: orDefault(doc.SecureBootCurrentBoot, "Unknown"),
		Mode:        orDefault(doc.SecureBootMode, "Unknown"),
		Policy:      "N/A", CertificatesURI: doc.Oem.Dell.Certificates.ODataID,
	}, nil
}

// SetEnable PATCHes SecureBootEnable. The change takes effect on next boot.
func (h *Helper) SetEnable(ctx context.Context, enable bool) (*redfish.Response, error) {
	p, err := h.Path(ctx)
	if err != nil {
		return nil, err
	}
	return h.C.Patch(ctx, p, map[string]bool{"SecureBootEnable": enable})
}

// DBPath returns the Certificates collection URI of database id ("db", "KEK"...).
func (h *Helper) DBPath(ctx context.Context, id string) (string, error) {
	doc, err := h.Get(ctx)
	if err != nil {
		return "", err
	}
	dbs := doc.SecureBootDatabases.ODataID
	if dbs == "" {
		return "", errors.New("SecureBootDatabases not exposed by this BMC")
	}
	members, err := h.C.Members(ctx, dbs)
	if err != nil {
		return "", fmt.Errorf("secure boot databases: %w", err)
	}
	for _, m := range members {
		if !strings.EqualFold(path.Base(m.ODataID), id) {
			continue
		}
		var d struct {
			Certificates redfish.Link `json:"Certificates"`
		}
		if err := h.C.GetJSON(ctx, m.ODataID, &d); err != nil {
			return "", err
		}
		if d.Certificates.ODataID != "" {
			return d.Certificates.ODataID, nil
		}
		return m.ODataID + "/Certificates", nil
	}
	return "", fmt.Errorf("secure boot database %q not found", id)
}

// DBCerts lists the certificates of database id.
func (h *Helper) DBCerts(ctx context.Context, id string) ([]platform.Cert, error) {
	p, err := h.DBPath(ctx, id)
	if err != nil {
		return nil, err
	}
	members, err := h.C.Members(ctx, p)
	if err != nil {
		return nil, err
	}
	certs := make([]platform.Cert, len(members))
	for i, m := range members {
		certs[i] = platform.Cert{URI: m.ODataID}
	}
	return certs, nil
}

// ImportPEM enrols a PEM certificate into database id (additive).
func (h *Helper) ImportPEM(ctx context.Context, id string, pemBytes []byte) (*redfish.Response, error) {
	p, err := h.DBPath(ctx, id)
	if err != nil {
		return nil, err
	}
	return h.C.SendJSON(ctx, http.MethodPost, p, map[string]string{
		"CertificateString": string(pemBytes), "CertificateType": "PEM"})
}

// ToPEM returns PEM bytes for a PEM or DER X.509 certificate.
func ToPEM(data []byte) ([]byte, error) {
	if bytes.Contains(data, []byte("-----BEGIN")) {
		return data, nil
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("not a PEM or DER certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), nil
}

// DERLen returns the DER size of the first certificate in pemBytes, or 0.
func DERLen(pemBytes []byte) int {
	if block, _ := pem.Decode(pemBytes); block != nil {
		return len(block.Bytes)
	}
	return 0
}
```

- [ ] **Step 5: Implement `internal/stdsb/driver.go`**

```go
package stdsb

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"slices"

	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
)

var driverActions = []string{
	platform.ActionStatus, platform.ActionEnable, platform.ActionDisable,
	platform.ActionDBList, platform.ActionDBImport, platform.ActionDBDelete,
}

// Driver is the generic DMTF-standard driver (HPE iLO, Supermicro). Other
// drivers embed it and override what differs.
type Driver struct {
	platform.Unsupported
	H       Helper
	name    string
	maxCert int
}

var _ platform.Platform = (*Driver)(nil)

// NewDriver builds a driver; maxCertBytes > 0 caps the DER size of an imported certificate.
func NewDriver(name string, c *redfish.Client, maxCertBytes int) *Driver {
	return &Driver{H: Helper{C: c}, name: name, maxCert: maxCertBytes}
}

func (d *Driver) Name() string { return d.name }

func (d *Driver) Supports(action string) bool { return slices.Contains(driverActions, action) }

func (d *Driver) Status(ctx context.Context) (platform.Status, error) { return d.H.Status(ctx) }

// SetSecureBoot PATCHes SecureBootEnable. The DMTF schema states the change
// "takes effect on next boot", so a reboot is always reported as required.
func (d *Driver) SetSecureBoot(ctx context.Context, enable bool) (platform.Change, error) {
	resp, err := d.H.SetEnable(ctx, enable)
	if err != nil {
		return platform.Change{}, err
	}
	return platform.Change{
		Message:        "Success. Messages: " + redfish.Summarize(redfish.ParseMessages(resp.Body)),
		RebootRequired: true,
	}, nil
}

func (d *Driver) DBList(ctx context.Context) ([]platform.Cert, error) { return d.H.DBCerts(ctx, "db") }

// DBImport enrols a PEM or DER certificate file into the "db" database.
func (d *Driver) DBImport(ctx context.Context, file string) (platform.Change, error) {
	data, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return platform.Change{}, fmt.Errorf("certificate file not found: %s", file)
	}
	if err != nil {
		return platform.Change{}, fmt.Errorf("read certificate file: %w", err)
	}
	if len(data) == 0 {
		return platform.Change{}, fmt.Errorf("certificate file is empty: %s", file)
	}
	pemBytes, err := ToPEM(data)
	if err != nil {
		return platform.Change{}, err
	}
	if n := DERLen(pemBytes); d.maxCert > 0 && n > d.maxCert {
		return platform.Change{}, fmt.Errorf("certificate is %d bytes, device limit is %d", n, d.maxCert)
	}
	resp, err := d.H.ImportPEM(ctx, "db", pemBytes)
	if err != nil {
		return platform.Change{}, err
	}
	msgs := redfish.ParseMessages(resp.Body)
	return platform.Change{
		Message:        "Certificate import successful. Messages: " + redfish.Summarize(msgs),
		RebootRequired: redfish.NeedsReboot(msgs),
	}, nil
}

// DBDelete removes the certificate at uri.
func (d *Driver) DBDelete(ctx context.Context, uri string) (platform.Change, error) {
	if _, err := d.H.C.Do(ctx, http.MethodDelete, uri, nil, nil); err != nil {
		return platform.Change{}, err
	}
	return platform.Change{Message: "DB certificate deleted successfully"}, nil
}
```

- [ ] **Step 6: Run to verify pass**

Run: `go test ./internal/stdsb/ && go vet ./internal/stdsb/ && gofmt -l internal/stdsb`
Expected: `ok`, no vet or gofmt output.

- [ ] **Step 7: Commit**

```bash
git add internal/stdsb
git commit -m "feat(stdsb): standard SecureBoot helper and generic iLO/Supermicro driver" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Dell driver — status (applied and pending policy), enable/disable

**Files:**
- Create: `internal/dell/driver.go`
- Test: `internal/dell/driver_test.go`

**Interfaces:**
- Consumes: `stdsb.Helper` (`Status`, `Get`, `SetEnable`, `Path`), `redfish.Client`, `platform`.
- Produces:
  - `func New(c *redfish.Client, name, method string) *Driver` — `name` is `idrac9` or `idrac10`; `method` is `oem`, `standard` or `""` (default `oem` for iDRAC9, `standard` for iDRAC10)
  - `Driver` methods `Name`, `Supports` (iDRAC9: all nine actions; iDRAC10: `status`, `db_list`, `db_import`, `db_delete`), `Status`, `SetSecureBoot`
  - unexported `(d *Driver) bios(ctx) (biosDoc, settingsPath string, err error)` used by Task 8

- [ ] **Step 1: Write the failing tests and the shared fake `internal/dell/driver_test.go`**

```go
package dell

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
	"sbmgr/internal/testbmc"
)

const (
	sys   = "/redfish/v1/Systems/System.Embedded.1"
	store = sys + "/SecureBoot/Oem/Dell/Certificates/DB"
	task  = "/redfish/v1/TaskService/Tasks/JID_706967682250"
)

func info(id, resolution string) map[string]any {
	return map[string]any{"@Message.ExtendedInfo": []any{
		map[string]any{"MessageId": id, "Message": "msg " + id, "Severity": "OK", "Resolution": resolution},
	}}
}

func registerBios(s *testbmc.Server) {
	s.JSON("GET", sys+"/Bios", 200, map[string]any{
		"Attributes":        map[string]any{"SecureBootPolicy": "Standard"},
		"@Redfish.Settings": map[string]any{"SettingsObject": testbmc.Link(sys + "/Bios/Settings")},
	})
	s.JSON("GET", sys+"/Bios/Settings", 200, map[string]any{"Attributes": map[string]any{}})
}

// newFake9 builds a fake iDRAC9 with every endpoint the driver can touch.
func newFake9(t *testing.T, method string, o ...redfish.Options) (*testbmc.Server, *Driver) {
	t.Helper()
	opts := redfish.Options{PollInterval: time.Millisecond, TaskTimeout: time.Second}
	if len(o) > 0 {
		opts = o[0]
	}
	s := testbmc.New(t)
	s.Redfish("Dell", "System.Embedded.1", "16G Monolithic", "7.20.30.50")
	s.JSON("GET", sys, 200, map[string]any{"SecureBoot": testbmc.Link(sys + "/SecureBoot"), "Bios": testbmc.Link(sys + "/Bios")})
	s.JSON("GET", sys+"/SecureBoot", 200, map[string]any{
		"Name": "UEFI Secure Boot Configuration", "Description": "UEFI Secure Boot Configuration",
		"SecureBootEnable": false, "SecureBootCurrentBoot": "Disabled", "SecureBootMode": "DeployedMode",
		"Oem": map[string]any{"Dell": map[string]any{"Certificates": testbmc.Link(sys + "/SecureBoot/Oem/Dell/Certificates")}},
	})
	registerBios(s)
	s.JSON("PATCH", sys+"/SecureBoot", 200, info("IDRAC.2.9.SYS430", "Restart the server for the change to take effect."))
	s.JSONH("PATCH", sys+"/Bios/Settings", 202, map[string]string{"Location": task}, info("Base.1.12.Success", "None"))
	s.JSON("GET", task, 200, map[string]any{"TaskState": "New", "TaskStatus": "OK", "Name": "Config: Bios"})
	s.JSON("GET", store, 200, map[string]any{"Certificates": []any{
		testbmc.Link(store + "/CustSecbootpolicy.1"), testbmc.Link(store + "/CustSecbootpolicy.2")}})
	s.JSON("POST", store+"/", 200, info("Base.1.12.Success", "None"))
	s.Handle("GET", store+"/CustSecbootpolicy.7", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("CERT-BYTES"))
	})
	s.JSON("DELETE", store+"/CustSecbootpolicy.7", 204, nil)
	c, err := redfish.New(s.URL, "root", "pw", opts)
	if err != nil {
		t.Fatal(err)
	}
	return s, New(c, "idrac9", method)
}

func TestStatusReadsAppliedAndPendingPolicy(t *testing.T) {
	s, d := newFake9(t, "")
	s.JSON("GET", sys+"/Bios/Settings", 200, map[string]any{"Attributes": map[string]any{"SecureBootPolicy": "Custom"}})
	st, err := d.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Enabled || st.Mode != "DeployedMode" || st.Policy != "Standard" || st.PendingPolicy != "Custom" {
		t.Errorf("status = %+v", st)
	}
	if st.CertificatesURI != sys+"/SecureBoot/Oem/Dell/Certificates" {
		t.Errorf("CertificatesURI = %q", st.CertificatesURI)
	}
}

func TestStatusPolicyUnknownWhenBiosUnreadable(t *testing.T) {
	s, d := newFake9(t, "")
	s.JSON("GET", sys+"/Bios", 500, nil)
	st, err := d.Status(context.Background())
	if err != nil || st.Policy != "Unknown" || st.PendingPolicy != "" {
		t.Fatalf("st = %+v, err = %v", st, err)
	}
}

func TestSetSecureBootReportsPendingReboot(t *testing.T) {
	s, d := newFake9(t, "")
	ch, err := d.SetSecureBoot(context.Background(), true)
	if err != nil || !ch.RebootRequired || !strings.Contains(ch.Message, "Server restart required") {
		t.Fatalf("ch = %+v, err = %v", ch, err)
	}
	var body string
	for _, r := range s.Requests() {
		if r.Method == "PATCH" {
			body = r.Body
		}
	}
	if strings.TrimSpace(body) != `{"SecureBootEnable":true}` {
		t.Errorf("PATCH body = %q", body)
	}
}

func TestSetSecureBootUnknownResponseIsAnError(t *testing.T) {
	s, d := newFake9(t, "")
	s.JSON("PATCH", sys+"/SecureBoot", 200, info("Foo.1.0.Bar", ""))
	if _, err := d.SetSecureBoot(context.Background(), true); err == nil || !strings.Contains(err.Error(), "unknown response") {
		t.Errorf("err = %v, want unknown response", err)
	}
}

func TestSetSecureBootCriticalSYS4xxIsNotSuccess(t *testing.T) {
	s, d := newFake9(t, "")
	s.JSON("PATCH", sys+"/SecureBoot", 200, map[string]any{"@Message.ExtendedInfo": []any{
		map[string]any{"MessageId": "IDRAC.2.9.SYS403", "Message": "resource not found", "Severity": "Critical"}}})
	if _, err := d.SetSecureBoot(context.Background(), true); err == nil || !strings.Contains(err.Error(), "unknown response") {
		t.Errorf("err = %v, want unknown response for a Critical SYS4xx", err)
	}
}

func TestSetSecureBootAcceptsEmptyBody(t *testing.T) {
	s, d := newFake9(t, "")
	s.JSON("PATCH", sys+"/SecureBoot", 204, nil)
	ch, err := d.SetSecureBoot(context.Background(), false)
	if err != nil || ch.RebootRequired {
		t.Fatalf("ch = %+v, err = %v", ch, err)
	}
}

func TestSupportsPerGeneration(t *testing.T) {
	_, d9 := newFake9(t, "")
	for _, a := range platform.AllActions {
		if !d9.Supports(a) {
			t.Errorf("idrac9 must support %s", a)
		}
	}
	d10 := New(nil, "idrac10", "")
	for _, a := range platform.AllActions {
		want := a == platform.ActionStatus || a == platform.ActionDBList || a == platform.ActionDBImport || a == platform.ActionDBDelete
		if d10.Supports(a) != want {
			t.Errorf("idrac10 Supports(%s) = %v, want %v", a, !want, want)
		}
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/dell/`
Expected: FAIL (`undefined: New`).

- [ ] **Step 3: Implement `internal/dell/driver.go`**

```go
// Package dell implements the iDRAC9 and iDRAC10 drivers. Dell-specific
// resources (OEM certificate store, SecureBootPolicy BIOS attribute) live here.
package dell

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
	"sbmgr/internal/stdsb"
)

// Driver drives one iDRAC. method selects how certificates are imported:
// "oem" (multipart on the Dell store) or "standard" (DMTF POST).
type Driver struct {
	platform.Unsupported
	c      *redfish.Client
	name   string
	method string
	h      stdsb.Helper
	std    *stdsb.Driver
}

var _ platform.Platform = (*Driver)(nil)

// New builds a driver. An empty method defaults to "oem" on idrac9 and
// "standard" on idrac10 (ADR 0005).
func New(c *redfish.Client, name, method string) *Driver {
	if method == "" {
		method = "oem"
		if name == "idrac10" {
			method = "standard"
		}
	}
	return &Driver{c: c, name: name, method: method, h: stdsb.Helper{C: c}, std: stdsb.NewDriver(name, c, 0)}
}

func (d *Driver) Name() string { return d.name }

func (d *Driver) Supports(action string) bool {
	if d.name == "idrac10" {
		switch action {
		case platform.ActionStatus, platform.ActionDBList, platform.ActionDBImport, platform.ActionDBDelete:
			return true
		}
		return false
	}
	return slices.Contains(platform.AllActions, action)
}

type biosDoc struct {
	Attributes struct {
		SecureBootPolicy string `json:"SecureBootPolicy"`
	} `json:"Attributes"`
	Settings struct {
		SettingsObject redfish.Link `json:"SettingsObject"`
	} `json:"@Redfish.Settings"`
}

const policyQuery = "?$select=Attributes/SecureBootPolicy"

// bios reads the applied SecureBootPolicy and returns the Bios/Settings URI
// (from @Redfish.Settings, else <bios>/Settings as a last resort).
func (d *Driver) bios(ctx context.Context) (doc biosDoc, settingsPath string, err error) {
	sys, err := d.c.SystemPath(ctx)
	if err != nil {
		return doc, "", err
	}
	var sd struct {
		Bios redfish.Link `json:"Bios"`
	}
	if err := d.c.GetJSON(ctx, sys, &sd); err != nil {
		return doc, "", fmt.Errorf("system: %w", err)
	}
	bp := sd.Bios.ODataID
	if bp == "" {
		bp = sys + "/Bios"
	}
	if err := d.c.GetJSON(ctx, bp+policyQuery, &doc); err != nil {
		return doc, "", err
	}
	settingsPath = doc.Settings.SettingsObject.ODataID
	if settingsPath == "" {
		settingsPath = bp + "/Settings"
	}
	return doc, settingsPath, nil
}

// Status returns the Secure Boot state with the applied policy and any
// different policy pending in Bios/Settings. An unreadable BIOS is not fatal:
// the policy is reported as "Unknown".
func (d *Driver) Status(ctx context.Context) (platform.Status, error) {
	st, err := d.h.Status(ctx)
	if err != nil {
		return platform.Status{}, err
	}
	st.Policy = "Unknown"
	doc, settings, err := d.bios(ctx)
	if err != nil {
		slog.Debug("could not read SecureBootPolicy", "err", err)
		return st, nil
	}
	if doc.Attributes.SecureBootPolicy != "" {
		st.Policy = doc.Attributes.SecureBootPolicy
	}
	var pending biosDoc
	if err := d.c.GetJSON(ctx, settings+policyQuery, &pending); err == nil {
		st.PendingPolicy = pending.Attributes.SecureBootPolicy
	}
	return st, nil
}

// SetSecureBoot PATCHes SecureBootEnable. Messages with a success MessageId (or
// no message at all) mean success; any other messages are an unknown response.
// The change stays pending until the next reboot.
func (d *Driver) SetSecureBoot(ctx context.Context, enable bool) (platform.Change, error) {
	resp, err := d.h.SetEnable(ctx, enable)
	if err != nil {
		return platform.Change{}, err
	}
	msgs := redfish.ParseMessages(resp.Body)
	ok := len(msgs) == 0
	for _, m := range msgs {
		if redfish.IsSuccess(m) {
			ok = true
		}
	}
	if !ok {
		return platform.Change{}, fmt.Errorf("unknown response. Messages: %s", redfish.Summarize(msgs))
	}
	reboot := redfish.NeedsReboot(msgs)
	restart := ""
	if reboot {
		restart = " (Server restart required)"
	}
	return platform.Change{
		Message:        fmt.Sprintf("Success%s. Messages: %s", restart, redfish.Summarize(msgs)),
		RebootRequired: reboot,
	}, nil
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/dell/ && go vet ./internal/dell/ && gofmt -l internal/dell`
Expected: `ok`, no vet or gofmt output.

- [ ] **Step 5: Commit**

```bash
git add internal/dell
git commit -m "feat(dell): status with applied and pending policy, enable/disable" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Dell driver — set policy (Custom/Standard) with task verification

**Files:**
- Modify: `internal/dell/driver.go` (imports and new method)
- Test: `internal/dell/policy_test.go`

**Interfaces:**
- Consumes: `(d *Driver) bios`, `redfish.Client.Patch`, `WaitTask`, `NoWait` (Tasks 3, 4, 7).
- Produces: `(d *Driver) SetPolicy(ctx, policy string) (platform.Change, error)` — `Change.Location` is the task monitor URI, `Change.JobID` is the part starting at `JID_` (or the last path segment).

- [ ] **Step 1: Write the failing tests `internal/dell/policy_test.go`**

```go
package dell

import (
	"context"
	"strings"
	"testing"
	"time"

	"sbmgr/internal/redfish"
)

func TestSetPolicyStagesOnResetAndVerifiesTask(t *testing.T) {
	s, d := newFake9(t, "")
	ch, err := d.SetPolicy(context.Background(), "Custom")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Location != task || ch.JobID != "JID_706967682250" {
		t.Errorf("Location/JobID = %q / %q", ch.Location, ch.JobID)
	}
	if !strings.Contains(ch.Message, "Verification: State: New, Status: OK, Name: Config: Bios") {
		t.Errorf("message = %q", ch.Message)
	}
	var body string
	for _, r := range s.Requests() {
		if r.Method == "PATCH" && r.Path == sys+"/Bios/Settings" {
			body = r.Body
		}
	}
	for _, want := range []string{`"SecureBootPolicy":"Custom"`, `"ApplyTime":"OnReset"`} {
		if !strings.Contains(body, want) {
			t.Errorf("PATCH body %q lacks %s", body, want)
		}
	}
}

// Changelog bug 3: the task is polled where the BMC says (Location), whatever
// the firmware's TaskService layout is.
func TestSetPolicyFollowsLocationUnderTaskMonitors(t *testing.T) {
	s, d := newFake9(t, "")
	mon := "/redfish/v1/TaskService/TaskMonitors/JID_42"
	s.JSONH("PATCH", sys+"/Bios/Settings", 202, map[string]string{"Location": mon}, info("Base.1.12.Success", "None"))
	s.JSON("GET", mon, 200, map[string]any{"TaskState": "Scheduled", "TaskStatus": "OK", "Name": "x"})
	ch, err := d.SetPolicy(context.Background(), "Standard")
	if err != nil || ch.JobID != "JID_42" {
		t.Fatalf("ch = %+v, err = %v", ch, err)
	}
	if s.Count("GET", mon) != 1 || s.Count("GET", task) != 0 {
		t.Error("the Location from the PATCH response must be the only task URI polled")
	}
}

func TestSetPolicyFailedTaskIsAnError(t *testing.T) {
	s, d := newFake9(t, "")
	s.JSON("GET", task, 200, map[string]any{"TaskState": "Exception", "TaskStatus": "Critical", "Name": "x"})
	if _, err := d.SetPolicy(context.Background(), "Custom"); err == nil || !strings.Contains(err.Error(), "task failed") {
		t.Errorf("err = %v", err)
	}
}

func TestSetPolicyNoWaitSkipsTaskPolling(t *testing.T) {
	s, d := newFake9(t, "", redfish.Options{NoWait: true, PollInterval: time.Millisecond})
	ch, err := d.SetPolicy(context.Background(), "Custom")
	if err != nil || ch.Location != task {
		t.Fatalf("ch = %+v, err = %v", ch, err)
	}
	if s.Count("GET", task) != 0 {
		t.Error("--no-wait must not poll the task")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/dell/ -run SetPolicy`
Expected: FAIL (`d.SetPolicy undefined` falls to `platform.Unsupported`: error `action not supported`).

- [ ] **Step 3: Replace the import block of `internal/dell/driver.go`**

```go
import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
	"sbmgr/internal/stdsb"
)
```

- [ ] **Step 4: Append to `internal/dell/driver.go`**

```go
// SetPolicy stages SecureBootPolicy ("Custom" or "Standard") in Bios/Settings,
// applied on the next reset, and verifies the resulting task unless --no-wait.
func (d *Driver) SetPolicy(ctx context.Context, policy string) (platform.Change, error) {
	_, settings, err := d.bios(ctx)
	if err != nil {
		return platform.Change{}, err
	}
	payload := map[string]any{
		"Attributes":                 map[string]string{"SecureBootPolicy": policy},
		"@Redfish.SettingsApplyTime": map[string]string{"ApplyTime": "OnReset"},
	}
	resp, err := d.c.Patch(ctx, settings, payload)
	if err != nil {
		return platform.Change{}, err
	}
	location := resp.Header.Get("Location")
	msgs := redfish.ParseMessages(resp.Body)
	ch := platform.Change{Location: location, JobID: jobID(location), RebootRequired: redfish.NeedsReboot(msgs)}
	verification := ""
	if location != "" && !d.c.NoWait() {
		tr, err := d.c.WaitTask(ctx, location)
		switch {
		case err != nil:
			verification = " (Verification: " + err.Error() + ")"
		case tr.Outcome == redfish.OutcomeFailed:
			return platform.Change{}, fmt.Errorf("policy change task failed. %s", tr.Detail)
		default:
			verification = " (Verification: " + tr.Detail + ")"
		}
	}
	restart, loc, job := "", "", ""
	if ch.RebootRequired {
		restart = " (Server restart required)"
	}
	if location != "" {
		loc = " (Location: " + location + ")"
	}
	if ch.JobID != "" {
		job = " (Job ID: " + ch.JobID + ")"
	}
	ch.Message = fmt.Sprintf("Policy change successful%s%s%s%s. Messages: %s", restart, loc, job, verification, redfish.Summarize(msgs))
	return ch, nil
}

// jobID extracts "JID_<n>" from a task Location, else its last path segment.
func jobID(loc string) string {
	if loc == "" {
		return ""
	}
	if i := strings.LastIndex(loc, "JID_"); i >= 0 {
		return loc[i:]
	}
	return loc[strings.LastIndex(loc, "/")+1:]
}
```

- [ ] **Step 5: Run to verify pass**

Run: `go test ./internal/dell/ && gofmt -l internal/dell`
Expected: `ok`, no gofmt output.

- [ ] **Step 6: Commit**

```bash
git add internal/dell
git commit -m "feat(dell): set SecureBootPolicy with task verification" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Dell driver — certificate store (list, import, export, delete)

**Files:**
- Create: `internal/dell/certs.go`
- Test: `internal/dell/certs_test.go`

**Interfaces:**
- Consumes: `stdsb.Helper.Get/Path`, `stdsb.Driver` (`d.std`), `redfish.Client.Upload/Do` (Tasks 3, 6, 7).
- Produces: `DBList`, `DBImport`, `DBExport`, `DBDelete` on `*Driver`. `DBList` and `DBImport` use the standard path when `d.method == "standard"` (list falls back to the OEM store on error); export and delete are always URI-based.

- [ ] **Step 1: Write the failing tests `internal/dell/certs_test.go`**

```go
package dell

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sbmgr/internal/testbmc"
)

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDBListReadsCertificatesThenHashThenEmpty(t *testing.T) {
	s, d := newFake9(t, "")
	ctx := context.Background()
	certs, err := d.DBList(ctx)
	if err != nil || len(certs) != 2 {
		t.Fatalf("certs = %+v, err = %v", certs, err)
	}
	s.JSON("GET", store, 200, map[string]any{"Hash": []any{testbmc.Link(store + "/h1")}})
	if certs, err := d.DBList(ctx); err != nil || len(certs) != 1 {
		t.Errorf("Hash variant: %+v, %v", certs, err)
	}
	s.JSON("GET", store, 200, map[string]any{"Certificates": []any{}})
	if certs, err := d.DBList(ctx); err != nil || len(certs) != 0 {
		t.Errorf("empty variant: %+v, %v", certs, err)
	}
}

func TestDBImportUploadsMultipartToStore(t *testing.T) {
	s, d := newFake9(t, "")
	got := make(chan [2]string, 1)
	s.Handle("POST", store+"/", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			testbmc.WriteJSON(w, 400, nil)
			return
		}
		f, h, err := r.FormFile("file")
		if err != nil {
			testbmc.WriteJSON(w, 400, nil)
			return
		}
		b, _ := io.ReadAll(f)
		got <- [2]string{h.Filename, string(b)}
		testbmc.WriteJSON(w, 200, info("Base.1.12.Success", "None"))
	})
	ch, err := d.DBImport(context.Background(), writeFile(t, "dell_2025.der", []byte("DER")))
	if err != nil || !strings.Contains(ch.Message, "Certificate import successful") {
		t.Fatalf("ch = %+v, err = %v", ch, err)
	}
	if v := <-got; v[0] != "dell_2025.der" || v[1] != "DER" {
		t.Errorf("uploaded %v", v)
	}
}

// Changelog bug 4: a 2xx import is a success even when the MessageIds are not
// the ones an older firmware used.
func TestDBImportAcceptsNewerMessageIdsAndReportsReboot(t *testing.T) {
	s, d := newFake9(t, "")
	s.JSON("POST", store+"/", 200, info("IDRAC.2.9.SYS430", "Restart the server."))
	ch, err := d.DBImport(context.Background(), writeFile(t, "c.der", []byte("DER")))
	if err != nil || !ch.RebootRequired || !strings.Contains(ch.Message, "Reboot required to take effect") {
		t.Fatalf("ch = %+v, err = %v", ch, err)
	}
}

func TestDBImportRejectsMissingAndEmptyFile(t *testing.T) {
	s, d := newFake9(t, "")
	ctx := context.Background()
	if _, err := d.DBImport(ctx, filepath.Join(t.TempDir(), "absent.der")); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("missing: err = %v", err)
	}
	if _, err := d.DBImport(ctx, writeFile(t, "e.der", nil)); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty: err = %v", err)
	}
	if s.Count("POST", store+"/") != 0 {
		t.Error("nothing must be uploaded for a bad file")
	}
}

// Changelog bug 1: the exported file must hold the certificate bytes, never 0 bytes.
func TestDBExportWritesCertificateBytes(t *testing.T) {
	_, d := newFake9(t, "")
	out := filepath.Join(t.TempDir(), "out.der")
	ch, err := d.DBExport(context.Background(), store+"/CustSecbootpolicy.7", out)
	if err != nil || !strings.Contains(ch.Message, out) {
		t.Fatalf("ch = %+v, err = %v", ch, err)
	}
	if b, _ := os.ReadFile(out); string(b) != "CERT-BYTES" {
		t.Errorf("exported file = %q", b)
	}
}

func TestDBExportEmptyBodyIsAnErrorAndWritesNothing(t *testing.T) {
	s, d := newFake9(t, "")
	s.Handle("GET", store+"/empty", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	out := filepath.Join(t.TempDir(), "out.der")
	if _, err := d.DBExport(context.Background(), store+"/empty", out); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("an empty export must not leave a 0-byte file")
	}
}

func TestDBDeleteSendsDELETE(t *testing.T) {
	s, d := newFake9(t, "")
	if _, err := d.DBDelete(context.Background(), store+"/CustSecbootpolicy.7"); err != nil {
		t.Fatal(err)
	}
	if s.Count("DELETE", store+"/CustSecbootpolicy.7") != 1 {
		t.Error("DELETE was not sent")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/dell/ -run 'DB'`
Expected: FAIL (`platform.ErrUnsupported`-style errors: `action not supported`).

- [ ] **Step 3: Implement `internal/dell/certs.go`**

```go
package dell

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
)

// dbStore returns the OEM "DB" certificate store URI: the Dell certificates link
// of the SecureBoot resource, else <SecureBoot>/Oem/Dell/Certificates (fallback).
func (d *Driver) dbStore(ctx context.Context) (string, error) {
	doc, err := d.h.Get(ctx)
	if err != nil {
		return "", err
	}
	base := doc.Oem.Dell.Certificates.ODataID
	if base == "" {
		sb, err := d.h.Path(ctx)
		if err != nil {
			return "", err
		}
		base = sb + "/Oem/Dell/Certificates"
	}
	return base + "/DB", nil
}

// DBList lists the "db" certificates. With the standard method it asks the DMTF
// collection first and falls back to the Dell OEM store when that fails.
func (d *Driver) DBList(ctx context.Context) ([]platform.Cert, error) {
	if d.method == "standard" {
		certs, err := d.std.DBList(ctx)
		if err == nil {
			return certs, nil
		}
		slog.Debug("standard db listing failed, falling back to the Dell OEM store", "err", err)
	}
	return d.oemList(ctx)
}

func (d *Driver) oemList(ctx context.Context) ([]platform.Cert, error) {
	store, err := d.dbStore(ctx)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Certificates []redfish.Link `json:"Certificates"`
		Hash         []redfish.Link `json:"Hash"`
	}
	if err := d.c.GetJSON(ctx, store, &doc); err != nil {
		return nil, err
	}
	links := doc.Certificates
	if len(links) == 0 {
		links = doc.Hash
	}
	certs := make([]platform.Cert, len(links))
	for i, l := range links {
		certs[i] = platform.Cert{URI: l.ODataID}
	}
	return certs, nil
}

// DBImport enrols a certificate file: by the standard POST when method is
// "standard", else as a multipart upload to the Dell OEM store.
func (d *Driver) DBImport(ctx context.Context, file string) (platform.Change, error) {
	if d.method == "standard" {
		return d.std.DBImport(ctx, file)
	}
	data, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return platform.Change{}, fmt.Errorf("certificate file not found: %s", file)
	}
	if err != nil {
		return platform.Change{}, fmt.Errorf("read certificate file: %w", err)
	}
	if len(data) == 0 {
		return platform.Change{}, fmt.Errorf("certificate file is empty: %s", file)
	}
	store, err := d.dbStore(ctx)
	if err != nil {
		return platform.Change{}, err
	}
	resp, err := d.c.Upload(ctx, store+"/", "file", filepath.Base(file), data)
	if err != nil {
		return platform.Change{}, err
	}
	msgs := redfish.ParseMessages(resp.Body)
	restart := ""
	if redfish.NeedsReboot(msgs) {
		restart = " (Reboot required to take effect)"
	}
	return platform.Change{
		Message:        fmt.Sprintf("Certificate import successful%s. Messages: %s", restart, redfish.Summarize(msgs)),
		RebootRequired: redfish.NeedsReboot(msgs),
	}, nil
}

// DBExport saves the certificate at uri to file.
func (d *Driver) DBExport(ctx context.Context, uri, file string) (platform.Change, error) {
	resp, err := d.c.Do(ctx, http.MethodGet, uri, http.Header{"Accept": {"application/octet-stream"}}, nil)
	if err != nil {
		return platform.Change{}, err
	}
	if len(resp.Body) == 0 {
		return platform.Change{}, fmt.Errorf("exported certificate is empty: %s", uri)
	}
	if err := os.WriteFile(file, resp.Body, 0o644); err != nil {
		return platform.Change{}, fmt.Errorf("failed to save certificate: %w", err)
	}
	return platform.Change{Message: "DB certificate exported to " + file}, nil
}

// DBDelete removes the certificate at uri.
func (d *Driver) DBDelete(ctx context.Context, uri string) (platform.Change, error) {
	if _, err := d.c.Do(ctx, http.MethodDelete, uri, nil, nil); err != nil {
		return platform.Change{}, err
	}
	return platform.Change{Message: "DB certificate deleted successfully"}, nil
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/dell/ && go vet ./internal/dell/ && gofmt -l internal/dell`
Expected: `ok`, no vet or gofmt output.

- [ ] **Step 5: Commit**

```bash
git add internal/dell
git commit -m "feat(dell): certificate store list, import, export and delete" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Dell — iDRAC10 standard path and OpenAPI conformance

**Files:**
- Test: `internal/dell/idrac10_test.go`, `internal/dell/openapi_test.go`
- (No production change expected: Tasks 7 and 9 already implement the standard branch. If a test fails, fix `internal/dell/certs.go`.)

**Interfaces:**
- Consumes: everything from Tasks 3-9. Uses `docs/openapi-7.xx.yaml` and `docs/11017-1.30.xx.json` when present (they are git-ignored vendor files; the conformance test skips when absent).

- [ ] **Step 1: Write the iDRAC10 tests `internal/dell/idrac10_test.go`**

```go
package dell

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"sbmgr/internal/redfish"
	"sbmgr/internal/testbmc"
)

const dbs10 = sys + "/SecureBoot/SecureBootDatabases"

func newFake10(t *testing.T) (*testbmc.Server, *Driver) {
	t.Helper()
	s := testbmc.New(t)
	s.Redfish("Dell", "System.Embedded.1", "17G Monolithic", "1.30.60.50")
	s.StdSecureBoot("System.Embedded.1", false, "DeployedMode", 2)
	registerBios(s)
	c, err := redfish.New(s.URL, "root", "pw", redfish.Options{PollInterval: time.Millisecond, TaskTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return s, New(c, "idrac10", "")
}

func TestIdrac10DefaultsToStandardMethod(t *testing.T) {
	_, d := newFake10(t)
	if d.method != "standard" {
		t.Errorf("method = %q, want standard", d.method)
	}
	if New(nil, "idrac9", "").method != "oem" {
		t.Error("idrac9 must default to oem")
	}
	if New(nil, "idrac9", "standard").method != "standard" {
		t.Error("--method standard must be honoured on idrac9")
	}
}

func TestIdrac10ListsStandardDatabase(t *testing.T) {
	_, d := newFake10(t)
	certs, err := d.DBList(context.Background())
	if err != nil || len(certs) != 2 {
		t.Fatalf("certs = %+v, err = %v", certs, err)
	}
}

func TestIdrac10ImportPostsPEMJSON(t *testing.T) {
	s, d := newFake10(t)
	s.JSON("POST", dbs10+"/db/Certificates", 201, map[string]any{})
	pem := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	ch, err := d.DBImport(context.Background(), writeFile(t, "c.pem", []byte(pem)))
	if err != nil || !strings.Contains(ch.Message, "Certificate import successful") {
		t.Fatalf("ch = %+v, err = %v", ch, err)
	}
	var posted struct{ CertificateString, CertificateType string }
	for _, r := range s.Requests() {
		if r.Method == "POST" {
			_ = json.Unmarshal([]byte(r.Body), &posted)
		}
	}
	if posted.CertificateType != "PEM" || posted.CertificateString != pem {
		t.Errorf("posted = %+v", posted)
	}
}

func TestIdrac10DeleteUsesCertificateURI(t *testing.T) {
	s, d := newFake10(t)
	s.JSON("DELETE", dbs10+"/db/Certificates/1", 200, map[string]any{})
	if _, err := d.DBDelete(context.Background(), dbs10+"/db/Certificates/1"); err != nil {
		t.Fatal(err)
	}
}

func TestStandardListFallsBackToOEMStoreWhenDatabasesAreMissing(t *testing.T) {
	_, d := newFake9(t, "standard") // idrac9 fake exposes the OEM store only
	certs, err := d.DBList(context.Background())
	if err != nil || len(certs) != 2 {
		t.Fatalf("certs = %+v, err = %v", certs, err)
	}
}

func TestMethodOEMOnIdrac10UsesMultipartStore(t *testing.T) {
	s, _ := newFake10(t)
	c, err := redfish.New(s.URL, "root", "pw", redfish.Options{})
	if err != nil {
		t.Fatal(err)
	}
	d := New(c, "idrac10", "oem")
	s.JSON("GET", sys+"/SecureBoot", 200, map[string]any{"Oem": map[string]any{"Dell": map[string]any{
		"Certificates": testbmc.Link(sys + "/SecureBoot/Oem/Dell/Certificates")}}})
	s.JSON("GET", store, 200, map[string]any{"Certificates": []any{testbmc.Link(store + "/1")}})
	certs, err := d.DBList(context.Background())
	if err != nil || len(certs) != 1 {
		t.Fatalf("certs = %+v, err = %v", certs, err)
	}
}
```

- [ ] **Step 2: Write the OpenAPI conformance test `internal/dell/openapi_test.go`**

```go
package dell

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	reSystem  = regexp.MustCompile(`^/redfish/v1/Systems/[^/]+`)
	reOemCert = regexp.MustCompile(`/Oem/Dell/Certificates/[^/]+/[^/]+$`)
	reOemDB   = regexp.MustCompile(`/Oem/Dell/Certificates/[^/]+$`)
	reStdCert = regexp.MustCompile(`/SecureBootDatabases/[^/]+/Certificates/[^/]+$`)
	reStdColl = regexp.MustCompile(`/SecureBootDatabases/[^/]+/Certificates$`)
	reStdDB   = regexp.MustCompile(`/SecureBootDatabases/[^/]+$`)
	reTask    = regexp.MustCompile(`^/redfish/v1/TaskService/Tasks/[^/]+$`)
)

// normalize turns a concrete request path into the OpenAPI path template.
func normalize(p string) string {
	p = strings.TrimRight(p, "/")
	p = reSystem.ReplaceAllString(p, "/redfish/v1/Systems/{ComputerSystemId}")
	switch {
	case reOemCert.MatchString(p):
		p = reOemCert.ReplaceAllString(p, "/Oem/Dell/Certificates/{CertificateStoreId}/{CertificateId}")
	case reOemDB.MatchString(p):
		p = reOemDB.ReplaceAllString(p, "/Oem/Dell/Certificates/{CertificateStoreId}")
	case reStdCert.MatchString(p):
		p = reStdCert.ReplaceAllString(p, "/SecureBootDatabases/{DatabaseId}/Certificates/{CertificateId}")
	case reStdColl.MatchString(p):
		p = reStdColl.ReplaceAllString(p, "/SecureBootDatabases/{DatabaseId}/Certificates")
	case reStdDB.MatchString(p):
		p = reStdDB.ReplaceAllString(p, "/SecureBootDatabases/{DatabaseId}")
	}
	return reTask.ReplaceAllString(p, "/redfish/v1/TaskService/Tasks/{TaskId}")
}

// hasPath reports whether the OpenAPI document (YAML or JSON) declares the path.
func hasPath(spec, p string) bool {
	return strings.Contains(spec, "\""+p+"\":") || strings.Contains(spec, "\n  "+p+":")
}

func readSpec(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", name))
	if err != nil {
		t.Skipf("vendor OpenAPI %s not present (git-ignored): %v", name, err)
	}
	return string(b)
}

func assertPathsDocumented(t *testing.T, spec string, paths []string) {
	t.Helper()
	for _, p := range paths {
		if p == "/redfish/v1" {
			continue // service root
		}
		if n := normalize(p); !hasPath(spec, n) {
			t.Errorf("request path %q (template %q) is not in the vendor OpenAPI", p, n)
		}
	}
}

func TestIdrac9PathsExistInOpenAPI(t *testing.T) {
	spec := readSpec(t, "openapi-7.xx.yaml")
	for _, method := range []string{"oem", "standard"} {
		s, d := newFake9(t, method)
		ctx := context.Background()
		_, _ = d.Status(ctx)
		_, _ = d.SetSecureBoot(ctx, true)
		_, _ = d.SetPolicy(ctx, "Custom")
		_, _ = d.DBList(ctx)
		_, _ = d.DBImport(ctx, writeFile(t, "c.pem", []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")))
		_, _ = d.DBExport(ctx, store+"/CustSecbootpolicy.7", filepath.Join(t.TempDir(), "o.der"))
		_, _ = d.DBDelete(ctx, store+"/CustSecbootpolicy.7")
		var paths []string
		for _, r := range s.Requests() {
			paths = append(paths, r.Path)
		}
		if len(paths) < 8 {
			t.Fatalf("%s: only %d requests recorded, the scenario did not run", method, len(paths))
		}
		assertPathsDocumented(t, spec, paths)
	}
}

func TestIdrac10PathsExistInOpenAPI(t *testing.T) {
	spec := readSpec(t, "11017-1.30.xx.json")
	s, d := newFake10(t)
	s.JSON("POST", dbs10+"/db/Certificates", 201, map[string]any{})
	s.JSON("DELETE", dbs10+"/db/Certificates/1", 200, map[string]any{})
	ctx := context.Background()
	_, _ = d.Status(ctx)
	_, _ = d.DBList(ctx)
	_, _ = d.DBImport(ctx, writeFile(t, "c.pem", []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")))
	_, _ = d.DBDelete(ctx, dbs10+"/db/Certificates/1")
	var paths []string
	for _, r := range s.Requests() {
		paths = append(paths, r.Path)
	}
	assertPathsDocumented(t, spec, paths)
}
```

- [ ] **Step 3: Run the tests**

Run: `go test ./internal/dell/ -v -run 'Idrac10|Standard|MethodOEM|PathsExist' 2>&1 | tail -30`
Expected: all PASS. The two `PathsExist...` tests PASS when `docs/openapi-7.xx.yaml` and `docs/11017-1.30.xx.json` exist (they do on the author's machine) and SKIP otherwise. If a path is reported missing, either the driver calls a path the vendor does not document (fix the driver) or the `normalize` template is wrong (fix the regex).

- [ ] **Step 4: Run the whole package and vet**

Run: `go test ./internal/dell/ && go vet ./internal/dell/ && gofmt -l internal/dell`
Expected: `ok`, no output.

- [ ] **Step 5: Commit**

```bash
git add internal/dell
git commit -m "test(dell): iDRAC10 standard path and OpenAPI conformance" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 11: Lenovo driver

**Files:**
- Create: `internal/lenovo/driver.go`
- Test: `internal/lenovo/driver_test.go`

**Interfaces:**
- Consumes: `stdsb.Driver` (embedded; exported field `H`), `redfish.ParseMessages`.
- Produces: `func New(c *redfish.Client) *Driver`; `Driver` supports `status`, `enable`, `disable`, `db_list`, `db_import`, `db_delete`. `SetSecureBoot` reads the verdict from `ExtendedInfo` (HTTP 200 in both cases); `DBImport` adds a hint when the BMC answers `FQXSFPU4097G`.

- [ ] **Step 1: Write the failing tests `internal/lenovo/driver_test.go`**

```go
package lenovo

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
	"sbmgr/internal/testbmc"
)

const sb = "/redfish/v1/Systems/1/SecureBoot"

func newFake(t *testing.T) (*testbmc.Server, *Driver) {
	t.Helper()
	s := testbmc.New(t)
	s.Redfish("Lenovo", "1", "XCC", "6.0")
	s.StdSecureBoot("1", false, "SetupMode", 1)
	c, err := redfish.New(s.URL, "USERID", "pw", redfish.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return s, New(c)
}

func msg(id, text string) map[string]any {
	return map[string]any{"@Message.ExtendedInfo": []any{
		map[string]any{"MessageId": id, "Message": text, "Severity": "Warning", "Resolution": "Reboot the computer system."}}}
}

func TestSetSecureBootRebootRequiredIsSuccessDespiteHTTP200(t *testing.T) {
	s, d := newFake(t)
	s.JSON("PATCH", sb, 200, msg("Base.1.15.RebootRequired", "Changes completed successfully, but these changes will not take effect until next reboot."))
	ch, err := d.SetSecureBoot(context.Background(), true)
	if err != nil || !ch.RebootRequired {
		t.Fatalf("ch = %+v, err = %v", ch, err)
	}
}

func TestSetSecureBootPhysicalPresenceErrorIsAFailureDespiteHTTP200(t *testing.T) {
	s, d := newFake(t)
	s.JSON("PATCH", sb, 200, msg("Base.1.15.PhysicalPresenceError", "The operation failed because of Remote Physical Presence security requirements."))
	if _, err := d.SetSecureBoot(context.Background(), true); err == nil || !strings.Contains(err.Error(), "physical presence") {
		t.Errorf("err = %v, want physical presence failure", err)
	}
}

func TestSetSecureBootUnknownResponseIsAFailure(t *testing.T) {
	s, d := newFake(t)
	s.JSON("PATCH", sb, 200, map[string]any{})
	if _, err := d.SetSecureBoot(context.Background(), true); err == nil || !strings.Contains(err.Error(), "unknown response") {
		t.Errorf("err = %v", err)
	}
}

func TestDBImportExplainsFQXSFPU4097G(t *testing.T) {
	s, d := newFake(t)
	s.JSON("POST", sb+"/SecureBootDatabases/db/Certificates", 400, msg("FQXSFPU4097G", "Secure Boot policy is not Custom"))
	p := filepath.Join(t.TempDir(), "c.pem")
	if err := os.WriteFile(p, []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := d.DBImport(context.Background(), p)
	if err == nil || !strings.Contains(err.Error(), "FQXSFPU4097G") || !strings.Contains(err.Error(), "Custom Policy") {
		t.Errorf("err = %v, want the FQXSFPU4097G hint about Custom Policy", err)
	}
}

func TestStatusListAndSupports(t *testing.T) {
	_, d := newFake(t)
	st, err := d.Status(context.Background())
	if err != nil || st.Mode != "SetupMode" || st.Policy != "N/A" {
		t.Fatalf("st = %+v, err = %v", st, err)
	}
	certs, err := d.DBList(context.Background())
	if err != nil || len(certs) != 1 {
		t.Fatalf("certs = %+v, err = %v", certs, err)
	}
	if d.Name() != "lenovo" || d.Supports(platform.ActionPolicyCustom) || !d.Supports(platform.ActionDBImport) {
		t.Error("name or Supports() wrong")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/lenovo/`
Expected: FAIL (`undefined: New`).

- [ ] **Step 3: Implement `internal/lenovo/driver.go`**

```go
// Package lenovo implements the Lenovo XClarity Controller (XCC) driver. It is
// the generic standard driver with XCC's own verdict rule: PATCH SecureBoot
// answers HTTP 200 whether it worked or not, and the result is in ExtendedInfo.
package lenovo

import (
	"context"
	"fmt"
	"strings"

	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
	"sbmgr/internal/stdsb"
)

// Driver embeds the generic driver and overrides what XCC does differently.
type Driver struct{ *stdsb.Driver }

var _ platform.Platform = (*Driver)(nil)

// New builds a Lenovo driver.
func New(c *redfish.Client) *Driver { return &Driver{stdsb.NewDriver("lenovo", c, 0)} }

// SetSecureBoot PATCHes SecureBootEnable and reads the verdict from ExtendedInfo:
// RebootRequired means accepted (effective on next boot); PhysicalPresenceError
// means refused (Remote Physical Presence not asserted); anything else is unknown.
func (d *Driver) SetSecureBoot(ctx context.Context, enable bool) (platform.Change, error) {
	resp, err := d.H.SetEnable(ctx, enable)
	if err != nil {
		return platform.Change{}, err
	}
	msgs := redfish.ParseMessages(resp.Body)
	for _, m := range msgs {
		if strings.Contains(strings.ToLower(m.ID), "physicalpresenceerror") {
			return platform.Change{}, fmt.Errorf("physical presence not asserted: %s", m.Text)
		}
	}
	for _, m := range msgs {
		if strings.Contains(strings.ToLower(m.ID), "rebootrequired") {
			return platform.Change{
				Message:        "Success (reboot required). Messages: " + redfish.Summarize(msgs),
				RebootRequired: true,
			}, nil
		}
	}
	return platform.Change{}, fmt.Errorf("unknown response. Messages: %s", redfish.Summarize(msgs))
}

// DBImport enrols a certificate. XCC refuses it with FQXSFPU4097G unless the
// Secure Boot policy is "Custom Policy"; the hint says how to fix that.
func (d *Driver) DBImport(ctx context.Context, file string) (platform.Change, error) {
	ch, err := d.Driver.DBImport(ctx, file)
	if err != nil && strings.Contains(err.Error(), "FQXSFPU4097G") {
		return ch, fmt.Errorf("%w (set the Secure Boot policy to \"Custom Policy\" in UEFI setup or with OneCLI, then retry)", err)
	}
	return ch, err
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/lenovo/ && go vet ./internal/lenovo/ && gofmt -l internal/lenovo`
Expected: `ok`, no output.

- [ ] **Step 5: Commit**

```bash
git add internal/lenovo
git commit -m "feat(lenovo): XCC driver with ExtendedInfo verdict and Custom Policy hint" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 12: Platform detection and driver factory

**Files:**
- Create: `internal/detect/detect.go`
- Test: `internal/detect/detect_test.go`

**Interfaces:**
- Consumes: `redfish.Client.Root/Manager`, `dell.New`, `stdsb.NewDriver`, `lenovo.New`.
- Produces: `func New(ctx context.Context, c *redfish.Client, forced, method string) (platform.Platform, error)` — `forced` is `auto`, `""`, `idrac9`, `idrac10`, `ilo`, `lenovo` or `supermicro`; `method` is passed to the Dell driver (`""`, `oem`, `standard`).

- [ ] **Step 1: Write the failing tests**

```go
package detect

import (
	"context"
	"strings"
	"testing"

	"sbmgr/internal/redfish"
	"sbmgr/internal/testbmc"
)

func client(t *testing.T, vendor, firmware string) *redfish.Client {
	t.Helper()
	s := testbmc.New(t)
	s.Redfish(vendor, "1", "Model", firmware)
	c, err := redfish.New(s.URL, "u", "p", redfish.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAutoDetectionByVendorAndFirmware(t *testing.T) {
	cases := []struct{ vendor, firmware, want string }{
		{"Dell", "7.20.30.50", "idrac9"},
		{"Dell", "4.40.00.00", "idrac9"},
		{"Dell", "3.30.30.30", "idrac9"},
		{"Dell", "1.30.60.50", "idrac10"},
		{"HPE", "1.62", "ilo"},
		{"Hewlett Packard Enterprise", "1.62", "ilo"},
		{"Lenovo", "6.0", "lenovo"},
		{"Supermicro", "1.0", "supermicro"},
		{"Super Micro Computer", "1.0", "supermicro"},
	}
	for _, tc := range cases {
		p, err := New(context.Background(), client(t, tc.vendor, tc.firmware), "auto", "")
		if err != nil || p.Name() != tc.want {
			t.Errorf("%s %s: got %v, %v; want %s", tc.vendor, tc.firmware, p, err, tc.want)
		}
	}
}

func TestDetectionFailuresSuggestPlatformFlag(t *testing.T) {
	for _, tc := range []struct{ vendor, firmware, want string }{
		{"Acme", "1.0", "unknown vendor"},
		{"Dell", "2.1.0.0", "unsupported iDRAC firmware"},
		{"Dell", "abc", "unreadable iDRAC firmware version"},
	} {
		_, err := New(context.Background(), client(t, tc.vendor, tc.firmware), "", "")
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "--platform") {
			t.Errorf("%s %s: err = %v, want %q and a --platform hint", tc.vendor, tc.firmware, err, tc.want)
		}
	}
}

func TestForcedPlatformSkipsDetection(t *testing.T) {
	p, err := New(context.Background(), client(t, "Dell", "7.0.0.0"), "ilo", "")
	if err != nil || p.Name() != "ilo" {
		t.Fatalf("got %v, %v", p, err)
	}
	if _, err := New(context.Background(), client(t, "Dell", "7.0.0.0"), "nope", ""); err == nil || !strings.Contains(err.Error(), "unknown platform") {
		t.Errorf("err = %v", err)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/detect/`
Expected: FAIL (`undefined: New`).

- [ ] **Step 3: Implement `internal/detect/detect.go`**

```go
// Package detect identifies a BMC's platform from Redfish and builds its driver.
package detect

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"sbmgr/internal/dell"
	"sbmgr/internal/lenovo"
	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
	"sbmgr/internal/stdsb"
)

// New returns the driver for forced (idrac9, idrac10, ilo, lenovo, supermicro),
// or detects it when forced is "" or "auto". method only affects Dell drivers.
func New(ctx context.Context, c *redfish.Client, forced, method string) (platform.Platform, error) {
	name := strings.ToLower(forced)
	if name == "" || name == "auto" {
		var err error
		if name, err = identify(ctx, c); err != nil {
			return nil, err
		}
	}
	switch name {
	case "idrac9", "idrac10":
		return dell.New(c, name, method), nil
	case "ilo":
		return stdsb.NewDriver("ilo", c, 3072), nil // iLO: 3 KiB per certificate
	case "supermicro":
		return stdsb.NewDriver("supermicro", c, 0), nil
	case "lenovo":
		return lenovo.New(c), nil
	}
	return nil, fmt.Errorf("unknown platform %q", forced)
}

// identify reads Vendor from the service root and, for Dell, the BMC firmware
// major version (1.x is iDRAC10; 3.x to 7.x is iDRAC9).
func identify(ctx context.Context, c *redfish.Client) (string, error) {
	root, err := c.Root(ctx)
	if err != nil {
		return "", err
	}
	v := strings.ToLower(root.Vendor)
	switch {
	case strings.Contains(v, "dell"):
		m, err := c.Manager(ctx)
		if err != nil {
			return "", err
		}
		major, err := strconv.Atoi(strings.SplitN(m.FirmwareVersion, ".", 2)[0])
		if err != nil {
			return "", fmt.Errorf("cannot detect platform: unreadable iDRAC firmware version %q (use --platform)", m.FirmwareVersion)
		}
		switch {
		case major == 1:
			return "idrac10", nil
		case major >= 3 && major <= 7:
			return "idrac9", nil
		}
		return "", fmt.Errorf("cannot detect platform: unsupported iDRAC firmware %q (use --platform)", m.FirmwareVersion)
	case strings.Contains(v, "hpe"), strings.Contains(v, "hewlett"):
		return "ilo", nil
	case strings.Contains(v, "lenovo"):
		return "lenovo", nil
	case strings.Contains(v, "supermicro"), strings.Contains(v, "super micro"):
		return "supermicro", nil
	}
	return "", fmt.Errorf("cannot detect platform: unknown vendor %q (use --platform)", root.Vendor)
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/detect/ && go vet ./internal/detect/ && gofmt -l internal/detect`
Expected: `ok`, no output.

- [ ] **Step 5: Commit**

```bash
git add internal/detect
git commit -m "feat(detect): identify the platform from Redfish and build its driver" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 13: Action orchestration

**Files:**
- Create: `internal/actions/actions.go`
- Test: `internal/actions/actions_test.go`

**Interfaces:**
- Consumes: `platform.Platform`, `report.New`, `redfish.SanitizePath`.
- Produces: `type Params struct{ CertURI, CertFile string }`; `func Run(ctx context.Context, p platform.Platform, ip, action string, par Params) report.Result`. Behaviour: unsupported action → error row with no network call; `status` first for every Secure Boot action; enable/disable skip the write when the state already matches; policy actions refuse when Secure Boot is enabled and the mode is not `DeployedMode`, skip the write only when the applied policy is the target **and** no different policy is pending, and report "already pending" when the target is already staged.

- [ ] **Step 1: Write the failing tests**

```go
package actions

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"sbmgr/internal/platform"
)

type fake struct {
	platform.Unsupported
	supported []string
	status    platform.Status
	statusErr error
	change    platform.Change
	err       error
	certs     []platform.Cert
	calls     []string
}

func (f *fake) Name() string           { return "fake" }
func (f *fake) Supports(a string) bool { return slices.Contains(f.supported, a) }
func (f *fake) Status(context.Context) (platform.Status, error) {
	f.calls = append(f.calls, "status")
	return f.status, f.statusErr
}
func (f *fake) SetSecureBoot(_ context.Context, en bool) (platform.Change, error) {
	f.calls = append(f.calls, fmt.Sprintf("enable=%v", en))
	return f.change, f.err
}
func (f *fake) SetPolicy(_ context.Context, p string) (platform.Change, error) {
	f.calls = append(f.calls, "policy="+p)
	return f.change, f.err
}
func (f *fake) DBList(context.Context) ([]platform.Cert, error) { return f.certs, f.err }
func (f *fake) DBImport(_ context.Context, file string) (platform.Change, error) {
	f.calls = append(f.calls, "import="+file)
	return f.change, f.err
}
func (f *fake) DBExport(_ context.Context, uri, file string) (platform.Change, error) {
	f.calls = append(f.calls, "export="+uri+">"+file)
	return f.change, f.err
}
func (f *fake) DBDelete(_ context.Context, uri string) (platform.Change, error) {
	f.calls = append(f.calls, "delete="+uri)
	return f.change, f.err
}

func newFake() *fake {
	return &fake{supported: platform.AllActions, status: platform.Status{
		Name: "SB", Mode: "DeployedMode", Policy: "Standard", CurrentBoot: "Disabled"}}
}

func TestUnsupportedActionMakesNoCall(t *testing.T) {
	f := newFake()
	f.supported = []string{platform.ActionStatus}
	r := Run(context.Background(), f, "10.0.0.1", platform.ActionDBImport, Params{})
	if r.Success || !strings.Contains(r.Error, "not supported on fake") || len(f.calls) != 0 {
		t.Errorf("r = %+v, calls = %v", r, f.calls)
	}
}

func TestStatusAction(t *testing.T) {
	f := newFake()
	r := Run(context.Background(), f, "10.0.0.1", platform.ActionStatus, Params{})
	if !r.Success || r.CurrentStatus != "Disabled" || r.NewStatus != "Disabled" || r.CurrentPolicy != "Standard" || r.NewPolicy != "Standard" || r.Name != "SB" {
		t.Errorf("r = %+v", r)
	}
	f = newFake()
	f.statusErr = errors.New("boom")
	if r := Run(context.Background(), f, "10.0.0.1", platform.ActionStatus, Params{}); r.Success || r.Error != "Failed to get status: boom" {
		t.Errorf("r = %+v", r)
	}
}

func TestEnableReportsPendingRebootAndSkipsWhenAlreadyEnabled(t *testing.T) {
	f := newFake()
	f.change = platform.Change{Message: "Success (Server restart required)", RebootRequired: true}
	r := Run(context.Background(), f, "10.0.0.1", platform.ActionEnable, Params{})
	if !r.Success || r.NewStatus != "Enabled (Pending - Reboot Required)" || r.ChangeMessage == "" || !slices.Contains(f.calls, "enable=true") {
		t.Errorf("r = %+v, calls = %v", r, f.calls)
	}
	f = newFake()
	f.status.Enabled = true
	r = Run(context.Background(), f, "10.0.0.1", platform.ActionEnable, Params{})
	if !r.Success || r.NewStatus != "Enabled" || slices.Contains(f.calls, "enable=true") {
		t.Errorf("already enabled: r = %+v, calls = %v", r, f.calls)
	}
	f = newFake()
	f.status.Enabled = true
	f.change = platform.Change{}
	r = Run(context.Background(), f, "10.0.0.1", platform.ActionDisable, Params{})
	if !r.Success || r.NewStatus != "Disabled" {
		t.Errorf("disable without reboot: r = %+v", r)
	}
}

func TestPolicyGuardRefusesNonDeployedMode(t *testing.T) {
	f := newFake()
	f.status.Enabled, f.status.Mode = true, "SetupMode"
	r := Run(context.Background(), f, "10.0.0.1", platform.ActionPolicyCustom, Params{})
	if r.Success || !strings.Contains(r.Error, "expected 'DeployedMode'") || slices.Contains(f.calls, "policy=Custom") {
		t.Errorf("r = %+v, calls = %v", r, f.calls)
	}
}

func TestPolicyIdempotencyConsidersPendingValue(t *testing.T) {
	ctx := context.Background()
	// applied == target, nothing pending: no write.
	f := newFake()
	f.status.Policy = "Custom"
	r := Run(ctx, f, "ip", platform.ActionPolicyCustom, Params{})
	if !r.Success || r.NewPolicy != "Custom" || slices.Contains(f.calls, "policy=Custom") {
		t.Errorf("applied==target: r = %+v, calls = %v", r, f.calls)
	}
	// applied == target but a different value is pending: must write to override it.
	f = newFake()
	f.status.Policy, f.status.PendingPolicy = "Custom", "Standard"
	f.change = platform.Change{Location: "/t/JID_1", JobID: "JID_1"}
	r = Run(ctx, f, "ip", platform.ActionPolicyCustom, Params{})
	if !r.Success || !slices.Contains(f.calls, "policy=Custom") {
		t.Errorf("stale pending: r = %+v, calls = %v", r, f.calls)
	}
	// target already pending: no write, reported as pending.
	f = newFake()
	f.status.PendingPolicy = "Custom"
	r = Run(ctx, f, "ip", platform.ActionPolicyCustom, Params{})
	if !r.Success || r.NewPolicy != "Custom (Pending - Reboot Required)" || slices.Contains(f.calls, "policy=Custom") {
		t.Errorf("already pending: r = %+v, calls = %v", r, f.calls)
	}
}

func TestPolicyChangeNeedsLocationAndJobID(t *testing.T) {
	f := newFake()
	f.change = platform.Change{Location: "/t/JID_9", JobID: "JID_9", Message: "ok"}
	r := Run(context.Background(), f, "ip", platform.ActionPolicyCustom, Params{})
	if !r.Success || r.NewPolicy != "Custom (Pending - Reboot Required)" {
		t.Errorf("r = %+v", r)
	}
	f = newFake()
	f.change = platform.Change{Message: "ok"}
	r = Run(context.Background(), f, "ip", platform.ActionPolicyCustom, Params{})
	if r.Success || !strings.Contains(r.Error, "missing Location or Job ID") || r.NewPolicy != "Unknown (Task Creation Failed)" {
		t.Errorf("r = %+v", r)
	}
	f = newFake()
	f.err = errors.New("SYS011")
	if r := Run(context.Background(), f, "ip", platform.ActionPolicyCustom, Params{}); r.Success || r.Error != "Failed to set policy: SYS011" {
		t.Errorf("r = %+v", r)
	}
}

func TestDBActions(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.certs = []platform.Cert{{URI: "/a"}, {URI: "/b"}}
	if r := Run(ctx, f, "ip", platform.ActionDBList, Params{}); !r.Success || r.CertCount != 2 || r.Message != "Found 2 DB certificates" {
		t.Errorf("list: %+v", r)
	}
	f = newFake()
	f.change = platform.Change{Message: "imported"}
	if r := Run(ctx, f, "ip", platform.ActionDBImport, Params{CertFile: "c.der"}); !r.Success || r.Message != "imported" || !slices.Contains(f.calls, "import=c.der") {
		t.Errorf("import: %+v calls=%v", r, f.calls)
	}
	// MSYS-mangled URIs are repaired before reaching the driver.
	f = newFake()
	Run(ctx, f, "ip", platform.ActionDBDelete, Params{CertURI: "C:/Program Files/Git/redfish/v1/x/DB/Cust.7"})
	Run(ctx, f, "ip", platform.ActionDBExport, Params{CertURI: "redfish/v1/x/DB/Cust.7", CertFile: "o.der"})
	if !slices.Contains(f.calls, "delete=/redfish/v1/x/DB/Cust.7") || !slices.Contains(f.calls, "export=/redfish/v1/x/DB/Cust.7>o.der") {
		t.Errorf("calls = %v", f.calls)
	}
	f = newFake()
	f.err = errors.New("HTTP 500: x")
	if r := Run(ctx, f, "ip", platform.ActionDBList, Params{}); r.Success || r.Error != "Failed to get DB certificates: HTTP 500: x" {
		t.Errorf("list error: %+v", r)
	}
	if r := Run(ctx, f, "ip", platform.ActionDBDelete, Params{CertURI: "/u"}); r.Success || r.Error != "HTTP 500: x" {
		t.Errorf("delete error: %+v", r)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/actions/`
Expected: FAIL (`undefined: Run`, `undefined: Params`).

- [ ] **Step 3: Implement `internal/actions/actions.go`**

```go
// Package actions turns one CLI action into driver calls and a report.Result.
package actions

import (
	"context"
	"fmt"

	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
	"sbmgr/internal/report"
)

// Params carries the CLI arguments some actions need.
type Params struct{ CertURI, CertFile string }

// Run executes action on p and describes the outcome. It never panics on
// driver errors: every failure becomes r.Error.
func Run(ctx context.Context, p platform.Platform, ip, action string, par Params) report.Result {
	r := report.New(ip, action, p.Name())
	if !p.Supports(action) {
		r.Error = fmt.Sprintf("action not supported on %s", p.Name())
		return r
	}
	if platform.IsDBAction(action) {
		runDB(ctx, p, action, par, &r)
	} else {
		runSecureBoot(ctx, p, action, &r)
	}
	return r
}

func finish(r *report.Result, ch platform.Change, err error) {
	if err != nil {
		r.Error = err.Error()
		return
	}
	r.Success = true
	r.Message = ch.Message
}

func runDB(ctx context.Context, p platform.Platform, action string, par Params, r *report.Result) {
	switch action {
	case platform.ActionDBList:
		certs, err := p.DBList(ctx)
		if err != nil {
			r.Error = "Failed to get DB certificates: " + err.Error()
			return
		}
		r.Success, r.CertCount = true, len(certs)
		r.Message = fmt.Sprintf("Found %d DB certificates", len(certs))
	case platform.ActionDBImport:
		ch, err := p.DBImport(ctx, par.CertFile)
		finish(r, ch, err)
	case platform.ActionDBExport:
		ch, err := p.DBExport(ctx, redfish.SanitizePath(par.CertURI), par.CertFile)
		finish(r, ch, err)
	case platform.ActionDBDelete:
		ch, err := p.DBDelete(ctx, redfish.SanitizePath(par.CertURI))
		finish(r, ch, err)
	}
}

func setIf(dst *string, v string) {
	if v != "" {
		*dst = v
	}
}

func runSecureBoot(ctx context.Context, p platform.Platform, action string, r *report.Result) {
	st, err := p.Status(ctx)
	if err != nil {
		r.Error = "Failed to get status: " + err.Error()
		return
	}
	r.CurrentStatus = "Disabled"
	if st.Enabled {
		r.CurrentStatus = "Enabled"
	}
	r.Description = st.Description
	setIf(&r.Name, st.Name)
	setIf(&r.CurrentBoot, st.CurrentBoot)
	setIf(&r.CurrentMode, st.Mode)
	setIf(&r.CurrentPolicy, st.Policy)
	setIf(&r.CertificatesURI, st.CertificatesURI)

	switch action {
	case platform.ActionStatus:
		r.Success, r.NewStatus, r.NewPolicy = true, r.CurrentStatus, r.CurrentPolicy
	case platform.ActionPolicyCustom, platform.ActionPolicyStandard:
		setPolicy(ctx, p, action, st, r)
	default:
		setEnable(ctx, p, action, st, r)
	}
}

func setPolicy(ctx context.Context, p platform.Platform, action string, st platform.Status, r *report.Result) {
	target := "Custom"
	if action == platform.ActionPolicyStandard {
		target = "Standard"
	}
	if st.Enabled && st.Mode != "DeployedMode" {
		r.Error = fmt.Sprintf("Cannot change policy: Secure Boot mode is '%s', expected 'DeployedMode'", st.Mode)
		return
	}
	switch {
	case st.Policy == target && (st.PendingPolicy == "" || st.PendingPolicy == target):
		r.Success, r.NewPolicy = true, target
		return
	case st.PendingPolicy == target:
		r.Success, r.NewPolicy = true, platform.PendingStatus(target, true)
		r.ChangeMessage = "Policy change to " + target + " is already pending; reboot to apply"
		return
	}
	ch, err := p.SetPolicy(ctx, target)
	if err != nil {
		r.Error = "Failed to set policy: " + err.Error()
		return
	}
	r.ChangeMessage = ch.Message
	if ch.Location == "" || ch.JobID == "" {
		r.NewPolicy = "Unknown (Task Creation Failed)"
		r.Error = "Policy change task creation failed - missing Location or Job ID"
		return
	}
	r.NewPolicy = platform.PendingStatus(target, true)
	r.Success = true
}

func setEnable(ctx context.Context, p platform.Platform, action string, st platform.Status, r *report.Result) {
	target := action == platform.ActionEnable
	if st.Enabled == target {
		r.Success, r.NewStatus = true, r.CurrentStatus
		return
	}
	ch, err := p.SetSecureBoot(ctx, target)
	if err != nil {
		r.Error = "Failed to set secure boot: " + err.Error()
		return
	}
	r.ChangeMessage = ch.Message
	word := "Disabled"
	if target {
		word = "Enabled"
	}
	r.NewStatus = platform.PendingStatus(word, ch.RebootRequired)
	r.Success = true
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/actions/ && go vet ./internal/actions/ && gofmt -l internal/actions`
Expected: `ok`; if `gofmt -l` lists the test file (struct alignment), run `gofmt -w internal/actions` and re-run.

- [ ] **Step 5: Commit**

```bash
git add internal/actions
git commit -m "feat(actions): orchestrate the nine actions, with pending-aware policy idempotency" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 14: Runner (worker pool and session lifecycle)

**Files:**
- Create: `internal/runner/runner.go`
- Test: `internal/runner/runner_test.go`

**Interfaces:**
- Consumes: `inventory.Host`, `redfish.New/Login/Logout`, `detect.New`, `actions.Run`, `report.New`.
- Produces: `type Options struct{ Action string; Params actions.Params; Platform, Method string; Concurrency int; Client redfish.Options }`; `func Run(ctx context.Context, hosts []inventory.Host, opt Options) []report.Result` — one result per host, in input order; every logged-in session is closed.

- [ ] **Step 1: Write the failing tests**

```go
package runner

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"sbmgr/internal/inventory"
	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
	"sbmgr/internal/testbmc"
)

const sessionURI = "/redfish/v1/SessionService/Sessions/1"

func lenovoBMC(t *testing.T) *testbmc.Server {
	t.Helper()
	s := testbmc.New(t)
	s.Redfish("Lenovo", "1", "XCC", "6.0")
	s.StdSecureBoot("1", false, "SetupMode", 1)
	return s
}

func host(s *testbmc.Server) inventory.Host {
	return inventory.Host{IP: s.URL, Username: "USERID", Password: "secret-pw"}
}

func opts(action string) Options {
	return Options{Action: action, Platform: "auto", Concurrency: 2, Client: redfish.Options{Timeout: 2 * time.Second}}
}

// Review Focus 3 and 4: one dead BMC does not stop the others, rows keep input
// order, and every session that was opened is closed.
func TestRunIsolatesFailuresKeepsOrderAndClosesSessions(t *testing.T) {
	a, b := lenovoBMC(t), lenovoBMC(t)
	dead := testbmc.New(t)
	dead.Close()
	res := Run(context.Background(), []inventory.Host{host(a), host(dead), host(b)}, opts(platform.ActionStatus))
	if len(res) != 3 {
		t.Fatalf("results = %d, want 3", len(res))
	}
	if !res[0].Success || res[0].IP != a.URL || res[0].Platform != "lenovo" {
		t.Errorf("res[0] = %+v", res[0])
	}
	if res[1].Success || res[1].Error == "" || res[1].IP != dead.URL {
		t.Errorf("res[1] = %+v, want an error row for the dead BMC", res[1])
	}
	if !res[2].Success || res[2].IP != b.URL {
		t.Errorf("res[2] = %+v", res[2])
	}
	for _, s := range []*testbmc.Server{a, b} {
		if n := s.Count("DELETE", sessionURI); n != 1 {
			t.Errorf("session DELETE count = %d, want 1", n)
		}
	}
	out, _ := json.Marshal(res)
	if strings.Contains(string(out), "secret-pw") {
		t.Error("results must never contain the password")
	}
}

func TestRunClosesSessionWhenTheActionFails(t *testing.T) {
	s := lenovoBMC(t)
	res := Run(context.Background(), []inventory.Host{host(s)}, opts(platform.ActionPolicyCustom))
	if res[0].Success || !strings.Contains(res[0].Error, "not supported on lenovo") {
		t.Fatalf("res[0] = %+v", res[0])
	}
	if n := s.Count("DELETE", sessionURI); n != 1 {
		t.Errorf("session DELETE count = %d, want 1 even when the action fails", n)
	}
}

func TestRunPassesParamsAndForcedPlatform(t *testing.T) {
	s := testbmc.New(t)
	s.Redfish("Acme", "1", "X", "1") // undetectable vendor
	s.StdSecureBoot("1", false, "SetupMode", 3)
	o := opts(platform.ActionDBList)
	o.Platform = "supermicro"
	res := Run(context.Background(), []inventory.Host{host(s)}, o)
	if !res[0].Success || res[0].CertCount != 3 || res[0].Platform != "supermicro" {
		t.Errorf("res[0] = %+v", res[0])
	}
}

func TestRunWithCancelledContextStillReturnsOneRowPerHost(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	hosts := []inventory.Host{{IP: "http://127.0.0.1:1"}, {IP: "http://127.0.0.1:2"}, {IP: "http://127.0.0.1:3"}}
	res := Run(ctx, hosts, opts(platform.ActionStatus))
	if len(res) != 3 {
		t.Fatalf("results = %d, want 3", len(res))
	}
	for i, r := range res {
		if r.Success || r.Error == "" {
			t.Errorf("res[%d] = %+v, want a failure row", i, r)
		}
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/runner/`
Expected: FAIL (`undefined: Run`, `undefined: Options`).

- [ ] **Step 3: Implement `internal/runner/runner.go`**

```go
// Package runner processes hosts in parallel, one Redfish session per host.
package runner

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"sbmgr/internal/actions"
	"sbmgr/internal/detect"
	"sbmgr/internal/inventory"
	"sbmgr/internal/redfish"
	"sbmgr/internal/report"
)

// Options configures a run.
type Options struct {
	Action      string
	Params      actions.Params
	Platform    string // "auto" or a forced platform name
	Method      string // Dell import method: "", "oem" or "standard"
	Concurrency int    // default 20
	Client      redfish.Options
}

// Run executes opt.Action on every host and returns one result per host, in
// input order. A failing host never stops the others.
func Run(ctx context.Context, hosts []inventory.Host, opt Options) []report.Result {
	n := opt.Concurrency
	if n <= 0 {
		n = 20
	}
	results := make([]report.Result, len(hosts))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < n && w < len(hosts); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = one(ctx, hosts[i], opt)
			}
		}()
	}
	for i := range hosts {
		select {
		case jobs <- i:
		case <-ctx.Done():
			for j := i; j < len(hosts); j++ {
				r := report.New(hosts[j].IP, opt.Action, "")
				r.Error = "cancelled before start: " + ctx.Err().Error()
				results[j] = r
			}
			close(jobs)
			wg.Wait()
			return results
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

// one processes a single host. The session is always closed, and a panic in a
// driver becomes an error row instead of killing the run.
func one(ctx context.Context, h inventory.Host, opt Options) (res report.Result) {
	res = report.New(h.IP, opt.Action, "")
	defer func() {
		if r := recover(); r != nil {
			res.Success = false
			res.Error = fmt.Sprintf("panic: %v", r)
		}
	}()
	c, err := redfish.New(h.IP, h.Username, h.Password, opt.Client)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if err := c.Login(ctx); err != nil {
		res.Error = "login failed: " + err.Error()
		return res
	}
	defer c.Logout(context.WithoutCancel(ctx))
	p, err := detect.New(ctx, c, opt.Platform, opt.Method)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	slog.Debug("platform detected", "ip", h.IP, "platform", p.Name())
	return actions.Run(ctx, p, h.IP, opt.Action, opt.Params)
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/runner/ && go vet ./internal/runner/ && gofmt -l internal/runner`
Expected: `ok`, no output.

- [ ] **Step 5: Commit**

```bash
git add internal/runner
git commit -m "feat(runner): parallel hosts with ordered results and guaranteed session logout" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 15: CLI

**Files:**
- Modify (replace): `cmd/sbmgr/main.go`
- Test: `cmd/sbmgr/main_test.go`

**Interfaces:**
- Consumes: `inventory`, `runner`, `report`, `platform.AllActions`.
- Produces: `func run(args []string, stdout, stderr io.Writer) int` (exit codes: 0 all hosts succeeded or `-h`, 1 at least one host failed, 2 usage or input error).

- [ ] **Step 1: Write the failing tests `cmd/sbmgr/main_test.go`**

```go
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
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./cmd/sbmgr/`
Expected: FAIL (`undefined: run`).

- [ ] **Step 3: Replace `cmd/sbmgr/main.go`**

```go
// Command sbmgr manages UEFI Secure Boot and the db certificate store over
// Redfish on a fleet of BMCs (Dell iDRAC, HPE iLO, Lenovo XCC, Supermicro).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"
	"time"

	"sbmgr/internal/actions"
	"sbmgr/internal/inventory"
	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
	"sbmgr/internal/report"
	"sbmgr/internal/runner"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

type options struct {
	input, output, action, format       string
	platform, method, certURI, certFile string
	caFile                              string
	concurrency                         int
	timeout, taskTimeout                time.Duration
	noWait, verifyTLS, verbose          bool
}

var platformNames = []string{"auto", "idrac9", "idrac10", "ilo", "lenovo", "supermicro"}

func (o *options) validate() string {
	switch {
	case o.input == "":
		return "-i/--input is required"
	case o.output == "":
		return "-o/--output is required"
	case o.action == "":
		return "-a/--action is required"
	case !slices.Contains(platform.AllActions, o.action):
		return fmt.Sprintf("unknown action %q (choose one of: %s)", o.action, strings.Join(platform.AllActions, ", "))
	case o.format != "csv" && o.format != "json":
		return "format must be csv or json"
	case !slices.Contains(platformNames, o.platform):
		return fmt.Sprintf("unknown platform %q (choose one of: %s)", o.platform, strings.Join(platformNames, ", "))
	case o.method != "" && o.method != "oem" && o.method != "standard":
		return "method must be oem or standard"
	case o.action == platform.ActionDBImport && o.certFile == "":
		return "db_import requires --cert-file"
	case o.action == platform.ActionDBDelete && o.certURI == "":
		return "db_delete requires --cert-uri"
	case o.action == platform.ActionDBExport && (o.certURI == "" || o.certFile == ""):
		return "db_export requires --cert-uri and --cert-file"
	case o.concurrency <= 0:
		return "concurrency must be positive"
	}
	return ""
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sbmgr", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	both := func(p *string, short, long, def, usage string) {
		fs.StringVar(p, short, def, usage)
		fs.StringVar(p, long, def, usage)
	}
	both(&o.input, "i", "input", "", "input CSV: start_ip,end_ip,username,password")
	both(&o.output, "o", "output", "", "output file")
	both(&o.action, "a", "action", "", "action: "+strings.Join(platform.AllActions, ", "))
	both(&o.format, "f", "format", "csv", "output format: csv or json")
	fs.StringVar(&o.platform, "platform", "auto", "auto, idrac9, idrac10, ilo, lenovo or supermicro (all but idrac9 are not validated on hardware)")
	fs.StringVar(&o.method, "method", "", "Dell certificate import method: oem or standard (default oem on iDRAC9, standard on iDRAC10)")
	fs.StringVar(&o.certURI, "cert-uri", "", "certificate URI for db_export and db_delete")
	fs.StringVar(&o.certFile, "cert-file", "", "certificate file for db_import (PEM or DER) and db_export")
	fs.IntVar(&o.concurrency, "concurrency", 20, "hosts processed in parallel")
	fs.DurationVar(&o.timeout, "timeout", 30*time.Second, "per-request timeout")
	fs.DurationVar(&o.taskTimeout, "task-timeout", 120*time.Second, "how long to follow an asynchronous task")
	fs.BoolVar(&o.noWait, "no-wait", false, "do not follow asynchronous tasks")
	fs.BoolVar(&o.verifyTLS, "verify-tls", false, "verify BMC TLS certificates (off by default: BMCs are self-signed)")
	fs.StringVar(&o.caFile, "ca-file", "", "PEM CA bundle used to verify BMC certificates (implies --verify-tls)")
	fs.BoolVar(&o.verbose, "v", false, "debug logs (never include secrets)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: sbmgr -i nodes.csv -o out.csv -a <action> [options]")
		fmt.Fprintln(stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if msg := o.validate(); msg != "" {
		fmt.Fprintln(stderr, "sbmgr:", msg)
		return 2
	}

	level := slog.LevelWarn
	if o.verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level})))

	if w := inventory.PermissionWarning(o.input); w != "" {
		fmt.Fprintln(stderr, "warning:", w)
	}
	rows, err := inventory.Read(o.input)
	if err != nil {
		fmt.Fprintln(stderr, "sbmgr:", err)
		return 2
	}
	hosts, err := inventory.Hosts(rows)
	if err != nil {
		fmt.Fprintln(stderr, "sbmgr:", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	results := runner.Run(ctx, hosts, runner.Options{
		Action:      o.action,
		Params:      actions.Params{CertURI: o.certURI, CertFile: o.certFile},
		Platform:    o.platform,
		Method:      o.method,
		Concurrency: o.concurrency,
		Client: redfish.Options{
			Timeout: o.timeout, TaskTimeout: o.taskTimeout, NoWait: o.noWait,
			VerifyTLS: o.verifyTLS, CAFile: o.caFile,
		},
	})

	if err := writeOutput(o, results); err != nil {
		fmt.Fprintln(stderr, "sbmgr:", err)
		return 2
	}
	failed := 0
	for _, r := range results {
		if !r.Success {
			failed++
		}
	}
	fmt.Fprintf(stdout, "Processing complete. Results saved to %s (%d succeeded, %d failed)\n", o.output, len(results)-failed, failed)
	if failed > 0 {
		return 1
	}
	return 0
}

func writeOutput(o options, results []report.Result) error {
	f, err := os.Create(o.output)
	if err != nil {
		return err
	}
	if o.format == "json" {
		err = report.WriteJSON(f, results)
	} else {
		err = report.WriteCSV(f, o.action, results)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./cmd/sbmgr/ && go vet ./cmd/... && gofmt -l cmd`
Expected: `ok`; run `gofmt -w cmd` if the struct field alignment is listed, then re-run.

- [ ] **Step 5: Commit**

```bash
git add cmd
git commit -m "feat(cli): flags, validation, output and exit codes" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 16: Full verification, cross-builds and docs

**Files:**
- Modify: `README.md`, `docs/superpowers/specs/2026-10-05-secure-boot-manager-go-design.md`

- [ ] **Step 1: Run the whole suite**

Run: `cd /Users/fjacquet/Projects/secure-import && go build ./... && go vet ./... && go test ./... -count=1 && make check`
Expected: every package `ok` (or `no test files` for `cmd` packages without tests), no vet output, no gofmt output.

- [ ] **Step 2: Run the race detector**

Run: `go test ./... -race -count=1`
Expected: all `ok`. A reported race in `runner` means result slots are shared incorrectly — fix before continuing.

- [ ] **Step 3: Build for every OS**

Run: `make build-all && ls bin`
Expected: `sbmgr-linux-amd64`, `sbmgr-linux-arm64`, `sbmgr-windows-amd64.exe`, `sbmgr-darwin-arm64`, `sbmgr-darwin-amd64` (each 6 to 7 MB, no CGO, no runtime to install).

- [ ] **Step 4: Smoke-test the native binary**

Run: `bin/sbmgr-darwin-arm64 -h 2>&1 | head -5` (use the binary matching your machine)
Expected: the usage line `Usage: sbmgr -i nodes.csv -o out.csv -a <action> [options]`.

Then run it against a **test** BMC, read-only first: `bin/sbmgr-darwin-arm64 -i nodes.csv -o status.csv -a status` and `-a db_list`. Do not run write actions before these two look right. The cross-built Windows and Linux binaries cannot be run on macOS; run `sbmgr.exe -h` once on a Windows machine.

- [ ] **Step 5: Update the README status and add build instructions**

In `README.md`, replace the badge line `![Status](https://img.shields.io/badge/status-design-orange)` with `![Status](https://img.shields.io/badge/status-alpha-orange)`. Replace the blockquote under the intro (`> **Status: design only.** ...` and its second line) with:

```
> **Status: alpha.** The code is written and tested against a fake BMC; only the
> iDRAC9 behavior relies on a script proven in production. No platform has been
> validated on hardware with this tool: start with `-a status`, then `-a db_list`.
```

Append this section before `## Documentation`:

```
## Building

```sh
make build        # local binary in bin/sbmgr
make build-all    # linux amd64/arm64, windows amd64, macOS arm64/amd64 (no CGO, no runtime)
make test         # tests against a fake BMC
```
```

(Replace the placeholder fences with real triple backticks when editing the file.)

- [ ] **Step 6: Record the implementation-time decisions in the spec**

In `docs/superpowers/specs/2026-10-05-secure-boot-manager-go-design.md`, in section 11, add as the last item:

```
7. Implementation status: the code and its tests (fake BMC, Dell OpenAPI specs) are in place;
   everything remains not validated on hardware. Recommended order of trials: `status`,
   `db_list`, then a write on a test server.
```

- [ ] **Step 7: Commit**

```bash
git add README.md docs
git commit -m "docs: mark the tool as alpha and document the build" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```
