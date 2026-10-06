// Package testbmc is a minimal fake Redfish BMC for tests.
package testbmc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
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
	fsys   fs.FS // optional static mockup tree, see Mount
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
	if h == nil && s.fsys != nil && s.serveMockup(w, r) {
		return
	}
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
