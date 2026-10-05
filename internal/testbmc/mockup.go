package testbmc

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"testing"
)

// ILOGen12 is a real HPE iLO capture (ProLiant DL360 Gen12) taken from HPE's
// ilo-redfish-emulator project (BSD-3-Clause, see testdata/ilo-dl360-gen12/LICENSE.emulator):
// the service root, the system and the whole SecureBoot tree with its databases.
//
//go:embed testdata/ilo-dl360-gen12
var iloFiles embed.FS

// ILOGen12 returns the capture rooted at the Redfish service (its index.json is /redfish/v1/).
func ILOGen12() fs.FS {
	sub, err := fs.Sub(iloFiles, "testdata/ilo-dl360-gen12")
	if err != nil {
		panic(err)
	}
	return sub
}

// Mount makes the server answer GET requests from a static mockup tree laid out as
// <redfish path>/index.json (DMTF mockup convention) whenever no explicit route
// matches. Any other method on a mounted path answers 405: the mockup is read-only,
// which also proves that a code path performs no write.
func (s *Server) Mount(root fs.FS) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fsys = root
}

// NewMockup starts a fake BMC serving the given mockup tree.
func NewMockup(t testing.TB, root fs.FS) *Server {
	s := New(t)
	s.Mount(root)
	return s
}

func (s *Server) serveMockup(w http.ResponseWriter, r *http.Request) bool {
	rel := strings.Trim(strings.TrimPrefix(r.URL.Path, "/redfish/v1"), "/")
	file := path.Join(rel, "index.json")
	data, err := fs.ReadFile(s.fsys, file)
	if err != nil {
		return false
	}
	if r.Method != http.MethodGet {
		WriteJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": map[string]any{
			"code": "Base.1.12.ActionNotSupported", "message": "mockup is read-only: " + r.Method + " " + r.URL.Path}})
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
	return true
}
