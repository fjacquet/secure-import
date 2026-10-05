package dell

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"sbmgr/internal/testbmc"
)

var (
	reSystem  = regexp.MustCompile(`^/redfish/v1/Systems/[^/]+`)
	reOemCert = regexp.MustCompile(`/Oem/Dell/Certificates/[^/]+/[^/]+$`)
	reOemDB   = regexp.MustCompile(`/Oem/Dell/Certificates/[^/]+$`)
	reStdCert = regexp.MustCompile(`/SecureBootDatabases/[^/]+/Certificates/[^/]+$`)
	reStdColl = regexp.MustCompile(`/SecureBootDatabases/[^/]+/Certificates$`)
	reStdSig  = regexp.MustCompile(`/SecureBootDatabases/[^/]+/Signatures(/[^/]+)?$`)
	reDBReset = regexp.MustCompile(`/SecureBootDatabases/[^/]+/Actions/SecureBootDatabase\.ResetKeys$`)
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
	case reDBReset.MatchString(p):
		p = reDBReset.ReplaceAllString(p, "/SecureBootDatabases/{DatabaseId}/Actions/SecureBootDatabase.ResetKeys")
	case reStdSig.MatchString(p):
		p = reStdSig.ReplaceAllStringFunc(p, func(m string) string {
			if strings.Count(m, "/") == 4 { // /SecureBootDatabases/<id>/Signatures/<sig>
				return "/SecureBootDatabases/{DatabaseId}/Signatures/{SignatureId}"
			}
			return "/SecureBootDatabases/{DatabaseId}/Signatures"
		})
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
		_, _ = d.DBImport(ctx, writeFile(t, "c.der", realCert(t)))
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
	_, _ = d.DBImport(ctx, writeFile(t, "c.der", realCert(t)))
	_, _ = d.DBDelete(ctx, dbs10+"/db/Certificates/1")
	var paths []string
	for _, r := range s.Requests() {
		paths = append(paths, r.Path)
	}
	assertPathsDocumented(t, spec, paths)
}

// The paths used for the other databases (KEK listing, dbx signatures, both ResetKeys
// actions) are declared by the iDRAC10 OpenAPI.
func TestIdrac10DatabasePathsExistInOpenAPI(t *testing.T) {
	spec := readSpec(t, "11017-1.30.xx.json")
	s, d := newFake10(t)
	const base = "/redfish/v1/Systems/System.Embedded.1/SecureBoot"
	reset := base + "/SecureBootDatabases/KEK/Actions/SecureBootDatabase.ResetKeys"
	s.JSON("GET", base, 200, map[string]any{"SecureBootDatabases": testbmc.Link(base + "/SecureBootDatabases"),
		"Actions": map[string]any{"#SecureBoot.ResetKeys": map[string]any{"target": base + "/Actions/SecureBoot.ResetKeys"}}})
	s.JSON("GET", base+"/SecureBootDatabases", 200, map[string]any{"Members": []any{
		testbmc.Link(base + "/SecureBootDatabases/KEK"), testbmc.Link(base + "/SecureBootDatabases/dbx")}})
	s.JSON("GET", base+"/SecureBootDatabases/KEK", 200, map[string]any{"Certificates": testbmc.Link(base + "/SecureBootDatabases/KEK/Certificates"),
		"Actions": map[string]any{"#SecureBootDatabase.ResetKeys": map[string]any{"target": reset}}})
	s.JSON("GET", base+"/SecureBootDatabases/KEK/Certificates", 200, map[string]any{"Members": []any{}})
	s.JSON("GET", base+"/SecureBootDatabases/dbx", 200, map[string]any{"Signatures": testbmc.Link(base + "/SecureBootDatabases/dbx/Signatures")})
	s.JSON("GET", base+"/SecureBootDatabases/dbx/Signatures", 200, map[string]any{"Members": []any{testbmc.Link(base + "/SecureBootDatabases/dbx/Signatures/1")}})
	s.JSON("POST", base+"/SecureBootDatabases/dbx/Signatures", 201, map[string]any{})
	s.JSON("POST", reset, 200, map[string]any{})
	s.JSON("POST", base+"/Actions/SecureBoot.ResetKeys", 200, map[string]any{})
	ctx := context.Background()
	d.WithDatabase("KEK")
	_, _ = d.DBList(ctx)
	_, _ = d.ResetKeys(ctx, "DeleteAllKeys")
	d.WithDatabase("dbx")
	_, _ = d.DBList(ctx)
	_, _ = d.AddSignature(ctx, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "")
	var paths []string
	for _, r := range s.Requests() {
		paths = append(paths, r.Path)
	}
	if len(paths) < 6 {
		t.Fatalf("only %d requests recorded, the scenario did not run", len(paths))
	}
	assertPathsDocumented(t, spec, paths)
}
