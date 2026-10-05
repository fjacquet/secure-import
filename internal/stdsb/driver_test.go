package stdsb

import (
	"context"
	"encoding/json"
	"encoding/pem"
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

func critical(id, text string) map[string]any {
	return map[string]any{"@Message.ExtendedInfo": []any{
		map[string]any{"MessageId": id, "Message": text, "Severity": "Critical", "Resolution": "None"}}}
}

func TestSetSecureBootCriticalMessageIsFailure(t *testing.T) {
	s, d := newFake(t, 0)
	s.JSON("PATCH", sys+"/SecureBoot", 200, critical("Base.1.0.GeneralError", "boom"))
	if _, err := d.SetSecureBoot(context.Background(), true); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("err = %v", err)
	}
}

func TestDBImportCriticalMessageIsFailure(t *testing.T) {
	s, d := newFake(t, 0)
	s.JSON("POST", dbs+"/db/Certificates", 200, critical("FQXSFPU4097G", "refused"))
	p := writeFile(t, testCertDER(t))
	if _, err := d.DBImport(context.Background(), p); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("err = %v", err)
	}
}

func TestDBImportRejectsOversizedFile(t *testing.T) {
	s, d := newFake(t, 0)
	p := writeFile(t, make([]byte, MaxCertFile+1))
	if _, err := d.DBImport(context.Background(), p); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("err = %v", err)
	}
	if s.Count("POST", dbs+"/db/Certificates") != 0 {
		t.Error("nothing must be sent")
	}
}

func TestDBDeleteCriticalMessageIsFailure(t *testing.T) {
	s, d := newFake(t, 0)
	uri := dbs + "/db/Certificates/1"
	s.JSON("DELETE", uri, 200, critical("Base.1.0.GeneralError", "cannot delete"))
	if _, err := d.DBDelete(context.Background(), uri); err == nil || !strings.Contains(err.Error(), "cannot delete") {
		t.Errorf("err = %v", err)
	}
}

func memberWithPEM(t *testing.T, s *testbmc.Server, der []byte) {
	t.Helper()
	s.JSON("GET", dbs+"/db/Certificates/1", 200, map[string]any{
		"Id": "1", "CertificateString": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		"Subject": map[string]any{"CommonName": "Vendor CA"}, "ValidNotAfter": "2035-01-01T00:00:00Z"})
}

func TestDBImportSkipsCertificateAlreadyPresent(t *testing.T) {
	s, d := newFake(t, 0)
	der := testCertDER(t)
	memberWithPEM(t, s, der)
	ch, err := d.DBImport(context.Background(), writeFile(t, der))
	if err != nil || !strings.Contains(ch.Message, "already present") || ch.RebootRequired {
		t.Fatalf("ch = %+v, err = %v", ch, err)
	}
	if s.Count("POST", dbs+"/db/Certificates") != 0 {
		t.Error("an enrolled certificate must not be posted again")
	}
}

func TestDBImportProceedsWhenCertificateIsDifferentOrUnknown(t *testing.T) {
	s, d := newFake(t, 0)
	s.JSON("POST", dbs+"/db/Certificates", 201, map[string]any{})
	memberWithPEM(t, s, testCertDER(t)) // another certificate
	if _, err := d.DBImport(context.Background(), writeFile(t, testCertDER(t))); err != nil || s.Count("POST", dbs+"/db/Certificates") != 1 {
		t.Errorf("err = %v, posts = %d", err, s.Count("POST", dbs+"/db/Certificates"))
	}
}

func TestDBListFillsOptionalDetails(t *testing.T) {
	s, d := newFake(t, 0)
	memberWithPEM(t, s, testCertDER(t))
	certs, err := d.DBList(context.Background())
	if err != nil || len(certs) != 2 || certs[0].Subject != "Vendor CA" || certs[0].NotAfter != "2035-01-01" || certs[1].Subject != "" {
		t.Errorf("certs = %+v, err = %v", certs, err)
	}
}

func TestStatusSaysUnsupportedWhenSecureBootResourceIsMissing(t *testing.T) {
	s := testbmc.New(t)
	s.Redfish("Supermicro", "1", "BMC", "1.0")
	s.JSON("GET", sys, 200, map[string]any{})
	c, _ := redfish.New(s.URL, "u", "p", redfish.Options{})
	_, err := NewDriver("supermicro", c, 0).Status(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Errorf("err = %v", err)
	}
}

func TestStatusSaysLicenseRequired(t *testing.T) {
	s, d := newFake(t, 0)
	s.JSON("GET", sys+"/SecureBoot", 403, map[string]any{"error": map[string]any{"@Message.ExtendedInfo": []any{
		map[string]any{"MessageId": "Base.1.0.OemLicenseNotPassed", "Message": "license", "Severity": "Critical"}}}})
	_, err := d.Status(context.Background())
	if err == nil || !strings.Contains(err.Error(), "license is required") {
		t.Errorf("err = %v", err)
	}
}
