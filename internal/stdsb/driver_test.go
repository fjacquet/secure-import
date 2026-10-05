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
	"time"

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

func resetDoc(s *testbmc.Server, allowed ...string) {
	s.JSON("GET", sys+"/SecureBoot", 200, map[string]any{
		"SecureBootEnable": true, "SecureBootDatabases": testbmc.Link(dbs),
		"Actions": map[string]any{"#SecureBoot.ResetKeys": map[string]any{
			"target": sys + "/SecureBoot/Actions/SecureBoot.ResetKeys", "ResetKeysType@Redfish.AllowableValues": allowed}}})
}

func TestResetKeysPostsTheTypeTheBMCAllows(t *testing.T) {
	s, d := newFake(t, 0)
	resetDoc(s, "ResetAllKeysToDefault", "DeleteAllKeys")
	s.JSON("POST", sys+"/SecureBoot/Actions/SecureBoot.ResetKeys", 200, map[string]any{})
	if _, err := d.ResetKeys(context.Background(), "DeleteAllKeys"); err != nil {
		t.Fatal(err)
	}
	var body string
	for _, r := range s.Requests() {
		if r.Method == "POST" && strings.HasSuffix(r.Path, "ResetKeys") {
			body = r.Body
		}
	}
	if !strings.Contains(body, `"ResetKeysType":"DeleteAllKeys"`) {
		t.Errorf("body = %q", body)
	}
	if _, err := d.ResetKeys(context.Background(), "DeletePK"); err == nil || !strings.Contains(err.Error(), "ResetAllKeysToDefault") {
		t.Errorf("a type the BMC does not list must be refused with the allowed values, err = %v", err)
	}
}

func TestResetKeysWithoutActionIsUnsupported(t *testing.T) {
	_, d := newFake(t, 0)
	if _, err := d.ResetKeys(context.Background(), "ResetAllKeysToDefault"); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Errorf("err = %v", err)
	}
}

func TestResetKeysCriticalMessageIsFailure(t *testing.T) {
	s, d := newFake(t, 0)
	resetDoc(s)
	s.JSON("POST", sys+"/SecureBoot/Actions/SecureBoot.ResetKeys", 200, critical("Base.1.0.GeneralError", "denied"))
	if _, err := d.ResetKeys(context.Background(), "ResetAllKeysToDefault"); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Errorf("err = %v", err)
	}
}

func TestResetKeysFollowsTheTaskOf202(t *testing.T) {
	s := testbmc.New(t)
	s.Redfish("Dell", "1", "16G", "7.20.30.50")
	s.StdSecureBoot("1", false, "SetupMode", 0)
	resetDoc(s)
	task := "/redfish/v1/TaskService/Tasks/JID_9"
	s.JSONH("POST", sys+"/SecureBoot/Actions/SecureBoot.ResetKeys", 202, map[string]string{"Location": task}, map[string]any{})
	c, err := redfish.New(s.URL, "u", "p", redfish.Options{PollInterval: time.Millisecond, TaskTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	d := NewDriver("idrac9", c, 0)
	s.JSON("GET", task, 200, map[string]any{"TaskState": "Exception", "TaskStatus": "Critical", "Name": "reset"})
	if _, err := d.ResetKeys(context.Background(), "ResetDB"); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Errorf("a failed task must be an error, err = %v", err)
	}
	s.JSON("GET", task, 200, map[string]any{"TaskState": "Completed", "TaskStatus": "OK", "Name": "reset"})
	if ch, err := d.ResetKeys(context.Background(), "ResetDB"); err != nil || !strings.Contains(ch.Message, "State: Completed") {
		t.Errorf("ch = %+v, err = %v", ch, err)
	}
}

func newFakeVendor(t *testing.T, vendor, name string, dbCerts int) (*testbmc.Server, *Driver) {
	t.Helper()
	s := testbmc.New(t)
	s.Redfish(vendor, "1", "BMC", "1.0")
	s.StdSecureBoot("1", false, "SetupMode", dbCerts)
	c, err := redfish.New(s.URL, "admin", "pw", redfish.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return s, NewDriver(name, c, 0)
}

func TestSupermicroForbiddenSecureBootMentionsTheLicense(t *testing.T) {
	s, d := newFakeVendor(t, "Supermicro", "supermicro", 0)
	s.JSON("GET", sys+"/SecureBoot", 403, map[string]any{})
	if _, err := d.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "SFT-DCMS-SINGLE") {
		t.Errorf("err = %v", err)
	}
	s.JSON("GET", sys+"/SecureBoot", 404, map[string]any{})
	if _, err := d.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "SFT-DCMS-SINGLE") {
		t.Errorf("404: err = %v", err)
	}
}

func TestSupermicroImportNotes201Expectation(t *testing.T) {
	s, d := newFakeVendor(t, "Supermicro", "supermicro", 0)
	s.JSON("POST", dbs+"/db/Certificates", 200, map[string]any{})
	ch, err := d.DBImport(context.Background(), writeFile(t, testCertDER(t)))
	if err != nil || !strings.Contains(ch.Message, "HTTP 200") {
		t.Fatalf("ch = %+v, err = %v", ch, err)
	}
	s.JSON("POST", dbs+"/db/Certificates", 201, map[string]any{})
	if ch, err = d.DBImport(context.Background(), writeFile(t, testCertDER(t))); err != nil || strings.Contains(ch.Message, "HTTP 20") {
		t.Errorf("a 201 needs no note: ch = %+v, err = %v", ch, err)
	}
}

func TestILORefusesImportWhenTheDatabaseIsFull(t *testing.T) {
	s, d := newFakeVendor(t, "HPE", "ilo", 16)
	s.JSON("POST", dbs+"/db/Certificates", 201, map[string]any{})
	_, err := d.DBImport(context.Background(), writeFile(t, testCertDER(t)))
	if err == nil || !strings.Contains(err.Error(), "16") || s.Count("POST", dbs+"/db/Certificates") != 0 {
		t.Errorf("err = %v, posts = %d", err, s.Count("POST", dbs+"/db/Certificates"))
	}
}
