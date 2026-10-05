package dell

import (
	"context"
	"encoding/json"
	pemEncode "encoding/pem"
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
	pem := string(pemEncode.EncodeToMemory(&pemEncode.Block{Type: "CERTIFICATE", Bytes: realCert(t)}))
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
