package probe

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"sbmgr/internal/redfish"
	"sbmgr/internal/report"
	"sbmgr/internal/testbmc"
)

const (
	sys = "/redfish/v1/Systems/1"
	dbs = sys + "/SecureBoot/SecureBootDatabases"
)

func client(t *testing.T, s *testbmc.Server) *redfish.Client {
	t.Helper()
	c, err := redfish.New(s.URL, "admin", "pw", redfish.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func find(checks []report.Check, name string) (report.Check, bool) {
	for _, c := range checks {
		if c.Name == name {
			return c, true
		}
	}
	return report.Check{}, false
}

func ilo(t *testing.T) *testbmc.Server {
	s := testbmc.New(t)
	s.Redfish("HPE", "1", "iLO 6", "1.62")
	s.StdSecureBoot("1", true, "UserMode", 1)
	s.JSON("GET", sys, 200, map[string]any{"SecureBoot": testbmc.Link(sys + "/SecureBoot"), "SerialNumber": "SN-SECRET-1"})
	s.JSON("GET", dbs+"/db/Certificates/1", 200, map[string]any{
		"Id": "1", "Fingerprint": "AB:CD", "FingerprintHashAlgorithm": "SHA-256",
		"Subject": map[string]any{"CommonName": "Vendor CA"}})
	return s
}

func TestProbeReportsEveryCheckAndWritesNothing(t *testing.T) {
	s := ilo(t)
	rep := Run(context.Background(), client(t, s), "auto", "", false)
	if rep.Platform != "ilo" {
		t.Errorf("platform = %q", rep.Platform)
	}
	for _, name := range []string{"service root", "platform detection", "SecureBoot resource", "SecureBoot databases",
		"db certificates", "driver status", "driver db_list"} {
		c, ok := find(rep.Checks, name)
		if !ok || c.Status != report.CheckOK {
			t.Errorf("check %q = %+v (found %v)", name, c, ok)
		}
	}
	if c, _ := find(rep.Checks, "db certificate fields"); !strings.Contains(c.Detail, "Fingerprint") || !strings.Contains(c.Detail, "Issuer") {
		t.Errorf("certificate fields = %+v", c)
	}
	for _, r := range s.Requests() {
		if r.Method != "GET" {
			t.Errorf("probe sent %s %s: it must only read", r.Method, r.Path)
		}
	}
}

func TestProbeFlagsMissingPartsInsteadOfStopping(t *testing.T) {
	s := testbmc.New(t)
	s.Redfish("Supermicro", "1", "BMC", "1.0")
	s.JSON("GET", sys, 200, map[string]any{"SecureBoot": testbmc.Link(sys + "/SecureBoot")})
	s.JSON("GET", sys+"/SecureBoot", 403, map[string]any{})
	rep := Run(context.Background(), client(t, s), "auto", "", false)
	if c, _ := find(rep.Checks, "SecureBoot resource"); c.Status != report.CheckFail || !strings.Contains(c.Detail, "403") {
		t.Errorf("SecureBoot resource = %+v", c)
	}
	if _, ok := find(rep.Checks, "driver status"); !ok {
		t.Error("later checks must still run")
	}
	if rep.OK() {
		t.Error("a failing check must make the report fail")
	}
}

func TestProbeCaptureRedactsIdentifiers(t *testing.T) {
	s := ilo(t)
	rep := Run(context.Background(), client(t, s), "auto", "", true)
	raw, ok := rep.Capture[sys]
	if !ok {
		t.Fatalf("capture keys = %v", keys(rep.Capture))
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["SerialNumber"] == "SN-SECRET-1" || !strings.Contains(string(raw), "redacted") {
		t.Errorf("serial number leaked: %s", raw)
	}
	all, _ := json.Marshal(rep.Capture)
	if strings.Contains(string(all), "SN-SECRET-1") || strings.Contains(string(all), "pw") && strings.Contains(string(all), `"pw"`) {
		t.Error("capture holds a secret")
	}
	if rep2 := Run(context.Background(), client(t, ilo(t)), "auto", "", false); rep2.Capture != nil {
		t.Error("nothing is captured unless asked")
	}
}

func keys(m map[string]json.RawMessage) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestProbeReportsEachDatabase(t *testing.T) {
	s := ilo(t)
	s.JSON("GET", dbs, 200, map[string]any{"Members": []any{
		testbmc.Link(dbs + "/PK"), testbmc.Link(dbs + "/KEK"), testbmc.Link(dbs + "/db"), testbmc.Link(dbs + "/dbx"), testbmc.Link(dbs + "/dbxDefault")}})
	s.JSON("GET", dbs+"/PK", 200, map[string]any{"Certificates": testbmc.Link(dbs + "/PK/Certificates")})
	s.JSON("GET", dbs+"/PK/Certificates", 200, map[string]any{"Members": []any{testbmc.Link(dbs + "/PK/Certificates/1")}})
	s.JSON("GET", dbs+"/KEK", 200, map[string]any{"Certificates": testbmc.Link(dbs + "/KEK/Certificates"),
		"Actions": map[string]any{"#SecureBootDatabase.ResetKeys": map[string]any{"target": "/x",
			"ResetKeysType@Redfish.AllowableValues": []string{"ResetAllKeysToDefault", "DeleteAllKeys"}}}})
	s.JSON("GET", dbs+"/KEK/Certificates", 200, map[string]any{"Members": []any{}})
	s.JSON("GET", dbs+"/dbx", 200, map[string]any{"Signatures": testbmc.Link(dbs + "/dbx/Signatures")})
	s.JSON("GET", dbs+"/dbx/Signatures", 200, map[string]any{"Members": []any{testbmc.Link(dbs + "/dbx/Signatures/1"), testbmc.Link(dbs + "/dbx/Signatures/2")}})
	rep := Run(context.Background(), client(t, s), "auto", "", false)
	want := map[string]string{
		"database PK": "Certificates: 1", "database KEK": "ResetAllKeysToDefault, DeleteAllKeys",
		"database dbx": "Signatures: 2", "default databases": "dbxDefault",
	}
	for name, frag := range want {
		if c, ok := find(rep.Checks, name); !ok || c.Status != report.CheckOK || !strings.Contains(c.Detail, frag) {
			t.Errorf("%s = %+v (found %v), want %q", name, c, ok, frag)
		}
	}
	for _, r := range s.Requests() {
		if r.Method != "GET" {
			t.Errorf("probe sent %s %s", r.Method, r.Path)
		}
	}
}

func TestProbeCaptureRedactsServiceTagsAndInitiatorNames(t *testing.T) {
	s := ilo(t)
	s.JSON("GET", sys, 200, map[string]any{"SecureBoot": testbmc.Link(sys + "/SecureBoot"),
		"Oem":              map[string]any{"Dell": map[string]any{"DellSystem": map[string]any{"ChassisServiceTag": "ABC1234", "NodeID": "N-77", "ExpressServiceCode": "123456789"}}},
		"SystemServiceTag": "SVC9999", "IscsiInitiatorName": "iqn.1998-01.com.vmware:esx01", "HostName": "esx01.corp.example"})
	rep := Run(context.Background(), client(t, s), "auto", "", true)
	all, _ := json.Marshal(rep.Capture)
	for _, secret := range []string{"ABC1234", "N-77", "123456789", "SVC9999", "iqn.1998", "esx01"} {
		if strings.Contains(string(all), secret) {
			t.Errorf("the capture still holds %q", secret)
		}
	}
}
