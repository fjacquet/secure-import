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
	if _, err := d.SetSecureBoot(context.Background(), true); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("err = %v, want a refusal for a Critical SYS4xx", err)
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

func TestSetSecureBootCriticalBesideSuccessIsFailure(t *testing.T) {
	s, d := newFake9(t, "")
	s.JSON("PATCH", sys+"/SecureBoot", 200, map[string]any{"@Message.ExtendedInfo": []any{
		map[string]any{"MessageId": "Base.1.12.Success", "Message": "ok", "Severity": "OK"},
		map[string]any{"MessageId": "IDRAC.2.9.SYS403", "Message": "bad", "Severity": "Critical"}}})
	if _, err := d.SetSecureBoot(context.Background(), true); err == nil || !strings.Contains(err.Error(), "bad") {
		t.Errorf("err = %v", err)
	}
}
