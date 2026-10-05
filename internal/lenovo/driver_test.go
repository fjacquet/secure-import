package lenovo

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: realCert(t)}), 0o600); err != nil {
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

func realCert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestResetKeysReadsVerdictFromMessages(t *testing.T) {
	s, d := newFake(t)
	s.JSON("GET", sb, 200, map[string]any{"SecureBootDatabases": map[string]string{"@odata.id": sb + "/SecureBootDatabases"},
		"Actions": map[string]any{"#SecureBoot.ResetKeys": map[string]any{"target": sb + "/Actions/SecureBoot.ResetKeys"}}})
	s.JSON("POST", sb+"/Actions/SecureBoot.ResetKeys", 200, msg("Lenovo.1.0.RebootRequired", "reboot"))
	ch, err := d.ResetKeys(context.Background(), "ResetAllKeysToDefault")
	if err != nil || !ch.RebootRequired {
		t.Fatalf("ch = %+v, err = %v", ch, err)
	}
	s.JSON("POST", sb+"/Actions/SecureBoot.ResetKeys", 200, msg("Lenovo.1.0.PhysicalPresenceError", "no presence"))
	if _, err := d.ResetKeys(context.Background(), "ResetAllKeysToDefault"); err == nil || !strings.Contains(err.Error(), "physical presence") {
		t.Errorf("err = %v", err)
	}
}

// A reset of one database must stay a reset of that database on XCC too, never a reset
// of every key (the top-level action).
func TestResetKeysOfOneDatabaseDoesNotFallBackToTheWholeSecureBoot(t *testing.T) {
	s, d := newFake(t)
	const dbs = sb + "/SecureBootDatabases"
	target := dbs + "/KEK/Actions/SecureBootDatabase.ResetKeys"
	s.JSON("GET", dbs, 200, map[string]any{"Members": []any{map[string]string{"@odata.id": dbs + "/KEK"}}})
	s.JSON("GET", dbs+"/KEK", 200, map[string]any{"Actions": map[string]any{"#SecureBootDatabase.ResetKeys": map[string]any{
		"target": target, "ResetKeysType@Redfish.AllowableValues": []string{"ResetAllKeysToDefault", "DeleteAllKeys"}}}})
	s.JSON("GET", sb, 200, map[string]any{"SecureBootDatabases": map[string]string{"@odata.id": dbs},
		"Actions": map[string]any{"#SecureBoot.ResetKeys": map[string]any{"target": sb + "/Actions/SecureBoot.ResetKeys"}}})
	s.JSON("POST", target, 200, msg("Lenovo.1.0.RebootRequired", "reboot"))
	s.JSON("POST", sb+"/Actions/SecureBoot.ResetKeys", 200, msg("Lenovo.1.0.RebootRequired", "reboot"))
	d.WithDatabase("KEK")
	if _, err := d.ResetKeys(context.Background(), "DeleteAllKeys"); err != nil {
		t.Fatal(err)
	}
	if s.Count("POST", target) != 1 || s.Count("POST", sb+"/Actions/SecureBoot.ResetKeys") != 0 {
		t.Error("the per-database action must be used, and the top-level reset (all keys) must not be")
	}
}
