package dell

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sbmgr/internal/platform"
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
	want := realCert(t)
	ch, err := d.DBImport(context.Background(), writeFile(t, "dell_2025.der", want))
	if err != nil || !strings.Contains(ch.Message, "Certificate import successful") {
		t.Fatalf("ch = %+v, err = %v", ch, err)
	}
	if v := <-got; v[0] != "dell_2025.der" || v[1] != string(want) {
		t.Errorf("uploaded %v", v)
	}
}

// Changelog bug 4: a 2xx import is a success even when the MessageIds are not
// the ones an older firmware used.
func TestDBImportAcceptsNewerMessageIdsAndReportsReboot(t *testing.T) {
	s, d := newFake9(t, "")
	s.JSON("POST", store+"/", 200, info("IDRAC.2.9.SYS430", "Restart the server."))
	ch, err := d.DBImport(context.Background(), writeFile(t, "c.der", realCert(t)))
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

func TestDBImportCriticalMessageIsFailure(t *testing.T) {
	s, d := newFake9(t, "")
	s.JSON("POST", store+"/", 200, map[string]any{"@Message.ExtendedInfo": []any{
		map[string]any{"MessageId": "IDRAC.2.9.SYS403", "Message": "duplicate", "Severity": "Critical"}}})
	if _, err := d.DBImport(context.Background(), writeFile(t, "c.der", realCert(t))); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("err = %v", err)
	}
}

func TestDBImportRejectsNonCertificate(t *testing.T) {
	s, d := newFake9(t, "")
	if _, err := d.DBImport(context.Background(), writeFile(t, "k.pem", []byte("-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n"))); err == nil {
		t.Error("private key must be rejected")
	}
	if s.Count("POST", store+"/") != 0 {
		t.Error("nothing must be uploaded")
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

func TestDBExportFileIsPrivate(t *testing.T) {
	_, d := newFake9(t, "")
	out := filepath.Join(t.TempDir(), "out.der")
	if _, err := d.DBExport(context.Background(), store+"/CustSecbootpolicy.7", out); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(out); fi == nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Errorf("mode = %v", fi)
	}
}

func TestDBDeleteCriticalMessageIsFailure(t *testing.T) {
	s, d := newFake9(t, "")
	s.JSON("DELETE", store+"/CustSecbootpolicy.1", 200, map[string]any{"@Message.ExtendedInfo": []any{
		map[string]any{"MessageId": "IDRAC.2.9.SYS403", "Message": "not deleted", "Severity": "Critical"}}})
	if _, err := d.DBDelete(context.Background(), store+"/CustSecbootpolicy.1"); err == nil || !strings.Contains(err.Error(), "not deleted") {
		t.Errorf("err = %v", err)
	}
}

func TestDBImportSkipsCertificateAlreadyInOEMStore(t *testing.T) {
	s, d := newFake9(t, "")
	der := realCert(t)
	s.Handle("GET", store+"/CustSecbootpolicy.1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(der)
	})
	ch, err := d.DBImport(context.Background(), writeFile(t, "c.der", der))
	if err != nil || !strings.Contains(ch.Message, "already present") {
		t.Fatalf("ch = %+v, err = %v", ch, err)
	}
	if s.Count("POST", store+"/") != 0 {
		t.Error("nothing must be uploaded")
	}
}

// iDRAC10's standard Certificate resource returns JSON, not the raw certificate.
func TestDBExportReadsCertificateStringFromJSON(t *testing.T) {
	s, d := newFake9(t, "")
	pemText := "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
	s.JSON("GET", store+"/Std.1", 200, map[string]any{"CertificateString": pemText, "CertificateType": "PEM"})
	out := filepath.Join(t.TempDir(), "o.pem")
	if _, err := d.DBExport(context.Background(), store+"/Std.1", out); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != pemText {
		t.Errorf("file = %q", b)
	}
}

func TestDBExportOfJSONWithoutCertificateIsAnError(t *testing.T) {
	s, d := newFake9(t, "")
	s.JSON("GET", store+"/Oem.1", 200, map[string]any{"Thumbprint": "ab", "SubjectCommonName_CN": "x"})
	out := filepath.Join(t.TempDir(), "o.pem")
	if _, err := d.DBExport(context.Background(), store+"/Oem.1", out); err == nil {
		t.Error("a metadata-only answer must not be written as a certificate")
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("nothing must be written")
	}
}

func TestDBExportLeavesNoTemporaryFile(t *testing.T) {
	_, d := newFake9(t, "")
	dir := t.TempDir()
	out := filepath.Join(dir, "out.der")
	_ = os.WriteFile(out, []byte("old"), 0o600)
	if _, err := d.DBExport(context.Background(), store+"/CustSecbootpolicy.7", out); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("directory holds %d entries, want only the exported file", len(entries))
	}
	if b, _ := os.ReadFile(out); string(b) == "old" {
		t.Error("the file was not replaced")
	}
}

// ---- other databases (ADR 0009)

func TestOtherDatabasesUseTheStandardPathEvenWithOEMMethod(t *testing.T) {
	s, d := newFake9(t, "oem")
	const dbs9 = sys + "/SecureBoot/SecureBootDatabases"
	s.JSON("GET", sys+"/SecureBoot", 200, map[string]any{"SecureBootDatabases": testbmc.Link(dbs9), "SecureBootEnable": false,
		"Oem": map[string]any{"Dell": map[string]any{"Certificates": testbmc.Link(sys + "/SecureBoot/Oem/Dell/Certificates")}}})
	s.JSON("GET", dbs9, 200, map[string]any{"Members": []any{testbmc.Link(dbs9 + "/KEK")}})
	s.JSON("GET", dbs9+"/KEK", 200, map[string]any{"Certificates": testbmc.Link(dbs9 + "/KEK/Certificates")})
	s.JSON("GET", dbs9+"/KEK/Certificates", 200, map[string]any{"Members": []any{testbmc.Link(dbs9 + "/KEK/Certificates/1")}})
	s.JSON("POST", dbs9+"/KEK/Certificates", 201, map[string]any{})
	d.WithDatabase("KEK")
	certs, err := d.DBList(context.Background())
	if err != nil || len(certs) != 1 {
		t.Fatalf("certs = %+v, err = %v", certs, err)
	}
	if _, err := d.DBImport(context.Background(), writeFile(t, "k.der", realCert(t))); err != nil {
		t.Fatal(err)
	}
	if s.Count("POST", dbs9+"/KEK/Certificates") != 1 || s.Count("POST", store+"/") != 0 {
		t.Error("the OEM multipart store only exists for db")
	}
}

func TestSignatureAndResetAreDelegatedToTheStandardDriver(t *testing.T) {
	_, d := newFake9(t, "")
	if _, err := d.AddSignature(context.Background(), "zz", ""); err == nil || errors.Is(err, platform.ErrUnsupported) {
		t.Errorf("AddSignature must reach the standard driver (and reject a bad hash), err = %v", err)
	}
}

func TestHasCertSeesACertificateInTheOEMStoreWithoutImporting(t *testing.T) {
	s, d := newFake9(t, "")
	der := realCert(t)
	s.Handle("GET", store+"/CustSecbootpolicy.2", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(der)
	})
	uri, ok := d.HasCert(context.Background(), der)
	if !ok || !strings.HasSuffix(uri, "CustSecbootpolicy.2") {
		t.Errorf("uri = %q, ok = %v", uri, ok)
	}
	if _, ok := d.HasCert(context.Background(), realCert(t)); ok {
		t.Error("a different certificate must not match")
	}
}

func TestOEMStoreIsReadInParallelButBounded(t *testing.T) {
	s, d := newFake9(t, "")
	var inFlight, peak atomic.Int32
	var members []any
	for i := 1; i <= 12; i++ {
		p := fmt.Sprintf("%s/CustSecbootpolicy.%d", store, i)
		members = append(members, testbmc.Link(p))
		s.Handle("GET", p, func(w http.ResponseWriter, _ *http.Request) {
			n := inFlight.Add(1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			inFlight.Add(-1)
			_, _ = w.Write([]byte("not a certificate"))
		})
	}
	s.JSON("GET", store, 200, map[string]any{"Certificates": members})
	d.HasCert(context.Background(), realCert(t))
	if p := peak.Load(); p < 2 || p > 4 {
		t.Errorf("peak concurrent downloads = %d, want between 2 and 4", p)
	}
}
