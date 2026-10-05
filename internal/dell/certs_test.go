package dell

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	ch, err := d.DBImport(context.Background(), writeFile(t, "dell_2025.der", []byte("DER")))
	if err != nil || !strings.Contains(ch.Message, "Certificate import successful") {
		t.Fatalf("ch = %+v, err = %v", ch, err)
	}
	if v := <-got; v[0] != "dell_2025.der" || v[1] != "DER" {
		t.Errorf("uploaded %v", v)
	}
}

// Changelog bug 4: a 2xx import is a success even when the MessageIds are not
// the ones an older firmware used.
func TestDBImportAcceptsNewerMessageIdsAndReportsReboot(t *testing.T) {
	s, d := newFake9(t, "")
	s.JSON("POST", store+"/", 200, info("IDRAC.2.9.SYS430", "Restart the server."))
	ch, err := d.DBImport(context.Background(), writeFile(t, "c.der", []byte("DER")))
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
