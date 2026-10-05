package probe

import (
	"context"
	"strings"
	"testing"

	"sbmgr/internal/detect"
	"sbmgr/internal/platform"
	"sbmgr/internal/report"
	"sbmgr/internal/stdsb"
	"sbmgr/internal/testbmc"
)

// These tests run the real code against a captured HPE iLO tree (ProLiant DL360 Gen12,
// from HPE's emulator). The mockup is read-only (writes answer 405), so a passing test
// also proves that reads never write.

func iloClient(t *testing.T) (*testbmc.Server, platform.Platform, context.Context) {
	t.Helper()
	s := testbmc.NewMockup(t, testbmc.ILOGen12())
	c := client(t, s)
	ctx := context.Background()
	d, err := detect.New(ctx, c, "auto", "")
	if err != nil {
		t.Fatal(err)
	}
	return s, d, ctx
}

func TestRealILOIsDetectedFromItsVendor(t *testing.T) {
	_, d, _ := iloClient(t)
	if d.Name() != "ilo" {
		t.Errorf("detected %q from Vendor %q, want ilo", d.Name(), "HPE")
	}
}

func TestRealILOStatusAndDatabaseListing(t *testing.T) {
	_, d, ctx := iloClient(t)
	st, err := d.Status(ctx)
	if err != nil || st.Enabled || st.Mode != "UserMode" || st.CurrentBoot != "Disabled" {
		t.Fatalf("status = %+v, err = %v", st, err)
	}
	certs, err := d.DBList(ctx)
	if err != nil || len(certs) != 8 {
		t.Fatalf("db certificates = %d, err = %v (the capture holds 8)", len(certs), err)
	}
	if certs[0].Subject == "" || certs[0].NotAfter == "" || certs[0].PEM == "" {
		t.Errorf("the optional certificate fields were not read from a real iLO answer: %+v", certs[0])
	}
}

func TestRealILOProbeFindsEveryDatabaseAndTheResetAction(t *testing.T) {
	s, _, ctx := iloClient(t)
	rep := Run(ctx, client(t, s), "auto", "", false)
	if rep.Platform != "ilo" || !rep.OK() {
		for _, c := range rep.Checks {
			t.Logf("%-24s %-6s %s", c.Name, c.Status, c.Detail)
		}
		t.Fatalf("platform = %q, ok = %v", rep.Platform, rep.OK())
	}
	for name, frag := range map[string]string{
		"SecureBoot databases": "PK", "db certificates": "8 certificates", "ResetKeys action": "allowed",
	} {
		if c, ok := find(rep.Checks, name); !ok || c.Status != report.CheckOK || !strings.Contains(c.Detail, frag) {
			t.Errorf("%s = %+v (found %v), want %q", name, c, ok, frag)
		}
	}
	for _, r := range s.Requests() {
		if r.Method != "GET" {
			t.Errorf("probe sent %s %s to a read-only mockup", r.Method, r.Path)
		}
	}
}

// A certificate the iLO already holds is recognised from the PEM the iLO itself returned
// (with its CRLF line endings), so no write is attempted.
func TestRealILOCertificateAlreadyPresentIsNotImportedAgain(t *testing.T) {
	_, d, ctx := iloClient(t)
	certs, err := d.DBList(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if uri, ok := stdsb.AlreadyPresent(certs, []byte(certs[0].PEM)); !ok || uri == "" {
		t.Errorf("the first certificate of the capture must be found among the listed ones (uri %q)", uri)
	}
}
