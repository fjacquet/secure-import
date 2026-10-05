package actions

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"sbmgr/internal/platform"
)

type fake struct {
	platform.Unsupported
	supported []string
	status    platform.Status
	statusErr error
	change    platform.Change
	err       error
	certs     []platform.Cert
	calls     []string
}

func (f *fake) Name() string           { return "fake" }
func (f *fake) Supports(a string) bool { return slices.Contains(f.supported, a) }
func (f *fake) Status(context.Context) (platform.Status, error) {
	f.calls = append(f.calls, "status")
	return f.status, f.statusErr
}
func (f *fake) SetSecureBoot(_ context.Context, en bool) (platform.Change, error) {
	f.calls = append(f.calls, fmt.Sprintf("enable=%v", en))
	return f.change, f.err
}
func (f *fake) SetPolicy(_ context.Context, p string) (platform.Change, error) {
	f.calls = append(f.calls, "policy="+p)
	return f.change, f.err
}
func (f *fake) DBList(context.Context) ([]platform.Cert, error) { return f.certs, f.err }
func (f *fake) DBImport(_ context.Context, file string) (platform.Change, error) {
	f.calls = append(f.calls, "import="+file)
	return f.change, f.err
}
func (f *fake) DBExport(_ context.Context, uri, file string) (platform.Change, error) {
	f.calls = append(f.calls, "export="+uri+">"+file)
	return f.change, f.err
}
func (f *fake) DBDelete(_ context.Context, uri string) (platform.Change, error) {
	f.calls = append(f.calls, "delete="+uri)
	return f.change, f.err
}

func newFake() *fake {
	return &fake{supported: platform.AllActions, status: platform.Status{
		Name: "SB", Mode: "DeployedMode", Policy: "Standard", CurrentBoot: "Disabled"}}
}

func TestUnsupportedActionMakesNoCall(t *testing.T) {
	f := newFake()
	f.supported = []string{platform.ActionStatus}
	r := Run(context.Background(), f, "10.0.0.1", platform.ActionDBImport, Params{})
	if r.Success || !strings.Contains(r.Error, "not supported on fake") || len(f.calls) != 0 {
		t.Errorf("r = %+v, calls = %v", r, f.calls)
	}
}

func TestStatusAction(t *testing.T) {
	f := newFake()
	r := Run(context.Background(), f, "10.0.0.1", platform.ActionStatus, Params{})
	if !r.Success || r.CurrentStatus != "Disabled" || r.NewStatus != "Disabled" || r.CurrentPolicy != "Standard" || r.NewPolicy != "Standard" || r.Name != "SB" {
		t.Errorf("r = %+v", r)
	}
	f = newFake()
	f.statusErr = errors.New("boom")
	if r := Run(context.Background(), f, "10.0.0.1", platform.ActionStatus, Params{}); r.Success || r.Error != "Failed to get status: boom" {
		t.Errorf("r = %+v", r)
	}
}

func TestEnableReportsPendingRebootAndSkipsWhenAlreadyEnabled(t *testing.T) {
	f := newFake()
	f.change = platform.Change{Message: "Success (Server restart required)", RebootRequired: true}
	r := Run(context.Background(), f, "10.0.0.1", platform.ActionEnable, Params{})
	if !r.Success || r.NewStatus != "Enabled (Pending - Reboot Required)" || r.ChangeMessage == "" || !slices.Contains(f.calls, "enable=true") {
		t.Errorf("r = %+v, calls = %v", r, f.calls)
	}
	f = newFake()
	f.status.Enabled = true
	r = Run(context.Background(), f, "10.0.0.1", platform.ActionEnable, Params{})
	if !r.Success || r.NewStatus != "Enabled" || slices.Contains(f.calls, "enable=true") {
		t.Errorf("already enabled: r = %+v, calls = %v", r, f.calls)
	}
	f = newFake()
	f.status.Enabled = true
	f.change = platform.Change{}
	r = Run(context.Background(), f, "10.0.0.1", platform.ActionDisable, Params{})
	if !r.Success || r.NewStatus != "Disabled" {
		t.Errorf("disable without reboot: r = %+v", r)
	}
}

func TestPolicyGuardRefusesNonDeployedMode(t *testing.T) {
	f := newFake()
	f.status.Enabled, f.status.Mode = true, "SetupMode"
	r := Run(context.Background(), f, "10.0.0.1", platform.ActionPolicyCustom, Params{})
	if r.Success || !strings.Contains(r.Error, "expected 'DeployedMode'") || slices.Contains(f.calls, "policy=Custom") {
		t.Errorf("r = %+v, calls = %v", r, f.calls)
	}
}

func TestPolicyIdempotencyConsidersPendingValue(t *testing.T) {
	ctx := context.Background()
	// applied == target, nothing pending: no write.
	f := newFake()
	f.status.Policy = "Custom"
	r := Run(ctx, f, "ip", platform.ActionPolicyCustom, Params{})
	if !r.Success || r.NewPolicy != "Custom" || slices.Contains(f.calls, "policy=Custom") {
		t.Errorf("applied==target: r = %+v, calls = %v", r, f.calls)
	}
	// applied == target but a different value is pending: must write to override it.
	f = newFake()
	f.status.Policy, f.status.PendingPolicy = "Custom", "Standard"
	f.change = platform.Change{Location: "/t/JID_1", JobID: "JID_1"}
	r = Run(ctx, f, "ip", platform.ActionPolicyCustom, Params{})
	if !r.Success || !slices.Contains(f.calls, "policy=Custom") {
		t.Errorf("stale pending: r = %+v, calls = %v", r, f.calls)
	}
	// target already pending: no write, reported as pending.
	f = newFake()
	f.status.PendingPolicy = "Custom"
	r = Run(ctx, f, "ip", platform.ActionPolicyCustom, Params{})
	if !r.Success || r.NewPolicy != "Custom (Pending - Reboot Required)" || slices.Contains(f.calls, "policy=Custom") {
		t.Errorf("already pending: r = %+v, calls = %v", r, f.calls)
	}
}

func TestPolicyChangeNeedsLocationAndJobID(t *testing.T) {
	f := newFake()
	f.change = platform.Change{Location: "/t/JID_9", JobID: "JID_9", Message: "ok"}
	r := Run(context.Background(), f, "ip", platform.ActionPolicyCustom, Params{})
	if !r.Success || r.NewPolicy != "Custom (Pending - Reboot Required)" {
		t.Errorf("r = %+v", r)
	}
	f = newFake()
	f.change = platform.Change{Message: "ok"}
	r = Run(context.Background(), f, "ip", platform.ActionPolicyCustom, Params{})
	if r.Success || !strings.Contains(r.Error, "missing Location or Job ID") || r.NewPolicy != "Unknown (Task Creation Failed)" {
		t.Errorf("r = %+v", r)
	}
	f = newFake()
	f.err = errors.New("SYS011")
	if r := Run(context.Background(), f, "ip", platform.ActionPolicyCustom, Params{}); r.Success || r.Error != "Failed to set policy: SYS011" {
		t.Errorf("r = %+v", r)
	}
}

func TestDBActions(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.certs = []platform.Cert{{URI: "/a"}, {URI: "/b"}}
	if r := Run(ctx, f, "ip", platform.ActionDBList, Params{}); !r.Success || r.CertCount != 2 || r.Message != "Found 2 DB certificates" {
		t.Errorf("list: %+v", r)
	}
	f = newFake()
	f.change = platform.Change{Message: "imported"}
	if r := Run(ctx, f, "ip", platform.ActionDBImport, Params{CertFile: "c.der"}); !r.Success || r.Message != "imported" || !slices.Contains(f.calls, "import=c.der") {
		t.Errorf("import: %+v calls=%v", r, f.calls)
	}
	// MSYS-mangled URIs are repaired before reaching the driver.
	f = newFake()
	Run(ctx, f, "ip", platform.ActionDBDelete, Params{CertURI: "C:/Program Files/Git/redfish/v1/x/Certificates/Cust.7"})
	Run(ctx, f, "ip", platform.ActionDBExport, Params{CertURI: "redfish/v1/x/Certificates/Cust.7", CertFile: "o.der"})
	if !slices.Contains(f.calls, "delete=/redfish/v1/x/Certificates/Cust.7") || !slices.Contains(f.calls, "export=/redfish/v1/x/Certificates/Cust.7>o_ip.der") {
		t.Errorf("calls = %v", f.calls)
	}
	f = newFake()
	f.err = errors.New("HTTP 500: x")
	if r := Run(ctx, f, "ip", platform.ActionDBList, Params{}); r.Success || r.Error != "Failed to get DB certificates: HTTP 500: x" {
		t.Errorf("list error: %+v", r)
	}
	if r := Run(ctx, f, "ip", platform.ActionDBDelete, Params{CertURI: "/redfish/v1/x/Certificates/u"}); r.Success || r.Error != "HTTP 500: x" {
		t.Errorf("delete error: %+v", r)
	}
}

func TestDBDeleteRefusesNonCertificateURI(t *testing.T) {
	f := newFake()
	r := Run(context.Background(), f, "ip", platform.ActionDBDelete, Params{CertURI: "/redfish/v1/AccountService/Accounts/2"})
	if r.Success || !strings.Contains(r.Error, "not a certificate URI") || len(f.calls) != 0 {
		t.Errorf("r = %+v, calls = %v", r, f.calls)
	}
}

func TestDBListMessageCarriesCertificateDetails(t *testing.T) {
	f := newFake()
	f.certs = []platform.Cert{{URI: "/a", Subject: "Vendor CA", NotAfter: "2035-01-01"}, {URI: "/b"}}
	r := Run(context.Background(), f, "ip", platform.ActionDBList, Params{})
	if !r.Success || !strings.Contains(r.Message, "Found 2 DB certificates") ||
		!strings.Contains(r.Message, "Vendor CA (expires 2035-01-01)") || !strings.Contains(r.Message, "/b") {
		t.Errorf("message = %q", r.Message)
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := Run(ctx, f, "ip", platform.ActionEnable, Params{DryRun: true})
	if !r.Success || !strings.Contains(r.ChangeMessage, "DRY RUN") {
		t.Errorf("enable: %+v", r)
	}
	r = Run(ctx, f, "ip", platform.ActionPolicyCustom, Params{DryRun: true})
	if !r.Success || !strings.Contains(r.ChangeMessage, "DRY RUN") {
		t.Errorf("policy: %+v", r)
	}
	f.certs = []platform.Cert{{URI: "/redfish/v1/x/Certificates/1"}}
	if r = Run(ctx, f, "ip", platform.ActionDBDelete, Params{CertURI: "/redfish/v1/x/Certificates/1", DryRun: true}); !r.Success || !strings.Contains(r.Message, "would delete") {
		t.Errorf("delete: %+v", r)
	}
	if r = Run(ctx, f, "ip", platform.ActionDBDelete, Params{CertURI: "/redfish/v1/x/Certificates/9", DryRun: true}); r.Success || !strings.Contains(r.Error, "not found") {
		t.Errorf("delete missing: %+v", r)
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(bad, []byte("junk"), 0o600)
	if r = Run(ctx, f, "ip", platform.ActionDBImport, Params{CertFile: bad, DryRun: true}); r.Success {
		t.Errorf("import of a bad file must fail even in a dry run: %+v", r)
	}
	for _, c := range f.calls {
		if c != "status" {
			t.Errorf("a dry run made the write call %q", c)
		}
	}
}

func (f *fake) ResetKeys(_ context.Context, t string) (platform.Change, error) {
	f.calls = append(f.calls, "reset="+t)
	return f.change, f.err
}

func TestResetKeysActionAndDryRun(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.change = platform.Change{Message: "done", RebootRequired: true}
	r := Run(ctx, f, "ip", platform.ActionResetKeys, Params{ResetType: "DeleteAllKeys", Confirm: true})
	if !r.Success || !slices.Contains(f.calls, "reset=DeleteAllKeys") || !strings.Contains(r.ChangeMessage, "done") {
		t.Errorf("r = %+v, calls = %v", r, f.calls)
	}
	f = newFake()
	r = Run(ctx, f, "ip", platform.ActionResetKeys, Params{ResetType: "DeleteAllKeys", DryRun: true})
	if !r.Success || !strings.Contains(r.ChangeMessage, "DRY RUN") || slices.Contains(f.calls, "reset=DeleteAllKeys") {
		t.Errorf("dry run: r = %+v, calls = %v", r, f.calls)
	}
}

func TestEnableHonoursAPendingOppositeChange(t *testing.T) {
	ctx := context.Background()
	yes, no := true, false
	// Enabled now, a disable is pending: "enable" must cancel it, not report "already enabled".
	f := newFake()
	f.status.Enabled, f.status.PendingEnabled = true, &no
	if r := Run(ctx, f, "ip", platform.ActionEnable, Params{}); !r.Success || !slices.Contains(f.calls, "enable=true") {
		t.Errorf("cancel pending: r = %+v, calls = %v", r, f.calls)
	}
	// Disabled now, enable already pending: nothing to send.
	f = newFake()
	f.status.PendingEnabled = &yes
	r := Run(ctx, f, "ip", platform.ActionEnable, Params{})
	if !r.Success || slices.Contains(f.calls, "enable=true") || !strings.Contains(r.ChangeMessage, "already pending") {
		t.Errorf("already pending: r = %+v, calls = %v", r, f.calls)
	}
}

// ---- other databases (ADR 0009)

func (f *fake) AddSignature(_ context.Context, sha, owner string) (platform.Change, error) {
	f.calls = append(f.calls, "signature="+sha+"/"+owner)
	return f.change, f.err
}

func TestWritesOnPKAndKEKNeedConfirmAndSetupOrAuditMode(t *testing.T) {
	ctx := context.Background()
	cert := filepath.Join(t.TempDir(), "k.pem")
	for _, db := range []string{"PK", "KEK"} {
		f := newFake()
		f.status.Mode = "SetupMode"
		if r := Run(ctx, f, "ip", platform.ActionDBImport, Params{Database: db, CertFile: cert}); r.Success || !strings.Contains(r.Error, "--confirm") {
			t.Errorf("%s without confirm: %+v", db, r)
		}
		f.status.Mode = "UserMode"
		if r := Run(ctx, f, "ip", platform.ActionDBImport, Params{Database: db, CertFile: cert, Confirm: true}); r.Success || !strings.Contains(r.Error, "SetupMode or AuditMode") {
			t.Errorf("%s in UserMode: %+v", db, r)
		}
		for _, c := range f.calls {
			if strings.HasPrefix(c, "import=") {
				t.Errorf("%s: a refused write reached the driver: %v", db, f.calls)
			}
		}
		f.status.Mode = "AuditMode"
		if r := Run(ctx, f, "ip", platform.ActionDBImport, Params{Database: db, CertFile: cert, Confirm: true}); !r.Success {
			t.Errorf("%s in AuditMode: %+v", db, r)
		}
	}
	// db is not guarded
	f := newFake()
	f.status.Mode = "UserMode"
	if r := Run(ctx, f, "ip", platform.ActionDBImport, Params{CertFile: cert}); !r.Success {
		t.Errorf("db import must stay unguarded: %+v", r)
	}
}

func TestDeleteInsidePKOrKEKIsGuardedWhateverTheFlag(t *testing.T) {
	f := newFake()
	f.status.Mode = "UserMode"
	r := Run(context.Background(), f, "ip", platform.ActionDBDelete, Params{CertURI: "/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/PK/Certificates/1", Confirm: true})
	if r.Success || !strings.Contains(r.Error, "SetupMode or AuditMode") || slices.Contains(f.calls, "delete=/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/PK/Certificates/1") {
		t.Errorf("r = %+v, calls = %v", r, f.calls)
	}
}

func TestDBXSignatureImportNeedsConfirm(t *testing.T) {
	ctx := context.Background()
	const sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	f := newFake()
	if r := Run(ctx, f, "ip", platform.ActionDBImport, Params{Database: "dbx", Signature: sha}); r.Success || !strings.Contains(r.Error, "--confirm") {
		t.Errorf("without confirm: %+v", r)
	}
	if r := Run(ctx, f, "ip", platform.ActionDBImport, Params{Database: "dbx", Signature: sha, SignatureOwner: "g", Confirm: true}); !r.Success || !slices.Contains(f.calls, "signature="+sha+"/g") {
		t.Errorf("with confirm: %+v, calls = %v", r, f.calls)
	}
	f = newFake()
	if r := Run(ctx, f, "ip", platform.ActionDBImport, Params{Database: "dbx", Signature: sha, Confirm: true, DryRun: true}); !r.Success || !strings.Contains(r.Message, "DRY RUN") || len(f.calls) != 0 {
		t.Errorf("dry run: %+v, calls = %v", r, f.calls)
	}
}

// ---- second review

func TestGuardedURIsAreRecognisedWhateverTheSpelling(t *testing.T) {
	for _, uri := range []string{
		"/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/%4BEK/Certificates/1",
		"/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/%6bek/Certificates/1",
		"/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/%254BEK/Certificates/1",
		"/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/kek;x=1/Certificates/1",
		"/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/KEK%20/Certificates/1",
		"/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/./KEK/Certificates/1",
		"/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases//KEK/Certificates/1",
		"/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/x/../KEK/Certificates/1",
		"/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/PK/Certificates/1?a=b",
	} {
		f := newFake()
		f.status.Mode = "UserMode"
		r := Run(context.Background(), f, "ip", platform.ActionDBDelete, Params{CertURI: uri})
		if r.Success || !strings.Contains(r.Error, "requires --confirm") {
			t.Errorf("%s: r = %+v", uri, r)
		}
		for _, c := range f.calls {
			if strings.HasPrefix(c, "delete=") {
				t.Errorf("%s: the guard was bypassed, calls = %v", uri, f.calls)
			}
		}
	}
}

func TestTheGuardedURIIsTheOneThatIsSent(t *testing.T) {
	f := newFake()
	f.status.Mode = "SetupMode"
	Run(context.Background(), f, "ip", platform.ActionDBDelete, Params{Confirm: true,
		CertURI: "/redfish/v1/x/SecureBootDatabases/%4BEK/Certificates/1"})
	if !slices.Contains(f.calls, "delete=/redfish/v1/x/SecureBootDatabases/KEK/Certificates/1") {
		t.Errorf("what is guarded and what is sent must be the same normalised URI: %v", f.calls)
	}
}

// Resets follow ADR 0006: --confirm is the safeguard, on every spelling. Requiring Setup or
// Audit mode would forbid the very operation that leads there (DeletePK, DeleteAllKeys).
func TestResetsNeedConfirmButNotSetupModeWhicheverSpelling(t *testing.T) {
	ctx := context.Background()
	for _, p := range []Params{
		{ResetType: "DeleteAllKeys"}, {ResetType: "DeletePK"},
		{Database: "KEK", ResetType: "DeleteAllKeys"}, {Database: "PK", ResetType: "DeleteAllKeys"},
	} {
		f := newFake()
		f.status.Mode = "UserMode"
		if r := Run(ctx, f, "ip", platform.ActionResetKeys, p); r.Success || !strings.Contains(r.Error, "requires --confirm") {
			t.Errorf("%+v without confirm: %+v", p, r)
		}
		p.Confirm = true
		f = newFake()
		f.status.Mode = "UserMode"
		if r := Run(ctx, f, "ip", platform.ActionResetKeys, p); !r.Success || !slices.Contains(f.calls, "reset="+p.ResetType) {
			t.Errorf("%+v with confirm in UserMode: %+v, calls = %v", p, r, f.calls)
		}
	}
}

// ---- deferred minors

// holder is a platform that can answer "is this certificate already enrolled?" itself
// (the Dell OEM store cannot be judged from DBList).
type holder struct {
	*fake
	uri string
}

func (h holder) HasCert(context.Context, []byte) (string, bool) { return h.uri, h.uri != "" }

func TestDryRunImportAsksThePlatformWhetherTheCertificateIsPresent(t *testing.T) {
	// a real PEM so the file validation passes
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	file := filepath.Join(t.TempDir(), "c.der")
	_ = os.WriteFile(file, der, 0o600)
	h := holder{fake: newFake(), uri: "/redfish/v1/x/Certificates/CustSecbootpolicy.3"}
	r := Run(context.Background(), h, "ip", platform.ActionDBImport, Params{CertFile: file, DryRun: true})
	if !r.Success || !strings.Contains(r.Message, "already present") || !strings.Contains(r.Message, "CustSecbootpolicy.3") {
		t.Errorf("r = %+v", r)
	}
}

func TestDryRunDeleteOfAnotherDatabaseSaysItWasNotVerified(t *testing.T) {
	f := newFake() // bound to db: its DBList cannot contain a KEK member
	f.status.Mode = "SetupMode"
	r := Run(context.Background(), f, "ip", platform.ActionDBDelete, Params{DryRun: true, Confirm: true,
		CertURI: "/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/KEK/Certificates/2"})
	if !r.Success || !strings.Contains(r.Message, "not verified") || !strings.Contains(r.Message, "--database KEK") {
		t.Errorf("a KEK member must not be reported as 'not found' from the db listing: %+v", r)
	}
}

func TestDBXSignatureMembersCanBeDeleted(t *testing.T) {
	f := newFake()
	uri := "/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/dbx/Signatures/4"
	if r := Run(context.Background(), f, "ip", platform.ActionDBDelete, Params{CertURI: uri, Confirm: true}); !r.Success || !slices.Contains(f.calls, "delete="+uri) {
		t.Errorf("r = %+v, calls = %v", r, f.calls)
	}
	if r := Run(context.Background(), newFake(), "ip", platform.ActionDBDelete, Params{CertURI: uri}); r.Success || !strings.Contains(r.Error, "--confirm") {
		t.Errorf("a dbx delete still needs --confirm: %+v", r)
	}
	if r := Run(context.Background(), newFake(), "ip", platform.ActionDBDelete, Params{CertURI: "/redfish/v1/AccountService/Accounts/2", Confirm: true}); r.Success {
		t.Error("only certificate or signature URIs can be deleted")
	}
}
