package stdsb

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
)

// iloMaxCerts is the number of certificates an iLO database accepts (HPE documentation).
const iloMaxCerts = 16

var driverActions = []string{
	platform.ActionStatus, platform.ActionEnable, platform.ActionDisable,
	platform.ActionDBList, platform.ActionDBImport, platform.ActionDBDelete,
	platform.ActionResetKeys,
}

// Driver is the generic DMTF-standard driver (HPE iLO, Supermicro). Other
// drivers embed it and override what differs.
type Driver struct {
	platform.Unsupported
	H        Helper
	name     string
	maxCert  int
	db       string // database for db_list/db_import (default "db")
	explicit bool   // a database was chosen: reset_keys then targets it, not the whole SecureBoot
}

var _ platform.Platform = (*Driver)(nil)

// NewDriver builds a driver; maxCertBytes > 0 caps the DER size of an imported certificate.
func NewDriver(name string, c *redfish.Client, maxCertBytes int) *Driver {
	return &Driver{H: Helper{C: c, Vendor: name}, name: name, maxCert: maxCertBytes, db: "db"}
}

// WithDatabase binds the driver to one Secure Boot database ("db", "KEK", "PK", "dbx").
func (d *Driver) WithDatabase(id string) *Driver {
	d.db, d.explicit = id, true
	return d
}

func (d *Driver) Name() string { return d.name }

func (d *Driver) Supports(action string) bool { return slices.Contains(driverActions, action) }

func (d *Driver) Status(ctx context.Context) (platform.Status, error) { return d.H.Status(ctx) }

// SetSecureBoot PATCHes SecureBootEnable. The DMTF schema states the change
// "takes effect on next boot", so a reboot is always reported as required.
func (d *Driver) SetSecureBoot(ctx context.Context, enable bool) (platform.Change, error) {
	resp, err := d.H.SetEnable(ctx, enable)
	if err != nil {
		return platform.Change{}, err
	}
	msgs := redfish.ParseMessages(resp.Body)
	if _, bad := redfish.FirstCritical(msgs); bad {
		return platform.Change{}, fmt.Errorf("secure boot change refused. Messages: %s", redfish.Summarize(msgs))
	}
	return platform.Change{
		Message:        "Success. Messages: " + redfish.Summarize(msgs),
		RebootRequired: true,
	}, nil
}

func (d *Driver) DBList(ctx context.Context) ([]platform.Cert, error) { return d.H.DBCerts(ctx, d.db) }

// DBImport enrols a PEM or DER certificate file into the "db" database.
func (d *Driver) DBImport(ctx context.Context, file string) (platform.Change, error) {
	data, err := ReadCertFile(file)
	if err != nil {
		return platform.Change{}, err
	}
	pemBytes, err := ToPEM(data)
	if err != nil {
		return platform.Change{}, err
	}
	if n := DERLen(pemBytes); d.maxCert > 0 && n > d.maxCert {
		return platform.Change{}, fmt.Errorf("certificate is %d bytes, device limit is %d", n, d.maxCert)
	}
	if listed, err := d.H.DBCerts(ctx, d.db); err == nil {
		if uri, ok := AlreadyPresent(listed, data); ok {
			return platform.Change{Message: "Certificate already present (" + uri + "), nothing imported"}, nil
		}
		if d.name == "ilo" && len(listed) >= iloMaxCerts {
			return platform.Change{}, fmt.Errorf("the db database already holds %d certificates, the iLO limit", len(listed))
		}
	}
	resp, err := d.H.ImportPEM(ctx, d.db, pemBytes)
	if err != nil {
		return platform.Change{}, err
	}
	msgs := redfish.ParseMessages(resp.Body)
	if _, bad := redfish.FirstCritical(msgs); bad {
		return platform.Change{}, fmt.Errorf("certificate import refused. Messages: %s", redfish.Summarize(msgs))
	}
	note := ""
	if d.name == "supermicro" && resp.Status != http.StatusCreated {
		note = fmt.Sprintf(" (HTTP %d, the Supermicro guide documents 201)", resp.Status)
	}
	return platform.Change{
		Message:        "Certificate import successful" + note + ". Messages: " + redfish.Summarize(msgs),
		RebootRequired: redfish.NeedsReboot(msgs),
	}, nil
}

// DBDelete removes the certificate at uri.
func (d *Driver) DBDelete(ctx context.Context, uri string) (platform.Change, error) {
	resp, err := d.H.C.Do(ctx, http.MethodDelete, uri, nil, nil)
	if err != nil {
		return platform.Change{}, err
	}
	if msgs := redfish.ParseMessages(resp.Body); len(msgs) > 0 {
		if _, bad := redfish.FirstCritical(msgs); bad {
			return platform.Change{}, fmt.Errorf("certificate deletion refused. Messages: %s", redfish.Summarize(msgs))
		}
	}
	return platform.Change{Message: "DB certificate deleted successfully"}, nil
}

// ResetKeys asks the BMC to reset or delete the Secure Boot keys.
func (d *Driver) ResetKeys(ctx context.Context, resetType string) (platform.Change, error) {
	resp, err := d.ResetKeysResponse(ctx, resetType)
	if err != nil {
		return platform.Change{}, err
	}
	msgs := redfish.ParseMessages(resp.Body)
	if _, bad := redfish.FirstCritical(msgs); bad {
		return platform.Change{}, fmt.Errorf("key reset refused. Messages: %s", redfish.Summarize(msgs))
	}
	verification := ""
	if location := resp.Header.Get("Location"); resp.Status == http.StatusAccepted && location != "" && !d.H.C.NoWait() {
		tr, err := d.H.C.WaitTask(ctx, location)
		switch {
		case err != nil:
			return platform.Change{}, fmt.Errorf("key reset requested but not verified: %w", err)
		case tr.Outcome == redfish.OutcomeFailed:
			return platform.Change{}, fmt.Errorf("key reset task failed. %s", tr.Detail)
		default:
			verification = " (Verification: " + tr.Detail + ")"
		}
	}
	return platform.Change{
		Message:        "Key reset (" + resetType + ") requested" + verification + ". Messages: " + redfish.Summarize(msgs),
		RebootRequired: redfish.NeedsReboot(msgs),
	}, nil
}

// AddSignature adds a SHA-256 signature to the dbx revocation list. owner is an
// optional signature-owner GUID.
func (d *Driver) AddSignature(ctx context.Context, sha256hex, owner string) (platform.Change, error) {
	if !sha256Hex.MatchString(sha256hex) {
		return platform.Change{}, fmt.Errorf("a SHA-256 signature is 64 hexadecimal characters, got %q", sha256hex)
	}
	resp, err := d.H.ImportSignature(ctx, "dbx", strings.ToLower(sha256hex), owner)
	if err != nil {
		return platform.Change{}, err
	}
	msgs := redfish.ParseMessages(resp.Body)
	if _, bad := redfish.FirstCritical(msgs); bad {
		return platform.Change{}, fmt.Errorf("signature import refused. Messages: %s", redfish.Summarize(msgs))
	}
	return platform.Change{
		Message:        "Signature added to dbx. Messages: " + redfish.Summarize(msgs),
		RebootRequired: redfish.NeedsReboot(msgs),
	}, nil
}

var sha256Hex = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// ResetKeysResponse sends the reset: the chosen database's own action when a database was
// chosen with WithDatabase, else the whole-SecureBoot action. Drivers that read the verdict
// differently (Lenovo) call this so they can never widen a per-database reset.
func (d *Driver) ResetKeysResponse(ctx context.Context, resetType string) (*redfish.Response, error) {
	if d.explicit {
		return d.H.DBResetKeys(ctx, d.db, resetType)
	}
	return d.H.ResetKeys(ctx, resetType)
}

// HasCert reports whether the certificate(s) in data are already in the chosen database,
// and where, without importing anything.
func (d *Driver) HasCert(ctx context.Context, data []byte) (string, bool) {
	listed, err := d.H.DBCerts(ctx, d.db)
	if err != nil {
		return "", false
	}
	return AlreadyPresent(listed, data)
}
