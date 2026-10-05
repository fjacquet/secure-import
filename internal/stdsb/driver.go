package stdsb

import (
	"context"
	"fmt"
	"net/http"
	"slices"

	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
)

var driverActions = []string{
	platform.ActionStatus, platform.ActionEnable, platform.ActionDisable,
	platform.ActionDBList, platform.ActionDBImport, platform.ActionDBDelete,
}

// Driver is the generic DMTF-standard driver (HPE iLO, Supermicro). Other
// drivers embed it and override what differs.
type Driver struct {
	platform.Unsupported
	H       Helper
	name    string
	maxCert int
}

var _ platform.Platform = (*Driver)(nil)

// NewDriver builds a driver; maxCertBytes > 0 caps the DER size of an imported certificate.
func NewDriver(name string, c *redfish.Client, maxCertBytes int) *Driver {
	return &Driver{H: Helper{C: c}, name: name, maxCert: maxCertBytes}
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

func (d *Driver) DBList(ctx context.Context) ([]platform.Cert, error) { return d.H.DBCerts(ctx, "db") }

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
	resp, err := d.H.ImportPEM(ctx, "db", pemBytes)
	if err != nil {
		return platform.Change{}, err
	}
	msgs := redfish.ParseMessages(resp.Body)
	if _, bad := redfish.FirstCritical(msgs); bad {
		return platform.Change{}, fmt.Errorf("certificate import refused. Messages: %s", redfish.Summarize(msgs))
	}
	return platform.Change{
		Message:        "Certificate import successful. Messages: " + redfish.Summarize(msgs),
		RebootRequired: redfish.NeedsReboot(msgs),
	}, nil
}

// DBDelete removes the certificate at uri.
func (d *Driver) DBDelete(ctx context.Context, uri string) (platform.Change, error) {
	if _, err := d.H.C.Do(ctx, http.MethodDelete, uri, nil, nil); err != nil {
		return platform.Change{}, err
	}
	return platform.Change{Message: "DB certificate deleted successfully"}, nil
}
