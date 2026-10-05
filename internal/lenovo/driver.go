// Package lenovo implements the Lenovo XClarity Controller (XCC) driver. It is
// the generic standard driver with XCC's own verdict rule: PATCH SecureBoot
// answers HTTP 200 whether it worked or not, and the result is in ExtendedInfo.
package lenovo

import (
	"context"
	"fmt"
	"strings"

	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
	"sbmgr/internal/stdsb"
)

// Driver embeds the generic driver and overrides what XCC does differently.
type Driver struct{ *stdsb.Driver }

var _ platform.Platform = (*Driver)(nil)

// New builds a Lenovo driver.
func New(c *redfish.Client) *Driver { return &Driver{stdsb.NewDriver("lenovo", c, 0)} }

// SetSecureBoot PATCHes SecureBootEnable and reads the verdict from ExtendedInfo:
// RebootRequired means accepted (effective on next boot); PhysicalPresenceError
// means refused (Remote Physical Presence not asserted); anything else is unknown.
func (d *Driver) SetSecureBoot(ctx context.Context, enable bool) (platform.Change, error) {
	resp, err := d.H.SetEnable(ctx, enable)
	if err != nil {
		return platform.Change{}, err
	}
	return verdict(redfish.ParseMessages(resp.Body))
}

// ResetKeys runs the key reset and reads the verdict like SetSecureBoot.
func (d *Driver) ResetKeys(ctx context.Context, resetType string) (platform.Change, error) {
	resp, err := d.ResetKeysResponse(ctx, resetType)
	if err != nil {
		return platform.Change{}, err
	}
	return verdict(redfish.ParseMessages(resp.Body))
}

// verdict applies the XCC rule: HTTP 200 whatever happened, the result is in the messages.
func verdict(msgs []redfish.Message) (platform.Change, error) {
	for _, m := range msgs {
		if strings.Contains(strings.ToLower(m.ID), "physicalpresenceerror") {
			return platform.Change{}, fmt.Errorf("physical presence not asserted: %s", m.Text)
		}
	}
	for _, m := range msgs {
		if strings.Contains(strings.ToLower(m.ID), "rebootrequired") {
			return platform.Change{
				Message:        "Success (reboot required). Messages: " + redfish.Summarize(msgs),
				RebootRequired: true,
			}, nil
		}
	}
	return platform.Change{}, fmt.Errorf("unknown response. Messages: %s", redfish.Summarize(msgs))
}

// DBImport enrols a certificate. XCC refuses it with FQXSFPU4097G unless the
// Secure Boot policy is "Custom Policy"; the hint says how to fix that.
func (d *Driver) DBImport(ctx context.Context, file string) (platform.Change, error) {
	ch, err := d.Driver.DBImport(ctx, file)
	if err != nil && strings.Contains(err.Error(), "FQXSFPU4097G") {
		return ch, fmt.Errorf("%w (set the Secure Boot policy to \"Custom Policy\" in UEFI setup or with OneCLI, then retry)", err)
	}
	return ch, err
}
