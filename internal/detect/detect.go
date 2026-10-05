// Package detect identifies a BMC's platform from Redfish and builds its driver.
package detect

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"sbmgr/internal/dell"
	"sbmgr/internal/lenovo"
	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
	"sbmgr/internal/stdsb"
)

// New returns the driver for forced (idrac9, idrac10, ilo, lenovo, supermicro),
// or detects it when forced is "" or "auto". method only affects Dell drivers.
func New(ctx context.Context, c *redfish.Client, forced, method string) (platform.Platform, error) {
	name := strings.ToLower(forced)
	if name == "" || name == "auto" {
		var err error
		if name, err = identify(ctx, c); err != nil {
			return nil, err
		}
	}
	switch name {
	case "idrac9", "idrac10":
		return dell.New(c, name, method), nil
	case "ilo":
		return stdsb.NewDriver("ilo", c, 3072), nil // iLO: 3 KiB per certificate
	case "supermicro":
		return stdsb.NewDriver("supermicro", c, 0), nil
	case "lenovo":
		return lenovo.New(c), nil
	}
	return nil, fmt.Errorf("unknown platform %q", forced)
}

// identify reads Vendor from the service root and, for Dell, the BMC firmware
// major version (1.x is iDRAC10; 3.x to 7.x is iDRAC9).
func identify(ctx context.Context, c *redfish.Client) (string, error) {
	root, err := c.Root(ctx)
	if err != nil {
		return "", err
	}
	v := strings.ToLower(root.Vendor)
	switch {
	case strings.Contains(v, "dell"):
		m, err := c.Manager(ctx)
		if err != nil {
			return "", err
		}
		major, err := strconv.Atoi(strings.SplitN(m.FirmwareVersion, ".", 2)[0])
		if err != nil {
			return "", fmt.Errorf("cannot detect platform: unreadable iDRAC firmware version %q (use --platform)", m.FirmwareVersion)
		}
		switch {
		case major == 1:
			return "idrac10", nil
		case major >= 3 && major <= 7:
			return "idrac9", nil
		}
		return "", fmt.Errorf("cannot detect platform: unsupported iDRAC firmware %q (use --platform)", m.FirmwareVersion)
	case strings.Contains(v, "hpe"), strings.Contains(v, "hewlett"):
		return "ilo", nil
	case strings.Contains(v, "lenovo"):
		return "lenovo", nil
	case strings.Contains(v, "supermicro"), strings.Contains(v, "super micro"):
		return "supermicro", nil
	}
	return "", fmt.Errorf("cannot detect platform: unknown vendor %q (use --platform)", root.Vendor)
}
