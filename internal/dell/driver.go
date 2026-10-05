// Package dell implements the iDRAC9 and iDRAC10 drivers. Dell-specific
// resources (OEM certificate store, SecureBootPolicy BIOS attribute) live here.
package dell

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
	"sbmgr/internal/stdsb"
)

// Driver drives one iDRAC. method selects how certificates are imported:
// "oem" (multipart on the Dell store) or "standard" (DMTF POST).
type Driver struct {
	platform.Unsupported
	c      *redfish.Client
	name   string
	method string
	h      stdsb.Helper
	std    *stdsb.Driver
}

var _ platform.Platform = (*Driver)(nil)

// New builds a driver. An empty method defaults to "oem" on idrac9 and
// "standard" on idrac10 (ADR 0005).
func New(c *redfish.Client, name, method string) *Driver {
	if method == "" {
		method = "oem"
		if name == "idrac10" {
			method = "standard"
		}
	}
	return &Driver{c: c, name: name, method: method, h: stdsb.Helper{C: c}, std: stdsb.NewDriver(name, c, 0)}
}

func (d *Driver) Name() string { return d.name }

func (d *Driver) Supports(action string) bool {
	return slices.Contains(platform.AllActions, action)
}

type biosDoc struct {
	Attributes struct {
		SecureBootPolicy string `json:"SecureBootPolicy"`
		SecureBoot       string `json:"SecureBoot"`
	} `json:"Attributes"`
	Settings struct {
		SettingsObject redfish.Link `json:"SettingsObject"`
	} `json:"@Redfish.Settings"`
}

const policyQuery = "?$select=Attributes/SecureBootPolicy,Attributes/SecureBoot"

// bios reads the applied SecureBootPolicy and returns the Bios/Settings URI
// (from @Redfish.Settings, else <bios>/Settings as a last resort).
func (d *Driver) bios(ctx context.Context) (doc biosDoc, settingsPath string, err error) {
	sys, err := d.c.SystemPath(ctx)
	if err != nil {
		return doc, "", err
	}
	var sd struct {
		Bios redfish.Link `json:"Bios"`
	}
	if err := d.c.GetJSON(ctx, sys, &sd); err != nil {
		return doc, "", fmt.Errorf("system: %w", err)
	}
	bp := sd.Bios.ODataID
	if bp == "" {
		bp = sys + "/Bios"
	}
	if err := d.c.GetJSON(ctx, bp+policyQuery, &doc); err != nil {
		return doc, "", err
	}
	settingsPath = doc.Settings.SettingsObject.ODataID
	if settingsPath == "" {
		settingsPath = bp + "/Settings"
	}
	return doc, settingsPath, nil
}

// Status returns the Secure Boot state with the applied policy and any
// different policy pending in Bios/Settings. An unreadable BIOS is not fatal:
// the policy is reported as "Unknown".
func (d *Driver) Status(ctx context.Context) (platform.Status, error) {
	st, err := d.h.Status(ctx)
	if err != nil {
		return platform.Status{}, err
	}
	st.Policy = "Unknown"
	doc, settings, err := d.bios(ctx)
	if err != nil {
		slog.Debug("could not read SecureBootPolicy", "err", err)
		return st, nil
	}
	if doc.Attributes.SecureBootPolicy != "" {
		st.Policy = doc.Attributes.SecureBootPolicy
	}
	var pending biosDoc
	if err := d.c.GetJSON(ctx, settings+policyQuery, &pending); err == nil {
		st.PendingPolicy = pending.Attributes.SecureBootPolicy
		switch pending.Attributes.SecureBoot {
		case "Enabled":
			v := true
			st.PendingEnabled = &v
		case "Disabled":
			v := false
			st.PendingEnabled = &v
		}
	}
	return st, nil
}

// SetSecureBoot PATCHes SecureBootEnable. Messages with a success MessageId (or
// no message at all) mean success; any other messages are an unknown response.
// The change stays pending until the next reboot.
func (d *Driver) SetSecureBoot(ctx context.Context, enable bool) (platform.Change, error) {
	resp, err := d.h.SetEnable(ctx, enable)
	if err != nil {
		return platform.Change{}, err
	}
	msgs := redfish.ParseMessages(resp.Body)
	if _, bad := redfish.FirstCritical(msgs); bad {
		return platform.Change{}, fmt.Errorf("secure boot change refused. Messages: %s", redfish.Summarize(msgs))
	}
	ok := len(msgs) == 0
	for _, m := range msgs {
		if redfish.IsSuccess(m) {
			ok = true
		}
	}
	if !ok {
		return platform.Change{}, fmt.Errorf("unknown response. Messages: %s", redfish.Summarize(msgs))
	}
	// SecureBootEnable only takes effect on the next boot, whatever the messages say.
	reboot := true
	restart := " (Server restart required)"
	return platform.Change{
		Message:        fmt.Sprintf("Success%s. Messages: %s", restart, redfish.Summarize(msgs)),
		RebootRequired: reboot,
	}, nil
}

// SetPolicy stages SecureBootPolicy ("Custom" or "Standard") in Bios/Settings,
// applied on the next reset, and verifies the resulting task unless --no-wait.
func (d *Driver) SetPolicy(ctx context.Context, policy string) (platform.Change, error) {
	_, settings, err := d.bios(ctx)
	if err != nil {
		return platform.Change{}, err
	}
	payload := map[string]any{
		"Attributes":                 map[string]string{"SecureBootPolicy": policy},
		"@Redfish.SettingsApplyTime": map[string]string{"ApplyTime": "OnReset"},
	}
	resp, err := d.c.Patch(ctx, settings, payload)
	if err != nil {
		return platform.Change{}, err
	}
	location := resp.Header.Get("Location")
	msgs := redfish.ParseMessages(resp.Body)
	if _, bad := redfish.FirstCritical(msgs); bad {
		return platform.Change{}, fmt.Errorf("policy change refused. Messages: %s", redfish.Summarize(msgs))
	}
	ch := platform.Change{Location: location, JobID: jobID(location), RebootRequired: redfish.NeedsReboot(msgs)}
	verification := ""
	if location != "" && !d.c.NoWait() {
		tr, err := d.c.WaitTask(ctx, location)
		switch {
		case err != nil:
			return platform.Change{}, fmt.Errorf("policy change staged but not verified: %w", err)
		case tr.Outcome == redfish.OutcomeFailed:
			return platform.Change{}, fmt.Errorf("policy change task failed. %s", tr.Detail)
		default:
			verification = " (Verification: " + tr.Detail + ")"
		}
	}
	restart, loc, job := "", "", ""
	if ch.RebootRequired {
		restart = " (Server restart required)"
	}
	if location != "" {
		loc = " (Location: " + location + ")"
	}
	if ch.JobID != "" {
		job = " (Job ID: " + ch.JobID + ")"
	}
	ch.Message = fmt.Sprintf("Policy change successful%s%s%s%s. Messages: %s", restart, loc, job, verification, redfish.Summarize(msgs))
	return ch, nil
}

// jobID extracts "JID_<n>" from a task Location, else its last path segment.
func jobID(loc string) string {
	if loc == "" {
		return ""
	}
	if i := strings.LastIndex(loc, "JID_"); i >= 0 {
		return loc[i:]
	}
	return loc[strings.LastIndex(loc, "/")+1:]
}

// ResetKeys delegates to the standard SecureBoot.ResetKeys action.
func (d *Driver) ResetKeys(ctx context.Context, resetType string) (platform.Change, error) {
	return d.std.ResetKeys(ctx, resetType)
}
