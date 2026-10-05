// Package platform defines the vendor-neutral driver contract.
package platform

import (
	"context"
	"errors"
	"strings"
)

// Action names, as given to -a.
const (
	ActionStatus         = "status"
	ActionEnable         = "enable"
	ActionDisable        = "disable"
	ActionPolicyCustom   = "set_policy_custom"
	ActionPolicyStandard = "set_policy_standard"
	ActionDBList         = "db_list"
	ActionDBImport       = "db_import"
	ActionDBExport       = "db_export"
	ActionDBDelete       = "db_delete"
	ActionResetKeys      = "reset_keys"
)

// AllActions lists every action the CLI accepts.
var AllActions = []string{
	ActionStatus, ActionEnable, ActionDisable, ActionPolicyCustom, ActionPolicyStandard,
	ActionDBList, ActionDBImport, ActionDBExport, ActionDBDelete, ActionResetKeys,
}

// IsDBAction reports whether the action targets the certificate store.
func IsDBAction(a string) bool { return strings.HasPrefix(a, "db_") }

// ErrUnsupported is returned by a driver for an action it does not implement.
var ErrUnsupported = errors.New("action not supported")

// Status is the Secure Boot state of one BMC.
type Status struct {
	Name, Description string
	Enabled           bool
	CurrentBoot, Mode string
	// Policy is the applied SecureBootPolicy ("N/A" where the platform has none);
	// PendingPolicy is a different value staged for the next reboot, or "".
	Policy, PendingPolicy string
	// PendingEnabled is a SecureBootEnable value staged for the next boot, when the
	// platform can read it; nil when unknown or nothing is pending.
	PendingEnabled  *bool
	CertificatesURI string
}

// Change describes an accepted modification.
type Change struct {
	Message         string
	RebootRequired  bool
	Location, JobID string
}

// Cert identifies one certificate in a store.
// Cert identifies one certificate in a store. Every field except URI is optional:
// BMCs populate them unevenly.
type Cert struct {
	URI                    string
	Subject, Issuer        string // common names
	NotAfter               string // date, YYYY-MM-DD
	Fingerprint, Algorithm string
	PEM                    string
}

// Platform is one vendor driver bound to one BMC.
type Platform interface {
	Name() string
	Supports(action string) bool
	Status(ctx context.Context) (Status, error)
	SetSecureBoot(ctx context.Context, enable bool) (Change, error)
	SetPolicy(ctx context.Context, policy string) (Change, error)
	DBList(ctx context.Context) ([]Cert, error)
	DBImport(ctx context.Context, file string) (Change, error)
	DBExport(ctx context.Context, uri, file string) (Change, error)
	DBDelete(ctx context.Context, uri string) (Change, error)
	ResetKeys(ctx context.Context, resetType string) (Change, error)
	// AddSignature adds a SHA-256 signature (hex) to the dbx revocation list.
	AddSignature(ctx context.Context, sha256hex, owner string) (Change, error)
}

// Unsupported is embedded by drivers; it answers ErrUnsupported for everything
// except Name, Supports and Status, which every driver implements itself.
type Unsupported struct{}

func (Unsupported) SetSecureBoot(context.Context, bool) (Change, error) {
	return Change{}, ErrUnsupported
}
func (Unsupported) SetPolicy(context.Context, string) (Change, error) {
	return Change{}, ErrUnsupported
}
func (Unsupported) DBList(context.Context) ([]Cert, error) { return nil, ErrUnsupported }
func (Unsupported) DBImport(context.Context, string) (Change, error) {
	return Change{}, ErrUnsupported
}
func (Unsupported) DBExport(context.Context, string, string) (Change, error) {
	return Change{}, ErrUnsupported
}
func (Unsupported) DBDelete(context.Context, string) (Change, error) {
	return Change{}, ErrUnsupported
}

// PendingStatus renders "<target> (Pending - Reboot Required)" when a reboot is needed.
func PendingStatus(target string, reboot bool) string {
	if reboot {
		return target + " (Pending - Reboot Required)"
	}
	return target
}

func (Unsupported) ResetKeys(context.Context, string) (Change, error) {
	return Change{}, ErrUnsupported
}

func (Unsupported) AddSignature(context.Context, string, string) (Change, error) {
	return Change{}, ErrUnsupported
}
