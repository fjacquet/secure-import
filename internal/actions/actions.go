// Package actions turns one CLI action into driver calls and a report.Result.
package actions

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
	"sbmgr/internal/report"
	"sbmgr/internal/stdsb"
)

// Params carries the CLI arguments some actions need.
type Params struct {
	CertURI, CertFile string
	ResetType         string
	// Database is the Secure Boot database chosen with --database ("" = db).
	Database string
	// Signature is a SHA-256 (hex) to add to dbx; SignatureOwner an optional owner GUID.
	Signature, SignatureOwner string
	// Confirm authorises writes the tool treats as dangerous (PK, KEK, dbx, resets).
	Confirm bool
	Capture bool // probe: keep a redacted copy of the raw responses
	// DryRun reads and validates everything but writes nothing: the result
	// says what would change.
	DryRun bool
}

// Run executes action on p and describes the outcome. It never panics on
// driver errors: every failure becomes r.Error.
func Run(ctx context.Context, p platform.Platform, ip, action string, par Params) report.Result {
	r := report.New(ip, action, p.Name())
	if !p.Supports(action) {
		r.Error = fmt.Sprintf("action not supported on %s", p.Name())
		return r
	}
	if platform.IsDBAction(action) {
		runDB(ctx, p, action, par, &r)
	} else {
		runSecureBoot(ctx, p, action, par, &r)
	}
	return r
}

func finish(r *report.Result, ch platform.Change, err error) {
	if err != nil {
		r.Error = err.Error()
		return
	}
	r.Success = true
	r.Message = ch.Message
}

func runDB(ctx context.Context, p platform.Platform, action string, par Params, r *report.Result) {
	switch action {
	case platform.ActionDBList:
		certs, err := p.DBList(ctx)
		if err != nil {
			r.Error = "Failed to get DB certificates: " + err.Error()
			return
		}
		r.Success, r.CertCount = true, len(certs)
		r.Message = fmt.Sprintf("Found %d DB certificates", len(certs)) + certDetails(certs)
	case platform.ActionDBImport:
		if par.Signature != "" {
			importSignature(ctx, p, par, r)
			return
		}
		if err := guardWrite(ctx, p, par.Database, par.Confirm); err != nil {
			r.Error = err.Error()
			return
		}
		if par.DryRun {
			dryImport(ctx, p, par.CertFile, r)
			return
		}
		ch, err := p.DBImport(ctx, par.CertFile)
		finish(r, ch, err)
	case platform.ActionDBExport:
		uri := normalizeURI(par.CertURI)
		if !isCertURI(uri) {
			r.Error = "not a certificate URI: " + par.CertURI
			return
		}
		ch, err := p.DBExport(ctx, uri, hostFile(par.CertFile, r.IP))
		finish(r, ch, err)
	case platform.ActionDBDelete:
		uri := normalizeURI(par.CertURI) // what is checked below is exactly what is sent
		if !isCertURI(uri) {
			r.Error = "not a certificate URI: " + par.CertURI
			return
		}
		if err := guardWrite(ctx, p, databaseOfURI(uri), par.Confirm); err != nil {
			r.Error = err.Error()
			return
		}
		if par.DryRun {
			dryDelete(ctx, p, uri, par.Database, r)
			return
		}
		ch, err := p.DBDelete(ctx, uri)
		finish(r, ch, err)
	}
}

func setIf(dst *string, v string) {
	if v != "" {
		*dst = v
	}
}

func runSecureBoot(ctx context.Context, p platform.Platform, action string, par Params, r *report.Result) {
	dry := par.DryRun
	st, err := p.Status(ctx)
	if err != nil {
		r.Error = "Failed to get status: " + err.Error()
		return
	}
	r.CurrentStatus = "Disabled"
	if st.Enabled {
		r.CurrentStatus = "Enabled"
	}
	r.Description = st.Description
	setIf(&r.Name, st.Name)
	setIf(&r.CurrentBoot, st.CurrentBoot)
	setIf(&r.CurrentMode, st.Mode)
	setIf(&r.CurrentPolicy, st.Policy)
	setIf(&r.CertificatesURI, st.CertificatesURI)

	switch action {
	case platform.ActionStatus:
		r.Success, r.NewStatus, r.NewPolicy = true, r.CurrentStatus, r.CurrentPolicy
	case platform.ActionResetKeys:
		resetKeys(ctx, p, par, st, r)
	case platform.ActionPolicyCustom, platform.ActionPolicyStandard:
		setPolicy(ctx, p, action, st, dry, r)
	default:
		setEnable(ctx, p, action, st, dry, r)
	}
}

func setPolicy(ctx context.Context, p platform.Platform, action string, st platform.Status, dry bool, r *report.Result) {
	target := "Custom"
	if action == platform.ActionPolicyStandard {
		target = "Standard"
	}
	if st.Enabled && st.Mode != "DeployedMode" {
		r.Error = fmt.Sprintf("Cannot change policy: Secure Boot mode is '%s', expected 'DeployedMode'", st.Mode)
		return
	}
	switch {
	case st.Policy == target && (st.PendingPolicy == "" || st.PendingPolicy == target):
		r.Success, r.NewPolicy = true, target
		return
	case st.PendingPolicy == target:
		r.Success, r.NewPolicy = true, platform.PendingStatus(target, true)
		r.ChangeMessage = "Policy change to " + target + " is already pending; reboot to apply"
		return
	}
	if dry {
		r.Success, r.NewPolicy = true, r.CurrentPolicy
		r.ChangeMessage = "DRY RUN: would set the Secure Boot policy to " + target
		return
	}
	ch, err := p.SetPolicy(ctx, target)
	if err != nil {
		r.Error = "Failed to set policy: " + err.Error()
		return
	}
	r.ChangeMessage = ch.Message
	if ch.Location == "" || ch.JobID == "" {
		r.NewPolicy = "Unknown (Task Creation Failed)"
		r.Error = "Policy change task creation failed - missing Location or Job ID"
		return
	}
	r.NewPolicy = platform.PendingStatus(target, true)
	r.Success = true
}

func setEnable(ctx context.Context, p platform.Platform, action string, st platform.Status, dry bool, r *report.Result) {
	target := action == platform.ActionEnable
	if st.PendingEnabled != nil && *st.PendingEnabled == target && st.Enabled != target {
		r.Success, r.NewStatus = true, platform.PendingStatus(map[bool]string{true: "Enabled", false: "Disabled"}[target], true)
		r.ChangeMessage = "Change to " + map[bool]string{true: "enabled", false: "disabled"}[target] + " is already pending; reboot to apply"
		return
	}
	if st.Enabled == target && (st.PendingEnabled == nil || *st.PendingEnabled == target) {
		r.Success, r.NewStatus = true, r.CurrentStatus
		return
	}
	if dry {
		r.Success, r.NewStatus = true, r.CurrentStatus
		r.ChangeMessage = fmt.Sprintf("DRY RUN: would set SecureBootEnable to %v", target)
		return
	}
	ch, err := p.SetSecureBoot(ctx, target)
	if err != nil {
		r.Error = "Failed to set secure boot: " + err.Error()
		return
	}
	r.ChangeMessage = ch.Message
	word := "Disabled"
	if target {
		word = "Enabled"
	}
	r.NewStatus = platform.PendingStatus(word, ch.RebootRequired)
	r.Success = true
}

// hostFile inserts the host address before the extension so that hosts exported
// in parallel never write the same file.
func hostFile(file, ip string) string {
	ext := filepath.Ext(file)
	return strings.TrimSuffix(file, ext) + "_" + strings.NewReplacer(":", "-", "/", "-").Replace(ip) + ext
}

// isCertURI guards db_export and db_delete: the URI must point into a Certificates (or, for
// dbx, Signatures) collection, so a typo cannot delete an account or a session.
func isCertURI(uri string) bool {
	lower := strings.ToLower(uri)
	return strings.Contains(lower, "/certificates/") || strings.Contains(lower, "/signatures/")
}

// certDetails lists the optional fields BMCs returned, one entry per certificate,
// so that a fleet audit does not need a separate query. It is empty when no
// certificate has any detail.
func certDetails(certs []platform.Cert) string {
	var parts []string
	any := false
	for _, c := range certs {
		label := c.Subject
		if label == "" {
			label = c.URI
		} else {
			any = true
		}
		if c.NotAfter != "" {
			label += " (expires " + c.NotAfter + ")"
			any = true
		}
		parts = append(parts, label)
	}
	if !any {
		return ""
	}
	return ": " + strings.Join(parts, "; ")
}

// dryImport validates the certificate file and says whether it is already enrolled.
func dryImport(ctx context.Context, p platform.Platform, file string, r *report.Result) {
	data, err := stdsb.ReadCertFile(file)
	if err == nil {
		_, err = stdsb.ToPEM(data)
	}
	if err != nil {
		r.Error = err.Error()
		return
	}
	r.Success = true
	var uri string
	var present bool
	if h, ok := p.(interface {
		HasCert(context.Context, []byte) (string, bool)
	}); ok {
		uri, present = h.HasCert(ctx, data) // the platform knows how to compare its own store
	} else if listed, err := p.DBList(ctx); err == nil {
		uri, present = stdsb.AlreadyPresent(listed, data)
	}
	if present {
		r.Message = "DRY RUN: certificate already present (" + uri + "), nothing would be imported"
		return
	}
	r.Message = "DRY RUN: would import " + file
}

// dryDelete checks the certificate is in the store before saying it would be deleted.
func dryDelete(ctx context.Context, p platform.Platform, uri string, bound string, r *report.Result) {
	// The platform lists only the database it is bound to (db by default). A member of
	// another database cannot be checked from that listing, and saying "not found" would
	// be wrong: say what could not be verified and how to verify it.
	if db := databaseOfURI(uri); db != "" && !strings.EqualFold(db, bound) {
		r.Success = true
		r.Message = "DRY RUN: would delete " + uri + " (not verified: pass --database " + db + " to check that it exists)"
		return
	}
	listed, err := p.DBList(ctx)
	if err != nil {
		r.Error = "Failed to get DB certificates: " + err.Error()
		return
	}
	if !slices.ContainsFunc(listed, func(c platform.Cert) bool { return strings.EqualFold(c.URI, uri) }) {
		r.Error = "certificate not found in the db store: " + uri
		return
	}
	r.Success = true
	r.Message = "DRY RUN: would delete " + uri
}

// resetKeys runs the destructive key reset. The CLI refuses it without --confirm.
func resetKeys(ctx context.Context, p platform.Platform, par Params, st platform.Status, r *report.Result) {
	// ADR 0006: --confirm is the safeguard of every reset. Requiring Setup or Audit mode
	// would forbid the operations that lead there (DeletePK, DeleteAllKeys), and a
	// whole-SecureBoot reset reaches PK and KEK anyway, so one rule covers every spelling.
	if !par.Confirm && !par.DryRun {
		r.Error = "reset_keys is destructive and requires --confirm"
		return
	}
	scope := "all Secure Boot keys"
	if par.Database != "" {
		scope = "the " + par.Database + " database"
	}
	if par.DryRun {
		r.Success, r.NewStatus = true, r.CurrentStatus
		r.ChangeMessage = "DRY RUN: would reset " + scope + " (" + par.ResetType + ")"
		return
	}
	ch, err := p.ResetKeys(ctx, par.ResetType)
	if err != nil {
		r.Error = "Failed to reset keys: " + err.Error()
		return
	}
	r.ChangeMessage = ch.Message
	r.NewStatus = platform.PendingStatus(r.CurrentStatus, ch.RebootRequired)
	r.Success = true
}

// guardedDatabases need --confirm for any write; PK and KEK also need the platform to
// be in Setup or Audit mode, so a deployed server is never left without its keys by mistake.
func guardWrite(ctx context.Context, p platform.Platform, database string, confirm bool) error {
	mode := ""
	if strings.EqualFold(database, "PK") || strings.EqualFold(database, "KEK") {
		if st, err := p.Status(ctx); err == nil {
			mode = st.Mode
		}
	}
	return guardWriteIn(database, confirm, mode)
}

func guardWriteIn(database string, confirm bool, mode string) error {
	switch strings.ToLower(database) {
	case "pk", "kek", "dbx":
		if !confirm {
			return fmt.Errorf("writing to the %s database is dangerous and requires --confirm", database)
		}
	}
	switch strings.ToLower(database) {
	case "pk", "kek":
		if mode != "SetupMode" && mode != "AuditMode" {
			return fmt.Errorf("refusing to change the %s database: Secure Boot mode is %q, it must be SetupMode or AuditMode", database, mode)
		}
	}
	return nil
}

// normalizeURI makes a user-supplied certificate URI canonical before it is checked AND
// sent: percent-decoded (repeatedly, so %254B cannot hide a K), cleaned of "." ".." and
// empty segments, of ";" parameters, of the query and of stray spaces. Without this a
// guarded database could be reached by a spelling the guard does not recognise but the
// BMC normalises (%4BEK, kek;x=1, KEK%20).
func normalizeURI(uri string) string {
	uri = redfish.SanitizePath(uri)
	for i := 0; i < 4; i++ {
		dec, err := url.PathUnescape(uri)
		if err != nil || dec == uri {
			break
		}
		uri = dec
	}
	if i := strings.IndexAny(uri, "?#"); i >= 0 {
		uri = uri[:i]
	}
	var segs []string
	for _, seg := range strings.Split(strings.ReplaceAll(uri, `\`, "/"), "/") {
		if i := strings.Index(seg, ";"); i >= 0 {
			seg = seg[:i]
		}
		switch seg = strings.TrimSpace(seg); seg {
		case "", ".":
		case "..":
			if len(segs) > 0 {
				segs = segs[:len(segs)-1]
			}
		default:
			segs = append(segs, seg)
		}
	}
	return "/" + strings.Join(segs, "/")
}

// databaseOfURI names the guarded database a (normalised) certificate URI lives in.
func databaseOfURI(uri string) string {
	for _, seg := range strings.Split(strings.ToLower(uri), "/") {
		switch seg {
		case "pk", "kek", "dbx":
			return strings.ToUpper(seg)
		}
	}
	return ""
}

// importSignature adds a SHA-256 to dbx (--signature). Always guarded.
func importSignature(ctx context.Context, p platform.Platform, par Params, r *report.Result) {
	if err := guardWrite(ctx, p, "dbx", par.Confirm); err != nil {
		r.Error = err.Error()
		return
	}
	if par.DryRun {
		r.Success = true
		r.Message = "DRY RUN: would add signature " + par.Signature + " to dbx"
		return
	}
	ch, err := p.AddSignature(ctx, par.Signature, par.SignatureOwner)
	finish(r, ch, err)
}
