// Package actions turns one CLI action into driver calls and a report.Result.
package actions

import (
	"context"
	"fmt"
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
		runSecureBoot(ctx, p, action, par.DryRun, &r)
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
		if par.DryRun {
			dryImport(ctx, p, par.CertFile, r)
			return
		}
		ch, err := p.DBImport(ctx, par.CertFile)
		finish(r, ch, err)
	case platform.ActionDBExport:
		if !isCertURI(redfish.SanitizePath(par.CertURI)) {
			r.Error = "not a certificate URI: " + par.CertURI
			return
		}
		ch, err := p.DBExport(ctx, redfish.SanitizePath(par.CertURI), hostFile(par.CertFile, r.IP))
		finish(r, ch, err)
	case platform.ActionDBDelete:
		if !isCertURI(redfish.SanitizePath(par.CertURI)) {
			r.Error = "not a certificate URI: " + par.CertURI
			return
		}
		if par.DryRun {
			dryDelete(ctx, p, redfish.SanitizePath(par.CertURI), r)
			return
		}
		ch, err := p.DBDelete(ctx, redfish.SanitizePath(par.CertURI))
		finish(r, ch, err)
	}
}

func setIf(dst *string, v string) {
	if v != "" {
		*dst = v
	}
}

func runSecureBoot(ctx context.Context, p platform.Platform, action string, dry bool, r *report.Result) {
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
	if st.Enabled == target {
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

// isCertURI guards db_export and db_delete: the URI must point into a Certificates
// collection, so a typo cannot delete an account or a session.
func isCertURI(uri string) bool {
	return strings.Contains(strings.ToLower(uri), "/certificates/")
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
	if listed, err := p.DBList(ctx); err == nil {
		if uri, ok := stdsb.AlreadyPresent(listed, data); ok {
			r.Message = "DRY RUN: certificate already present (" + uri + "), nothing would be imported"
			return
		}
	}
	r.Message = "DRY RUN: would import " + file
}

// dryDelete checks the certificate is in the store before saying it would be deleted.
func dryDelete(ctx context.Context, p platform.Platform, uri string, r *report.Result) {
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
