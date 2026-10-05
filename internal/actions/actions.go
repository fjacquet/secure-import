// Package actions turns one CLI action into driver calls and a report.Result.
package actions

import (
	"context"
	"fmt"

	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
	"sbmgr/internal/report"
)

// Params carries the CLI arguments some actions need.
type Params struct{ CertURI, CertFile string }

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
		runSecureBoot(ctx, p, action, &r)
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
		r.Message = fmt.Sprintf("Found %d DB certificates", len(certs))
	case platform.ActionDBImport:
		ch, err := p.DBImport(ctx, par.CertFile)
		finish(r, ch, err)
	case platform.ActionDBExport:
		ch, err := p.DBExport(ctx, redfish.SanitizePath(par.CertURI), par.CertFile)
		finish(r, ch, err)
	case platform.ActionDBDelete:
		ch, err := p.DBDelete(ctx, redfish.SanitizePath(par.CertURI))
		finish(r, ch, err)
	}
}

func setIf(dst *string, v string) {
	if v != "" {
		*dst = v
	}
}

func runSecureBoot(ctx context.Context, p platform.Platform, action string, r *report.Result) {
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
		setPolicy(ctx, p, action, st, r)
	default:
		setEnable(ctx, p, action, st, r)
	}
}

func setPolicy(ctx context.Context, p platform.Platform, action string, st platform.Status, r *report.Result) {
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

func setEnable(ctx context.Context, p platform.Platform, action string, st platform.Status, r *report.Result) {
	target := action == platform.ActionEnable
	if st.Enabled == target {
		r.Success, r.NewStatus = true, r.CurrentStatus
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
