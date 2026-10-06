// Package runner processes hosts in parallel, one Redfish session per host.
package runner

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"sbmgr/internal/actions"
	"sbmgr/internal/detect"
	"sbmgr/internal/inventory"
	"sbmgr/internal/probe"
	"sbmgr/internal/redfish"
	"sbmgr/internal/report"
)

// Options configures a run.
type Options struct {
	Action      string
	Params      actions.Params
	Platform    string // "auto" or a forced platform name
	Method      string // Dell import method: "", "oem" or "standard"
	Database    string // Secure Boot database ("" = db, or KEK, PK, dbx)
	Concurrency int    // default 20
	Client      redfish.Options
}

// Run executes opt.Action on every host and returns one result per host, in
// input order. A failing host never stops the others.
func Run(ctx context.Context, hosts []inventory.Host, opt Options) []report.Result {
	n := opt.Concurrency
	if n <= 0 {
		n = 20
	}
	results := make([]report.Result, len(hosts))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < n && w < len(hosts); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = one(ctx, hosts[i], opt)
			}
		}()
	}
	for i := range hosts {
		select {
		case jobs <- i:
		case <-ctx.Done():
			for j := i; j < len(hosts); j++ {
				r := report.New(hosts[j].IP, opt.Action, "")
				r.Error = "cancelled before start: " + ctx.Err().Error()
				results[j] = r
			}
			close(jobs)
			wg.Wait()
			return results
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

// one processes a single host. The session is always closed, and a panic in a
// driver becomes an error row instead of killing the run.
func one(ctx context.Context, h inventory.Host, opt Options) (res report.Result) {
	res = report.New(h.IP, opt.Action, "")
	start := time.Now()
	defer func() {
		if r := recover(); r != nil {
			res.Success = false
			res.Error = fmt.Sprintf("panic: %v", r)
		}
		slog.Info("host result", "ip", h.IP, "platform", res.Platform, "action", opt.Action, "database", opt.Database,
			"dry_run", opt.Params.DryRun, "success", res.Success, "message", res.Message, "change", res.ChangeMessage,
			"error", res.Error, "ms", time.Since(start).Milliseconds())
	}()
	c, err := redfish.New(h.IP, h.Username, h.Password, opt.Client)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if err := c.Login(ctx); err != nil {
		res.Error = "login failed: " + err.Error()
		return res
	}
	defer c.Logout(context.WithoutCancel(ctx))
	if opt.Action == "probe" {
		rep := probe.Run(ctx, c, opt.Platform, opt.Method, opt.Params.Capture)
		res.Platform, res.Checks, res.Capture, res.Success = rep.Platform, rep.Checks, rep.Capture, rep.OK()
		return res
	}
	p, err := detect.New(ctx, c, opt.Platform, opt.Method)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if opt.Database != "" && !detect.Bind(p, opt.Database) {
		res.Error = "this platform does not support --database"
		return res
	}
	slog.Debug("platform detected", "ip", h.IP, "platform", p.Name())
	return actions.Run(ctx, p, h.IP, opt.Action, opt.Params)
}
