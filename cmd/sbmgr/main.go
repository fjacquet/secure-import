// Command sbmgr manages UEFI Secure Boot and the db certificate store over
// Redfish on a fleet of BMCs (Dell iDRAC, HPE iLO, Lenovo XCC, Supermicro).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"
	"time"

	"sbmgr/internal/actions"
	"sbmgr/internal/inventory"
	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
	"sbmgr/internal/report"
	"sbmgr/internal/runner"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

type options struct {
	input, output, action, format       string
	platform, method, certURI, certFile string
	caFile                              string
	concurrency                         int
	timeout, taskTimeout                time.Duration
	noWait, verifyTLS, verbose          bool
}

var platformNames = []string{"auto", "idrac9", "idrac10", "ilo", "lenovo", "supermicro"}

func (o *options) validate() string {
	switch {
	case o.input == "":
		return "-i/--input is required"
	case o.output == "":
		return "-o/--output is required"
	case o.action == "":
		return "-a/--action is required"
	case !slices.Contains(platform.AllActions, o.action):
		return fmt.Sprintf("unknown action %q (choose one of: %s)", o.action, strings.Join(platform.AllActions, ", "))
	case o.format != "csv" && o.format != "json":
		return "format must be csv or json"
	case !slices.Contains(platformNames, o.platform):
		return fmt.Sprintf("unknown platform %q (choose one of: %s)", o.platform, strings.Join(platformNames, ", "))
	case o.method != "" && o.method != "oem" && o.method != "standard":
		return "method must be oem or standard"
	case o.action == platform.ActionDBImport && o.certFile == "":
		return "db_import requires --cert-file"
	case o.action == platform.ActionDBDelete && o.certURI == "":
		return "db_delete requires --cert-uri"
	case o.action == platform.ActionDBExport && (o.certURI == "" || o.certFile == ""):
		return "db_export requires --cert-uri and --cert-file"
	case o.concurrency <= 0:
		return "concurrency must be positive"
	}
	return ""
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sbmgr", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	both := func(p *string, short, long, def, usage string) {
		fs.StringVar(p, short, def, usage)
		fs.StringVar(p, long, def, usage)
	}
	both(&o.input, "i", "input", "", "input CSV: start_ip,end_ip,username,password")
	both(&o.output, "o", "output", "", "output file")
	both(&o.action, "a", "action", "", "action: "+strings.Join(platform.AllActions, ", "))
	both(&o.format, "f", "format", "csv", "output format: csv or json")
	fs.StringVar(&o.platform, "platform", "auto", "auto, idrac9, idrac10, ilo, lenovo or supermicro (all but idrac9 are not validated on hardware)")
	fs.StringVar(&o.method, "method", "", "Dell certificate import method: oem or standard (default oem on iDRAC9, standard on iDRAC10)")
	fs.StringVar(&o.certURI, "cert-uri", "", "certificate URI for db_export and db_delete")
	fs.StringVar(&o.certFile, "cert-file", "", "certificate file for db_import (PEM or DER, max 64 KiB) and db_export (host IP added to the name)")
	fs.IntVar(&o.concurrency, "concurrency", 20, "hosts processed in parallel")
	fs.DurationVar(&o.timeout, "timeout", 30*time.Second, "per-request timeout")
	fs.DurationVar(&o.taskTimeout, "task-timeout", 120*time.Second, "how long to follow an asynchronous task")
	fs.BoolVar(&o.noWait, "no-wait", false, "do not follow asynchronous tasks")
	fs.BoolVar(&o.verifyTLS, "verify-tls", false, "verify BMC TLS certificates (off by default: BMCs are self-signed)")
	fs.StringVar(&o.caFile, "ca-file", "", "PEM CA bundle used to verify BMC certificates (implies --verify-tls)")
	fs.BoolVar(&o.verbose, "v", false, "debug logs (never include secrets)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: sbmgr -i nodes.csv -o out.csv -a <action> [options]")
		fmt.Fprintln(stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if msg := o.validate(); msg != "" {
		fmt.Fprintln(stderr, "sbmgr:", msg)
		return 2
	}

	level := slog.LevelWarn
	if o.verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level})))

	if w := inventory.PermissionWarning(o.input); w != "" {
		fmt.Fprintln(stderr, "warning:", w)
	}
	rows, err := inventory.Read(o.input)
	if err != nil {
		fmt.Fprintln(stderr, "sbmgr:", err)
		return 2
	}
	hosts, rowErr := inventory.Hosts(rows)
	if len(hosts) == 0 {
		if rowErr != nil {
			fmt.Fprintln(stderr, "sbmgr:", rowErr)
		}
		fmt.Fprintln(stderr, "sbmgr: no hosts to process in", o.input)
		return 2
	}
	if rowErr != nil {
		fmt.Fprintln(stderr, "warning: invalid rows skipped:\n"+rowErr.Error())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	results := runner.Run(ctx, hosts, runner.Options{
		Action:      o.action,
		Params:      actions.Params{CertURI: o.certURI, CertFile: o.certFile},
		Platform:    o.platform,
		Method:      o.method,
		Concurrency: o.concurrency,
		Client: redfish.Options{
			Timeout: o.timeout, TaskTimeout: o.taskTimeout, NoWait: o.noWait,
			VerifyTLS: o.verifyTLS, CAFile: o.caFile,
		},
	})

	if err := writeOutput(o, results); err != nil {
		fmt.Fprintln(stderr, "sbmgr:", err)
		return 2
	}
	failed := 0
	for _, r := range results {
		if !r.Success {
			failed++
		}
	}
	fmt.Fprintf(stdout, "Processing complete. Results saved to %s (%d succeeded, %d failed)\n", o.output, len(results)-failed, failed)
	if failed > 0 || rowErr != nil {
		return 1
	}
	return 0
}

func writeOutput(o options, results []report.Result) error {
	f, err := os.Create(o.output)
	if err != nil {
		return err
	}
	if o.format == "json" {
		err = report.WriteJSON(f, results)
	} else {
		err = report.WriteCSV(f, o.action, results)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
