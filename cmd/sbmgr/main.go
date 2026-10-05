// Command sbmgr manages UEFI Secure Boot and the db certificate store over
// Redfish on a fleet of BMCs (Dell iDRAC, HPE iLO, Lenovo XCC, Supermicro).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"time"

	"sbmgr/internal/actions"
	"sbmgr/internal/inventory"
	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
	"sbmgr/internal/report"
	"sbmgr/internal/runner"

	"github.com/spf13/cobra"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

type options struct {
	input, output, action, format                                                                  string
	platform, method, certURI, certFile, resetType, probeDump, database, signature, signatureOwner string
	caFile                                                                                         string
	concurrency, retries                                                                           int
	timeout, taskTimeout                                                                           time.Duration
	noWait, verifyTLS, verbose, dryRun, confirm, showVersion                                       bool
}

const probeAction = "probe" // read-only: checks what each BMC answers

// resetTypes: the first three are the DMTF values; ResetPK, ResetKEK, ResetDB and
// ResetDBX are documented by the Dell iDRAC9 OpenAPI (ResetDB only touches "db").
// The BMC's own AllowableValues has the last word.
// version is set at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

var resetTypes = []string{"ResetAllKeysToDefault", "DeleteAllKeys", "DeletePK", "ResetPK", "ResetKEK", "ResetDB", "ResetDBX"}

var databaseNames = []string{"db", "KEK", "PK", "dbx"}

var platformNames = []string{"auto", "idrac9", "idrac10", "ilo", "lenovo", "supermicro"}

func (o *options) validate() string {
	switch {
	case o.input == "":
		return "-i/--input is required"
	case o.output == "":
		return "-o/--output is required"
	case o.action == "":
		return "-a/--action is required"
	case o.action != probeAction && !slices.Contains(platform.AllActions, o.action):
		return fmt.Sprintf("unknown action %q (choose one of: %s, %s)", o.action, strings.Join(platform.AllActions, ", "), probeAction)
	case o.format != "csv" && o.format != "json":
		return "format must be csv or json"
	case !slices.Contains(platformNames, o.platform):
		return fmt.Sprintf("unknown platform %q (choose one of: %s)", o.platform, strings.Join(platformNames, ", "))
	case o.method != "" && o.method != "oem" && o.method != "standard":
		return "method must be oem or standard"
	case o.database != "" && !slices.Contains(databaseNames, o.database):
		return "database must be one of " + strings.Join(databaseNames, ", ")
	case o.signature != "" && (o.action != platform.ActionDBImport || o.database != "dbx"):
		return "--signature only applies to db_import with --database dbx"
	case o.signature != "" && o.certFile != "":
		return "use either --signature or --cert-file, not both"
	case o.signature != "" && len(o.signature) != 64:
		return "--signature must be 64 hexadecimal characters (a SHA-256)"
	case o.action == platform.ActionDBImport && o.database == "dbx" && o.signature == "":
		return "dbx holds signatures: db_import needs --signature, not --cert-file"
	case o.action == platform.ActionResetKeys && o.database != "" && o.resetType != "ResetAllKeysToDefault" && o.resetType != "DeleteAllKeys":
		return "with --database, reset-type must be ResetAllKeysToDefault or DeleteAllKeys"
	case o.action == platform.ActionResetKeys && o.resetType == "":
		return "reset_keys requires --reset-type"
	case o.action == platform.ActionResetKeys && !slices.Contains(resetTypes, o.resetType):
		return "reset-type must be one of " + strings.Join(resetTypes, ", ")
	case o.action == platform.ActionResetKeys && !o.confirm && !o.dryRun:
		return "reset_keys is destructive (DeleteAllKeys and DeletePK leave the server in Setup Mode) and requires --confirm"
	case o.action == platform.ActionDBImport && o.certFile == "" && o.signature == "":
		return "db_import requires --cert-file"
	case o.action == platform.ActionDBDelete && o.certURI == "":
		return "db_delete requires --cert-uri"
	case o.action == platform.ActionDBExport && (o.certURI == "" || o.certFile == ""):
		return "db_export requires --cert-uri and --cert-file"
	case o.retries < 0:
		return "retries must not be negative"
	case o.concurrency <= 0:
		return "concurrency must be positive"
	}
	return ""
}

// versionLine is what --version and the version command print.
func versionLine() string {
	return fmt.Sprintf("sbmgr %s (%s, %s/%s)", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// run parses args, runs the command and returns the process exit code
// (0 ok, 1 a host or row failed, 2 usage or input error).
func run(args []string, stdout, stderr io.Writer) int {
	var o options
	code := 0
	root := newRootCmd(&o, stdout, stderr, &code)
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(stderr, "sbmgr:", err)
		return 2
	}
	return code
}

func newRootCmd(o *options, stdout, stderr io.Writer, code *int) *cobra.Command {
	root := &cobra.Command{
		Use:   "sbmgr -i nodes.csv -o out.csv -a <action> [flags]",
		Short: "Manage UEFI Secure Boot and the db certificate store over Redfish",
		Long: "sbmgr manages UEFI Secure Boot and the db certificate store of a fleet of BMCs\n" +
			"(Dell iDRAC, HPE iLO, Lenovo XCC, Supermicro) over Redfish.\n\n" +
			"New platform or firmware? Run -a probe first: it reads, writes nothing, and says\n" +
			"what each BMC answers.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(*cobra.Command, []string) error {
			if o.showVersion {
				fmt.Fprintln(stdout, versionLine())
				return nil
			}
			*code = execute(*o, stdout, stderr)
			return nil
		},
	}
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run:   func(*cobra.Command, []string) { fmt.Fprintln(stdout, versionLine()) },
	})

	fl := root.Flags()
	fl.SortFlags = false // keep the thematic order below
	// Input and output
	fl.StringVarP(&o.input, "input", "i", "", "input CSV: start_ip,end_ip,username,password")
	fl.StringVarP(&o.output, "output", "o", "", "output file")
	fl.StringVarP(&o.format, "format", "f", "csv", "output format: csv or json")
	// What to do
	fl.StringVarP(&o.action, "action", "a", "", "action: "+strings.Join(platform.AllActions, ", ")+", "+probeAction)
	fl.BoolVar(&o.dryRun, "dry-run", false, "read and validate only: report what would change, write nothing")
	fl.StringVar(&o.certFile, "cert-file", "", "certificate file for db_import (PEM or DER, max 64 KiB) and db_export (host IP added to the name)")
	fl.StringVar(&o.database, "database", "", "Secure Boot database: db (default), KEK, PK or dbx. Writes to PK, KEK and dbx need --confirm (PK and KEK also SetupMode or AuditMode)")
	fl.StringVar(&o.signature, "signature", "", "dbx: SHA-256 (64 hex characters) to add with db_import --database dbx")
	fl.StringVar(&o.signatureOwner, "signature-owner", "", "dbx: optional signature owner GUID")
	fl.StringVar(&o.certURI, "cert-uri", "", "certificate URI for db_export and db_delete")
	fl.StringVar(&o.resetType, "reset-type", "", "reset_keys type: "+strings.Join(resetTypes, ", "))
	fl.BoolVar(&o.confirm, "confirm", false, "confirm a destructive action (reset_keys)")
	fl.StringVar(&o.probeDump, "probe-dump", "", "probe: write the redacted raw responses of every host to this JSON file")
	// Platform
	fl.StringVar(&o.platform, "platform", "auto", "auto, idrac9, idrac10, ilo, lenovo or supermicro")
	fl.StringVar(&o.method, "method", "", "Dell certificate import method: oem or standard (default oem on iDRAC9, standard on iDRAC10)")
	// Network and tasks
	fl.IntVar(&o.concurrency, "concurrency", 20, "hosts processed in parallel")
	fl.DurationVar(&o.timeout, "timeout", 30*time.Second, "per-request timeout")
	fl.IntVar(&o.retries, "retries", 2, "extra attempts on transient errors (connection resets on reads, BMC busy answers)")
	fl.DurationVar(&o.taskTimeout, "task-timeout", 120*time.Second, "how long to follow an asynchronous task")
	fl.BoolVar(&o.noWait, "no-wait", false, "do not follow asynchronous tasks")
	// Security and diagnostics
	fl.BoolVar(&o.verifyTLS, "verify-tls", false, "verify BMC TLS certificates (off by default: BMCs are self-signed)")
	fl.StringVar(&o.caFile, "ca-file", "", "PEM CA bundle used to verify BMC certificates (implies --verify-tls)")
	fl.BoolVarP(&o.verbose, "verbose", "v", false, "debug logs (never include secrets)")
	fl.BoolVar(&o.showVersion, "version", false, "print the version and exit")

	registerCompletions(root)
	return root
}

// registerCompletions teaches the shell the fixed values and file types of the flags.
func registerCompletions(root *cobra.Command) {
	values := func(vs ...string) func(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
		return func(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
			return vs, cobra.ShellCompDirectiveNoFileComp
		}
	}
	_ = root.RegisterFlagCompletionFunc("action", values(append(slices.Clone(platform.AllActions), probeAction)...))
	_ = root.RegisterFlagCompletionFunc("platform", values(platformNames...))
	_ = root.RegisterFlagCompletionFunc("database", values(databaseNames...))
	_ = root.RegisterFlagCompletionFunc("method", values("oem", "standard"))
	_ = root.RegisterFlagCompletionFunc("reset-type", values(resetTypes...))
	_ = root.RegisterFlagCompletionFunc("format", values("csv", "json"))
	_ = root.MarkFlagFilename("input", "csv")
	_ = root.MarkFlagFilename("cert-file", "pem", "der", "crt", "cer")
	_ = root.MarkFlagFilename("ca-file", "pem", "crt")
	_ = root.MarkFlagFilename("probe-dump", "json")
}

// execute validates the options and processes the fleet.
func execute(o options, stdout, stderr io.Writer) int {
	if msg := o.validate(); msg != "" {
		fmt.Fprintln(stderr, "sbmgr:", msg)
		return 2
	}

	level := slog.LevelWarn
	if o.verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level})))

	if !o.verifyTLS && o.caFile == "" {
		fmt.Fprintln(stderr, "warning: TLS verification is disabled; credentials can be intercepted on an untrusted network (use --verify-tls or --ca-file)")
	}
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
		Params:      actions.Params{CertURI: o.certURI, CertFile: o.certFile, DryRun: o.dryRun, ResetType: o.resetType, Capture: o.probeDump != "", Database: o.database, Signature: o.signature, SignatureOwner: o.signatureOwner, Confirm: o.confirm},
		Platform:    o.platform,
		Method:      o.method,
		Database:    o.database,
		Concurrency: o.concurrency,
		Client: redfish.Options{
			Timeout: o.timeout, TaskTimeout: o.taskTimeout, NoWait: o.noWait, Retries: o.retries,
			VerifyTLS: o.verifyTLS, CAFile: o.caFile,
		},
	})

	if o.probeDump != "" {
		if err := writeProbeDump(o.probeDump, results); err != nil {
			fmt.Fprintln(stderr, "sbmgr:", err)
			return 2
		}
	}
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

// writeProbeDump saves the redacted raw responses of the probe, by host then URI.
// The file is 0600: it is redacted, but it still describes the machines.
func writeProbeDump(path string, results []report.Result) error {
	dump := map[string]map[string]json.RawMessage{}
	for _, r := range results {
		if r.Capture != nil {
			dump[r.IP] = r.Capture
		}
	}
	b, err := json.MarshalIndent(dump, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
