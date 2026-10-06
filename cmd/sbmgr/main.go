// Command sbmgr manages UEFI Secure Boot and the db certificate store over
// Redfish on a fleet of BMCs (Dell iDRAC, HPE iLO, Lenovo XCC, Supermicro).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"syscall"
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
	case o.signatureOwner != "" && o.signature == "":
		return "--signature-owner only applies with --signature"
	case o.probeDump != "" && o.action != probeAction:
		return "--probe-dump only applies to -a probe"
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

// commandFor maps an action to the subcommand that replaces the deprecated -a form.
var commandFor = map[string]string{
	"status": "sbmgr status", "enable": "sbmgr enable", "disable": "sbmgr disable",
	"set_policy_custom": "sbmgr policy custom", "set_policy_standard": "sbmgr policy standard",
	"db_list": "sbmgr db list", "db_import": "sbmgr db import", "db_export": "sbmgr db export",
	"db_delete": "sbmgr db delete", "reset_keys": "sbmgr reset-keys", "probe": "sbmgr probe",
}

func newRootCmd(o *options, stdout, stderr io.Writer, code *int) *cobra.Command {
	root := &cobra.Command{
		Use:   "sbmgr <command> -i nodes.csv -o out.csv [flags]",
		Short: "Manage UEFI Secure Boot and the Secure Boot databases over Redfish",
		Long: "sbmgr manages UEFI Secure Boot and its certificate databases on a fleet of BMCs\n" +
			"(Dell iDRAC, HPE iLO, Lenovo XCC, Supermicro) over Redfish. Every command reads a CSV of\n" +
			"hosts (-i) and writes a result per host (-o).\n\n" +
			"New platform or firmware? Run `sbmgr probe` first: it reads, writes nothing, and says\n" +
			"what each BMC answers.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(*cobra.Command, []string) error {
			if o.showVersion {
				fmt.Fprintln(stdout, versionLine())
				return nil
			}
			if o.action == "" {
				return errors.New("a command is required (see sbmgr -h)")
			}
			// The pre-subcommand form: sbmgr -i f -o f -a <action>. Still works, for scripts.
			if cmd, ok := commandFor[o.action]; ok {
				fmt.Fprintf(stderr, "warning: -a/--action is deprecated, use `%s`\n", cmd)
			}
			*code = execute(*o, stdout, stderr)
			return nil
		},
	}
	root.AddGroup(
		&cobra.Group{ID: "secureboot", Title: "Secure Boot:"},
		&cobra.Group{ID: "databases", Title: "Certificate databases:"},
		&cobra.Group{ID: "diagnostics", Title: "Diagnostics:"},
	)

	// act builds a command that runs one action over the fleet.
	act := func(group, use, short, actionName string, args cobra.PositionalArgs) *cobra.Command {
		return &cobra.Command{
			GroupID: group, Use: use, Short: short, Args: args,
			RunE: func(*cobra.Command, []string) error {
				o.action = actionName
				*code = execute(*o, stdout, stderr)
				return nil
			},
		}
	}

	status := act("secureboot", "status", "Show the Secure Boot state", "status", cobra.NoArgs)
	enable := act("secureboot", "enable", "Enable Secure Boot (pending until the next reboot)", "enable", cobra.NoArgs)
	disable := act("secureboot", "disable", "Disable Secure Boot (pending until the next reboot)", "disable", cobra.NoArgs)

	policy := &cobra.Command{GroupID: "secureboot", Use: "policy", Short: "Set the Dell Secure Boot policy (custom or standard)"}
	policy.AddCommand(
		act("", "custom", "Stage the Custom policy (applied on the next reboot)", "set_policy_custom", cobra.NoArgs),
		act("", "standard", "Stage the Standard policy (applied on the next reboot)", "set_policy_standard", cobra.NoArgs),
	)

	resetKeys := act("secureboot", "reset-keys", "Reset or delete Secure Boot keys (destructive, needs --confirm)", "reset_keys", cobra.NoArgs)
	resetKeys.Flags().StringVar(&o.resetType, "reset-type", "", "type: "+strings.Join(resetTypes, ", "))
	resetKeys.Flags().StringVar(&o.database, "database", "", "reset only this database (db, KEK, PK or dbx) instead of every key")
	resetKeys.Flags().BoolVar(&o.confirm, "confirm", false, "confirm this destructive action")

	db := &cobra.Command{GroupID: "databases", Use: "db", Short: "List, import, export and delete database entries"}
	db.PersistentFlags().StringVar(&o.database, "database", "", "Secure Boot database: db (default), KEK, PK or dbx. Writes to PK, KEK and dbx need --confirm (PK and KEK also SetupMode or AuditMode)")
	db.PersistentFlags().BoolVar(&o.confirm, "confirm", false, "confirm a dangerous write (PK, KEK, dbx)")
	dbList := act("", "list", "List the entries of a database", "db_list", cobra.NoArgs)
	dbImport := act("", "import", "Add a certificate (or, for dbx, a SHA-256 signature) to a database", "db_import", cobra.NoArgs)
	dbImport.Flags().StringVar(&o.certFile, "cert-file", "", "certificate file (PEM or DER, max 64 KiB)")
	dbImport.Flags().StringVar(&o.signature, "signature", "", "dbx: SHA-256 (64 hex characters) to add instead of a certificate")
	dbImport.Flags().StringVar(&o.signatureOwner, "signature-owner", "", "dbx: optional signature owner GUID")
	dbExport := act("", "export", "Save a certificate to a file (the host IP is added to the name)", "db_export", cobra.NoArgs)
	dbExport.Flags().StringVar(&o.certURI, "cert-uri", "", "certificate URI")
	dbExport.Flags().StringVar(&o.certFile, "cert-file", "", "output file")
	dbDelete := act("", "delete", "Delete a certificate or dbx signature by URI", "db_delete", cobra.NoArgs)
	dbDelete.Flags().StringVar(&o.certURI, "cert-uri", "", "certificate URI")
	db.AddCommand(dbList, dbImport, dbExport, dbDelete)

	probe := act("diagnostics", "probe", "Read-only check of what each BMC answers (writes nothing)", "probe", cobra.NoArgs)
	probe.Flags().StringVar(&o.probeDump, "probe-dump", "", "write the redacted raw responses of every host to this JSON file")
	version := &cobra.Command{GroupID: "diagnostics", Use: "version", Short: "Print the version", Args: cobra.NoArgs,
		Run: func(*cobra.Command, []string) { fmt.Fprintln(stdout, versionLine()) }}

	root.AddCommand(status, enable, disable, policy, resetKeys, db, probe, version)

	// Flags shared by every command.
	pf := root.PersistentFlags()
	pf.SortFlags = false
	pf.StringVarP(&o.input, "input", "i", "", "input CSV: start_ip,end_ip,username,password")
	pf.StringVarP(&o.output, "output", "o", "", "output file")
	pf.StringVarP(&o.format, "format", "f", "csv", "output format: csv or json")
	pf.BoolVar(&o.dryRun, "dry-run", false, "read and validate only: report what would change, write nothing")
	pf.StringVar(&o.platform, "platform", "auto", "auto, idrac9, idrac10, ilo, lenovo or supermicro")
	pf.StringVar(&o.method, "method", "", "Dell certificate import method: oem or standard (default oem on iDRAC9, standard on iDRAC10)")
	pf.IntVar(&o.concurrency, "concurrency", 20, "hosts processed in parallel")
	pf.DurationVar(&o.timeout, "timeout", 30*time.Second, "per-request timeout")
	pf.IntVar(&o.retries, "retries", 2, "extra attempts on transient errors (connection resets on reads, BMC busy answers)")
	pf.DurationVar(&o.taskTimeout, "task-timeout", 120*time.Second, "how long to follow an asynchronous task")
	pf.BoolVar(&o.noWait, "no-wait", false, "do not follow asynchronous tasks")
	pf.BoolVar(&o.verifyTLS, "verify-tls", false, "verify BMC TLS certificates (off by default: BMCs are self-signed)")
	pf.StringVar(&o.caFile, "ca-file", "", "PEM CA bundle used to verify BMC certificates (implies --verify-tls)")
	pf.BoolVarP(&o.verbose, "verbose", "v", false, "debug logs (never include secrets)")

	// Root-only flags: --version, and the deprecated pre-subcommand form (-a plus the
	// per-action flags), kept hidden so existing scripts keep working.
	rf := root.Flags()
	rf.BoolVar(&o.showVersion, "version", false, "print the version and exit")
	rf.StringVarP(&o.action, "action", "a", "", "DEPRECATED: use a command instead")
	rf.StringVar(&o.certFile, "cert-file", "", "")
	rf.StringVar(&o.certURI, "cert-uri", "", "")
	rf.StringVar(&o.database, "database", "", "")
	rf.StringVar(&o.signature, "signature", "", "")
	rf.StringVar(&o.signatureOwner, "signature-owner", "", "")
	rf.StringVar(&o.resetType, "reset-type", "", "")
	rf.BoolVar(&o.confirm, "confirm", false, "")
	rf.StringVar(&o.probeDump, "probe-dump", "", "")
	for _, name := range []string{"action", "cert-file", "cert-uri", "database", "signature", "signature-owner", "reset-type", "confirm", "probe-dump"} {
		_ = rf.MarkHidden(name)
	}

	registerCompletions(root, db, resetKeys, dbImport, dbExport, probe)
	return root
}

// registerCompletions teaches the shell the fixed values and file types of the flags.
func registerCompletions(root, db, resetKeys, dbImport, dbExport, probe *cobra.Command) {
	values := func(vs ...string) func(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
		return func(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
			return vs, cobra.ShellCompDirectiveNoFileComp
		}
	}
	_ = root.RegisterFlagCompletionFunc("action", values(append(slices.Clone(platform.AllActions), probeAction)...))
	_ = root.RegisterFlagCompletionFunc("platform", values(platformNames...))
	_ = root.RegisterFlagCompletionFunc("method", values("oem", "standard"))
	_ = root.RegisterFlagCompletionFunc("format", values("csv", "json"))
	_ = root.MarkPersistentFlagFilename("input", "csv")
	_ = root.MarkPersistentFlagFilename("ca-file", "pem", "crt")
	_ = db.RegisterFlagCompletionFunc("database", values(databaseNames...))
	_ = resetKeys.RegisterFlagCompletionFunc("database", values(databaseNames...))
	_ = resetKeys.RegisterFlagCompletionFunc("reset-type", values(resetTypes...))
	_ = dbImport.MarkFlagFilename("cert-file", "pem", "der", "crt", "cer")
	_ = probe.MarkFlagFilename("probe-dump", "json")
	_ = dbExport.MarkFlagFilename("cert-file")
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
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

	if err := writeOutput(o, results); err != nil {
		fmt.Fprintln(stderr, "sbmgr:", err)
		return 2
	}
	if o.probeDump != "" {
		if err := writeProbeDump(o.probeDump, results); err != nil {
			fmt.Fprintln(stderr, "sbmgr:", err)
			return 2
		}
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
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600) // WriteFile keeps the mode of a file that already exists
}
