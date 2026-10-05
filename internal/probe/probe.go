// Package probe is the read-only "probe" action: it replays the reads each driver
// depends on, says what the BMC actually answers, and can keep a redacted copy of
// the raw responses so a platform can be validated without touching it.
package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"sbmgr/internal/detect"
	"sbmgr/internal/redfish"
	"sbmgr/internal/report"
)

// Report is the outcome of probing one BMC.
type Report struct {
	Platform string
	Checks   []report.Check
	Capture  map[string]json.RawMessage // redacted raw answers by URI; nil unless requested
}

// OK reports whether no check failed. An absent resource is information, not a failure.
func (r Report) OK() bool {
	for _, c := range r.Checks {
		if c.Status == report.CheckFail {
			return false
		}
	}
	return true
}

type prober struct {
	c   *redfish.Client
	rep Report
}

func (p *prober) add(name, status, detail string) {
	p.rep.Checks = append(p.rep.Checks, report.Check{Name: name, Status: status, Detail: detail})
}

// fetch GETs path (reads only), keeps a redacted copy when capturing, and decodes it.
func (p *prober) fetch(ctx context.Context, path string) (map[string]any, error) {
	resp, err := p.c.Do(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(resp.Body, &doc); err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	if p.rep.Capture != nil {
		if b, err := json.Marshal(redact(doc)); err == nil {
			p.rep.Capture[path] = b
		}
	}
	return doc, nil
}

// Run probes one BMC. forced and method are the --platform and --method values.
// It never writes: every request is a GET. Checks that cannot run are reported,
// and the following ones still run.
func Run(ctx context.Context, c *redfish.Client, forced, method string, capture bool) Report {
	p := &prober{c: c}
	if capture {
		p.rep.Capture = map[string]json.RawMessage{}
	}
	root, err := c.Root(ctx)
	if err != nil {
		p.add("service root", report.CheckFail, err.Error())
		return p.rep
	}
	p.add("service root", report.CheckOK, fmt.Sprintf("Vendor=%q Product=%q", root.Vendor, root.Product))
	if _, err := p.fetch(ctx, "/redfish/v1/"); err != nil {
		p.add("service root capture", report.CheckAbsent, err.Error())
	}

	drv, err := detect.New(ctx, c, forced, method)
	if err != nil {
		p.add("platform detection", report.CheckFail, err.Error())
	} else {
		p.rep.Platform = drv.Name()
		p.add("platform detection", report.CheckOK, drv.Name())
	}
	if m, err := c.Manager(ctx); err != nil {
		p.add("manager firmware", report.CheckAbsent, err.Error())
	} else {
		p.add("manager firmware", report.CheckOK, fmt.Sprintf("Model=%q FirmwareVersion=%q", m.Model, m.FirmwareVersion))
	}

	sbPath := p.secureBoot(ctx)
	p.databases(ctx, sbPath)
	if strings.HasPrefix(p.rep.Platform, "idrac") {
		p.dell(ctx)
	}

	if drv != nil {
		if st, err := drv.Status(ctx); err != nil {
			p.add("driver status", report.CheckFail, err.Error())
		} else {
			p.add("driver status", report.CheckOK, fmt.Sprintf("Enabled=%v CurrentBoot=%s Mode=%s Policy=%s", st.Enabled, st.CurrentBoot, st.Mode, st.Policy))
		}
		if certs, err := drv.DBList(ctx); err != nil {
			p.add("driver db_list", report.CheckFail, err.Error())
		} else {
			p.add("driver db_list", report.CheckOK, fmt.Sprintf("%d certificates", len(certs)))
		}
	}
	return p.rep
}

func link(doc map[string]any, key string) string {
	if m, ok := doc[key].(map[string]any); ok {
		s, _ := m["@odata.id"].(string)
		return s
	}
	return ""
}

// secureBoot checks the SecureBoot resource and its ResetKeys action; it returns the
// SecureBoot URI ("" when it cannot be found).
func (p *prober) secureBoot(ctx context.Context) string {
	sys, err := p.c.SystemPath(ctx)
	if err != nil {
		p.add("computer system", report.CheckFail, err.Error())
		return ""
	}
	p.add("computer system", report.CheckOK, sys)
	sysDoc, err := p.fetch(ctx, sys)
	if err != nil {
		p.add("SecureBoot resource", report.CheckFail, err.Error())
		return ""
	}
	sb := link(sysDoc, "SecureBoot")
	if sb == "" {
		p.add("SecureBoot resource", report.CheckAbsent, "the system has no SecureBoot link")
		return ""
	}
	doc, err := p.fetch(ctx, sb)
	if err != nil {
		p.add("SecureBoot resource", report.CheckFail, err.Error())
		return ""
	}
	var missing []string
	for _, k := range []string{"SecureBootEnable", "SecureBootCurrentBoot", "SecureBootMode"} {
		if _, ok := doc[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		p.add("SecureBoot resource", report.CheckOK, sb+" (missing: "+strings.Join(missing, ", ")+")")
	} else {
		p.add("SecureBoot resource", report.CheckOK, sb)
	}
	actions, _ := doc["Actions"].(map[string]any)
	reset, ok := actions["#SecureBoot.ResetKeys"].(map[string]any)
	if !ok {
		p.add("ResetKeys action", report.CheckAbsent, "no #SecureBoot.ResetKeys in Actions")
		return sb
	}
	allowed, _ := reset["ResetKeysType@Redfish.AllowableValues"].([]any)
	var vals []string
	for _, v := range allowed {
		if s, ok := v.(string); ok {
			vals = append(vals, s)
		}
	}
	p.add("ResetKeys action", report.CheckOK, "allowed: "+strings.Join(vals, ", "))
	return sb
}

// databases checks the SecureBootDatabases collection and the certificates of db.
func (p *prober) databases(ctx context.Context, sb string) {
	if sb == "" {
		return
	}
	sbDoc, err := p.fetch(ctx, sb)
	if err != nil {
		return
	}
	dbs := link(sbDoc, "SecureBootDatabases")
	if dbs == "" {
		p.add("SecureBoot databases", report.CheckAbsent, "no SecureBootDatabases link")
		return
	}
	members, err := p.c.Members(ctx, dbs)
	if err != nil {
		p.add("SecureBoot databases", report.CheckFail, err.Error())
		return
	}
	var ids []string
	dbURI := ""
	for _, m := range members {
		id := m.ODataID[strings.LastIndex(m.ODataID, "/")+1:]
		ids = append(ids, id)
		if strings.EqualFold(id, "db") {
			dbURI = m.ODataID
		}
	}
	p.add("SecureBoot databases", report.CheckOK, strings.Join(ids, ", "))
	p.eachDatabase(ctx, members)
	if dbURI == "" {
		p.add("db certificates", report.CheckFail, "no database named db")
		return
	}
	dbDoc, err := p.fetch(ctx, dbURI)
	if err != nil {
		p.add("db certificates", report.CheckFail, err.Error())
		return
	}
	certs := link(dbDoc, "Certificates")
	if certs == "" {
		certs = dbURI + "/Certificates"
	}
	list, err := p.c.Members(ctx, certs)
	if err != nil {
		p.add("db certificates", report.CheckFail, err.Error())
		return
	}
	p.add("db certificates", report.CheckOK, fmt.Sprintf("%s: %d certificates", certs, len(list)))
	if len(list) == 0 {
		return
	}
	one, err := p.fetch(ctx, list[0].ODataID)
	if err != nil {
		p.add("db certificate fields", report.CheckAbsent, err.Error())
		return
	}
	var have, miss []string
	for _, k := range []string{"CertificateString", "Fingerprint", "FingerprintHashAlgorithm", "Subject", "Issuer", "ValidNotAfter"} {
		if _, ok := one[k]; ok {
			have = append(have, k)
		} else {
			miss = append(miss, k)
		}
	}
	d := "present: " + strings.Join(have, ", ")
	if len(miss) > 0 {
		d += "; missing: " + strings.Join(miss, ", ")
	}
	p.add("db certificate fields", report.CheckOK, d)
}

// dell checks what only the Dell drivers use: the BIOS policy attribute and the OEM store.
func (p *prober) dell(ctx context.Context) {
	sys, err := p.c.SystemPath(ctx)
	if err != nil {
		return
	}
	sysDoc, err := p.fetch(ctx, sys)
	if err != nil {
		return
	}
	bios := link(sysDoc, "Bios")
	if bios == "" {
		p.add("Bios SecureBootPolicy", report.CheckAbsent, "no Bios link")
		return
	}
	doc, err := p.fetch(ctx, bios)
	if err != nil {
		p.add("Bios SecureBootPolicy", report.CheckFail, err.Error())
		return
	}
	attrs, _ := doc["Attributes"].(map[string]any)
	if v, ok := attrs["SecureBootPolicy"].(string); ok {
		p.add("Bios SecureBootPolicy", report.CheckOK, v)
	} else {
		p.add("Bios SecureBootPolicy", report.CheckAbsent, "attribute not present")
	}
}

// sensitive matches keys whose values identify a machine or hold a secret.
var sensitive = regexp.MustCompile(`(?i)serial|uuid|mac|address|host|fqdn|dns|domain|password|token|asset|sku|partnumber|secret|key$|servicetag|nodeid|expressservice|iscsi|initiator|iqn|ipv4|ipv6`)

// redact replaces the value of every sensitive key by "<redacted>", recursively.
// Keys listed in keep are never redacted.
func redact(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if sensitive.MatchString(k) && !keep[k] {
				out[k] = "<redacted>"
				continue
			}
			out[k] = redact(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redact(val)
		}
		return out
	}
	return v
}

// keep lists keys the pattern could catch although they are what validation needs.
var keep = map[string]bool{"SecureBootEnable": true, "SecureBootCurrentBoot": true,
	"SecureBootMode": true, "SecureBootDatabases": true, "SecureBootPolicy": true}

// eachDatabase reports, for PK, KEK, db and dbx, which collection the BMC exposes, how
// many members it holds and what the per-database ResetKeys action allows, so nobody
// has to guess before writing to a database other than db.
func (p *prober) eachDatabase(ctx context.Context, members []redfish.Link) {
	var defaults []string
	for _, m := range members {
		id := m.ODataID[strings.LastIndex(m.ODataID, "/")+1:]
		if strings.HasSuffix(strings.ToLower(id), "default") {
			defaults = append(defaults, id)
			continue
		}
		switch strings.ToLower(id) {
		case "pk", "kek", "db", "dbx":
		default:
			continue
		}
		doc, err := p.fetch(ctx, m.ODataID)
		if err != nil {
			p.add("database "+id, report.CheckFail, err.Error())
			continue
		}
		kind := "Certificates"
		if link(doc, "Signatures") != "" && link(doc, "Certificates") == "" {
			kind = "Signatures"
		}
		detail := kind
		if coll := link(doc, kind); coll != "" {
			if list, err := p.c.Members(ctx, coll); err == nil {
				detail = fmt.Sprintf("%s: %d", kind, len(list))
			} else {
				detail = kind + ": " + err.Error()
			}
		}
		actions, _ := doc["Actions"].(map[string]any)
		if reset, ok := actions["#SecureBootDatabase.ResetKeys"].(map[string]any); ok {
			var vals []string
			if allowed, ok := reset["ResetKeysType@Redfish.AllowableValues"].([]any); ok {
				for _, v := range allowed {
					if s, ok := v.(string); ok {
						vals = append(vals, s)
					}
				}
			}
			detail += "; ResetKeys: " + strings.Join(vals, ", ")
		} else {
			detail += "; no ResetKeys action"
		}
		p.add("database "+id, report.CheckOK, detail)
	}
	if len(defaults) > 0 {
		p.add("default databases", report.CheckOK, strings.Join(defaults, ", "))
	} else {
		p.add("default databases", report.CheckAbsent, "no *Default database is exposed")
	}
}
