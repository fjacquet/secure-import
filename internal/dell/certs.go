package dell

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
	"sbmgr/internal/stdsb"
)

// dbStore returns the OEM "DB" certificate store URI: the Dell certificates link
// of the SecureBoot resource, else <SecureBoot>/Oem/Dell/Certificates (fallback).
func (d *Driver) dbStore(ctx context.Context) (string, error) {
	doc, err := d.h.Get(ctx)
	if err != nil {
		return "", err
	}
	base := doc.Oem.Dell.Certificates.ODataID
	if base == "" {
		sb, err := d.h.Path(ctx)
		if err != nil {
			return "", err
		}
		base = sb + "/Oem/Dell/Certificates"
	}
	return base + "/DB", nil
}

// DBList lists the "db" certificates. With the standard method it asks the DMTF
// collection first and falls back to the Dell OEM store when that fails.
func (d *Driver) DBList(ctx context.Context) ([]platform.Cert, error) {
	if d.standardOnly() {
		return d.std.DBList(ctx)
	}
	if d.method == "standard" {
		certs, err := d.std.DBList(ctx)
		if err == nil {
			return certs, nil
		}
		slog.Debug("standard db listing failed, falling back to the Dell OEM store", "err", err)
	}
	return d.oemList(ctx)
}

func (d *Driver) oemList(ctx context.Context) ([]platform.Cert, error) {
	store, err := d.dbStore(ctx)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Certificates []redfish.Link `json:"Certificates"`
		Hash         []redfish.Link `json:"Hash"`
	}
	if err := d.c.GetJSON(ctx, store, &doc); err != nil {
		return nil, err
	}
	links := doc.Certificates
	if len(links) == 0 {
		links = doc.Hash
	}
	certs := make([]platform.Cert, len(links))
	for i, l := range links {
		certs[i] = platform.Cert{URI: l.ODataID}
	}
	return certs, nil
}

// DBImport enrols a certificate file: by the standard POST when method is
// "standard", else as a multipart upload to the Dell OEM store.
func (d *Driver) DBImport(ctx context.Context, file string) (platform.Change, error) {
	if d.method == "standard" || d.standardOnly() {
		return d.std.DBImport(ctx, file)
	}
	data, err := stdsb.ReadCertFile(file)
	if err != nil {
		return platform.Change{}, err
	}
	if _, err := stdsb.ToPEM(data); err != nil {
		return platform.Change{}, err
	}
	store, err := d.dbStore(ctx)
	if err != nil {
		return platform.Change{}, err
	}
	if uri, ok := d.oemHas(ctx, data); ok {
		return platform.Change{Message: "Certificate already present (" + uri + "), nothing imported"}, nil
	}
	resp, err := d.c.Upload(ctx, store+"/", "file", filepath.Base(file), data)
	if err != nil {
		return platform.Change{}, err
	}
	msgs := redfish.ParseMessages(resp.Body)
	if _, bad := redfish.FirstCritical(msgs); bad {
		return platform.Change{}, fmt.Errorf("certificate import refused. Messages: %s", redfish.Summarize(msgs))
	}
	restart := ""
	if redfish.NeedsReboot(msgs) {
		restart = " (Reboot required to take effect)"
	}
	return platform.Change{
		Message:        fmt.Sprintf("Certificate import successful%s. Messages: %s", restart, redfish.Summarize(msgs)),
		RebootRequired: redfish.NeedsReboot(msgs),
	}, nil
}

// DBExport saves the certificate at uri to file.
func (d *Driver) DBExport(ctx context.Context, uri, file string) (platform.Change, error) {
	resp, err := d.c.Do(ctx, http.MethodGet, uri, http.Header{"Accept": {"application/octet-stream"}}, nil)
	if err != nil {
		return platform.Change{}, err
	}
	body := resp.Body
	if t := bytes.TrimSpace(body); len(t) > 0 && t[0] == '{' { // iDRAC10: a JSON Certificate resource
		var doc struct {
			CertificateString string
		}
		if json.Unmarshal(body, &doc) != nil || doc.CertificateString == "" {
			return platform.Change{}, fmt.Errorf("%s does not return the certificate itself, only metadata", uri)
		}
		body = []byte(doc.CertificateString)
	}
	if len(body) == 0 {
		return platform.Change{}, fmt.Errorf("exported certificate is empty: %s", uri)
	}
	if err := writeFileAtomic(file, body); err != nil {
		return platform.Change{}, fmt.Errorf("failed to save certificate: %w", err)
	}
	return platform.Change{Message: "DB certificate exported to " + file}, nil
}

// DBDelete removes the certificate at uri.
func (d *Driver) DBDelete(ctx context.Context, uri string) (platform.Change, error) {
	resp, err := d.c.Do(ctx, http.MethodDelete, uri, nil, nil)
	if err != nil {
		return platform.Change{}, err
	}
	if msgs := redfish.ParseMessages(resp.Body); len(msgs) > 0 {
		if _, bad := redfish.FirstCritical(msgs); bad {
			return platform.Change{}, fmt.Errorf("certificate deletion refused. Messages: %s", redfish.Summarize(msgs))
		}
	}
	return platform.Change{Message: "DB certificate deleted successfully"}, nil
}

// oemHas reports whether the OEM store already holds every certificate of data.
// The store lists opaque entries, so each one is downloaded and compared by hash;
// an entry that cannot be read is ignored (the import then goes ahead).
func (d *Driver) oemHas(ctx context.Context, data []byte) (string, bool) {
	listed, err := d.oemList(ctx)
	if err != nil {
		return "", false
	}
	for i, c := range listed {
		resp, err := d.c.Do(ctx, http.MethodGet, c.URI, http.Header{"Accept": {"application/octet-stream"}}, nil)
		if err != nil {
			continue
		}
		if fps, err := stdsb.CertSHA256s(resp.Body); err == nil && len(fps) > 0 {
			listed[i].PEM = string(pemOf(resp.Body))
		}
	}
	return stdsb.AlreadyPresent(listed, data)
}

func pemOf(b []byte) []byte {
	p, err := stdsb.ToPEM(b)
	if err != nil {
		return nil
	}
	return p
}

// writeFileAtomic writes through a temporary file in the same directory and renames
// it, so an interrupted run never leaves a truncated certificate. The file is 0600.
func writeFileAtomic(file string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(file), ".sbmgr-export-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), file)
}
