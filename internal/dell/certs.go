package dell

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
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
	if d.method == "standard" {
		return d.std.DBImport(ctx, file)
	}
	data, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return platform.Change{}, fmt.Errorf("certificate file not found: %s", file)
	}
	if err != nil {
		return platform.Change{}, fmt.Errorf("read certificate file: %w", err)
	}
	if len(data) == 0 {
		return platform.Change{}, fmt.Errorf("certificate file is empty: %s", file)
	}
	store, err := d.dbStore(ctx)
	if err != nil {
		return platform.Change{}, err
	}
	resp, err := d.c.Upload(ctx, store+"/", "file", filepath.Base(file), data)
	if err != nil {
		return platform.Change{}, err
	}
	msgs := redfish.ParseMessages(resp.Body)
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
	if len(resp.Body) == 0 {
		return platform.Change{}, fmt.Errorf("exported certificate is empty: %s", uri)
	}
	if err := os.WriteFile(file, resp.Body, 0o644); err != nil {
		return platform.Change{}, fmt.Errorf("failed to save certificate: %w", err)
	}
	return platform.Change{Message: "DB certificate exported to " + file}, nil
}

// DBDelete removes the certificate at uri.
func (d *Driver) DBDelete(ctx context.Context, uri string) (platform.Change, error) {
	if _, err := d.c.Do(ctx, http.MethodDelete, uri, nil, nil); err != nil {
		return platform.Change{}, err
	}
	return platform.Change{Message: "DB certificate deleted successfully"}, nil
}
