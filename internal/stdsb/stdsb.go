// Package stdsb implements the DMTF-standard SecureBoot resources (SecureBoot,
// SecureBootDatabases) shared by several vendors, plus a generic driver.
package stdsb

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"

	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
)

// Doc is the SecureBoot resource.
type Doc struct {
	Name                  string       `json:"Name"`
	Description           string       `json:"Description"`
	SecureBootEnable      bool         `json:"SecureBootEnable"`
	SecureBootCurrentBoot string       `json:"SecureBootCurrentBoot"`
	SecureBootMode        string       `json:"SecureBootMode"`
	SecureBootDatabases   redfish.Link `json:"SecureBootDatabases"`
	Oem                   struct {
		Dell struct {
			Certificates redfish.Link `json:"Certificates"`
		} `json:"Dell"`
	} `json:"Oem"`
}

// Helper reads and writes the SecureBoot tree of one BMC.
type Helper struct {
	C      *redfish.Client
	sbPath string
}

// Path returns the SecureBoot URI, discovered from the computer system.
func (h *Helper) Path(ctx context.Context) (string, error) {
	if h.sbPath != "" {
		return h.sbPath, nil
	}
	sys, err := h.C.SystemPath(ctx)
	if err != nil {
		return "", err
	}
	var doc struct {
		SecureBoot redfish.Link `json:"SecureBoot"`
	}
	if err := h.C.GetJSON(ctx, sys, &doc); err != nil {
		return "", fmt.Errorf("system: %w", err)
	}
	h.sbPath = doc.SecureBoot.ODataID
	if h.sbPath == "" {
		h.sbPath = sys + "/SecureBoot" // last-resort fallback
	}
	return h.sbPath, nil
}

// Get reads the SecureBoot resource.
func (h *Helper) Get(ctx context.Context) (Doc, error) {
	p, err := h.Path(ctx)
	if err != nil {
		return Doc{}, err
	}
	var doc Doc
	if err := h.C.GetJSON(ctx, p, &doc); err != nil {
		return Doc{}, err
	}
	return doc, nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// Status maps the SecureBoot resource to a platform.Status (Policy "N/A").
func (h *Helper) Status(ctx context.Context) (platform.Status, error) {
	doc, err := h.Get(ctx)
	if err != nil {
		return platform.Status{}, err
	}
	return platform.Status{
		Name: doc.Name, Description: doc.Description, Enabled: doc.SecureBootEnable,
		CurrentBoot: orDefault(doc.SecureBootCurrentBoot, "Unknown"),
		Mode:        orDefault(doc.SecureBootMode, "Unknown"),
		Policy:      "N/A", CertificatesURI: doc.Oem.Dell.Certificates.ODataID,
	}, nil
}

// SetEnable PATCHes SecureBootEnable. The change takes effect on next boot.
func (h *Helper) SetEnable(ctx context.Context, enable bool) (*redfish.Response, error) {
	p, err := h.Path(ctx)
	if err != nil {
		return nil, err
	}
	return h.C.Patch(ctx, p, map[string]bool{"SecureBootEnable": enable})
}

// DBPath returns the Certificates collection URI of database id ("db", "KEK"...).
func (h *Helper) DBPath(ctx context.Context, id string) (string, error) {
	doc, err := h.Get(ctx)
	if err != nil {
		return "", err
	}
	dbs := doc.SecureBootDatabases.ODataID
	if dbs == "" {
		return "", errors.New("SecureBootDatabases not exposed by this BMC")
	}
	members, err := h.C.Members(ctx, dbs)
	if err != nil {
		return "", fmt.Errorf("secure boot databases: %w", err)
	}
	for _, m := range members {
		if !strings.EqualFold(path.Base(m.ODataID), id) {
			continue
		}
		var d struct {
			Certificates redfish.Link `json:"Certificates"`
		}
		if err := h.C.GetJSON(ctx, m.ODataID, &d); err != nil {
			return "", err
		}
		if d.Certificates.ODataID != "" {
			return d.Certificates.ODataID, nil
		}
		return m.ODataID + "/Certificates", nil
	}
	return "", fmt.Errorf("secure boot database %q not found", id)
}

// DBCerts lists the certificates of database id.
func (h *Helper) DBCerts(ctx context.Context, id string) ([]platform.Cert, error) {
	p, err := h.DBPath(ctx, id)
	if err != nil {
		return nil, err
	}
	members, err := h.C.Members(ctx, p)
	if err != nil {
		return nil, err
	}
	certs := make([]platform.Cert, len(members))
	for i, m := range members {
		certs[i] = platform.Cert{URI: m.ODataID}
	}
	return certs, nil
}

// ImportPEM enrols a PEM certificate into database id (additive).
func (h *Helper) ImportPEM(ctx context.Context, id string, pemBytes []byte) (*redfish.Response, error) {
	p, err := h.DBPath(ctx, id)
	if err != nil {
		return nil, err
	}
	return h.C.SendJSON(ctx, http.MethodPost, p, map[string]string{
		"CertificateString": string(pemBytes), "CertificateType": "PEM"})
}

// ToPEM returns PEM bytes for a PEM or DER X.509 certificate.
func ToPEM(data []byte) ([]byte, error) {
	if bytes.Contains(data, []byte("-----BEGIN")) {
		return data, nil
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("not a PEM or DER certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), nil
}

// DERLen returns the DER size of the first certificate in pemBytes, or 0.
func DERLen(pemBytes []byte) int {
	if block, _ := pem.Decode(pemBytes); block != nil {
		return len(block.Bytes)
	}
	return 0
}
