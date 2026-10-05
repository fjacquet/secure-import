// Package stdsb implements the DMTF-standard SecureBoot resources (SecureBoot,
// SecureBootDatabases) shared by several vendors, plus a generic driver.
package stdsb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"slices"
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
	Actions               map[string]struct {
		Target  string   `json:"target"`
		Allowed []string `json:"ResetKeysType@Redfish.AllowableValues"`
	} `json:"Actions"`
	Oem struct {
		Dell struct {
			Certificates redfish.Link `json:"Certificates"`
		} `json:"Dell"`
	} `json:"Oem"`
}

// Helper reads and writes the SecureBoot tree of one BMC.
type Helper struct {
	C      *redfish.Client
	Vendor string // driver name ("ilo", "supermicro"...), used for vendor-specific hints
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
		var he *redfish.HTTPError
		switch {
		case strings.Contains(err.Error(), "OemLicenseNotPassed"):
			return Doc{}, fmt.Errorf("a license is required to use Secure Boot on this BMC (OemLicenseNotPassed): %w", err)
		case h.Vendor == "supermicro" && errors.As(err, &he) && (he.Status == http.StatusForbidden || he.Status == http.StatusNotFound):
			return Doc{}, fmt.Errorf("Secure Boot is not supported or not licensed: the SFT-DCMS-SINGLE license may be missing, or the BMC predates SecureBootDatabases (X13/H13 or newer): %w", err)
		case errors.As(err, &he) && he.Status == http.StatusNotFound:
			return Doc{}, fmt.Errorf("Secure Boot is not supported by this system (no SecureBoot resource): %w", err)
		}
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
		certs[i] = h.certDetails(ctx, m.ODataID)
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

// MaxCertFile caps the size of a certificate file read from disk.
const MaxCertFile = 64 << 10

// ReadCertFile reads a certificate file, refusing missing, empty and oversized files.
func ReadCertFile(file string) ([]byte, error) {
	fi, err := os.Stat(file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("certificate file not found: %s", file)
	}
	if err != nil {
		return nil, fmt.Errorf("read certificate file: %w", err)
	}
	if fi.Size() > MaxCertFile {
		return nil, fmt.Errorf("certificate file is too large: %d bytes (limit %d)", fi.Size(), MaxCertFile)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read certificate file: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("certificate file is empty: %s", file)
	}
	return data, nil
}

// ToPEM returns clean PEM bytes for a PEM or DER X.509 certificate. PEM input
// must hold only CERTIFICATE blocks (a private key is rejected); text around the
// blocks is dropped.
func ToPEM(data []byte) ([]byte, error) {
	if bytes.Contains(data, []byte("-----BEGIN")) {
		var out []byte
		for rest := data; ; {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				return nil, fmt.Errorf("PEM block %q is not a certificate", block.Type)
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return nil, fmt.Errorf("not a valid certificate: %w", err)
			}
			out = append(out, pem.EncodeToMemory(block)...)
		}
		if out == nil {
			return nil, fmt.Errorf("no valid PEM certificate found")
		}
		return out, nil
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("not a PEM or DER certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), nil
}

// DERLen returns the largest DER size among the certificates in pemBytes, or 0.
func DERLen(pemBytes []byte) int {
	n := 0
	for rest := pemBytes; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return n
		}
		n = max(n, len(block.Bytes))
	}
}

// certDetails reads the optional fields of one Certificate resource. A member
// that cannot be read is still listed, by URI only.
func (h *Helper) certDetails(ctx context.Context, uri string) platform.Cert {
	c := platform.Cert{URI: uri}
	var d struct {
		CertificateString string
		Fingerprint       string
		Algorithm         string `json:"FingerprintHashAlgorithm"`
		Subject, Issuer   struct{ CommonName string }
		ValidNotAfter     string
	}
	if err := h.C.GetJSON(ctx, uri, &d); err != nil {
		return c
	}
	c.PEM, c.Fingerprint, c.Algorithm = d.CertificateString, d.Fingerprint, d.Algorithm
	c.Subject, c.Issuer = d.Subject.CommonName, d.Issuer.CommonName
	c.NotAfter = d.ValidNotAfter
	if len(c.NotAfter) > 10 {
		c.NotAfter = c.NotAfter[:10]
	}
	return c
}

// CertSHA256s returns the hex SHA-256 of the DER of each certificate in a PEM or
// DER input.
func CertSHA256s(data []byte) ([]string, error) {
	pemBytes, err := ToPEM(data)
	if err != nil {
		return nil, err
	}
	var out []string
	for rest := pemBytes; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out, nil
		}
		sum := sha256.Sum256(block.Bytes)
		out = append(out, hex.EncodeToString(sum[:]))
	}
}

// Matches reports whether a listed certificate has the given SHA-256. It compares
// the certificate text when the BMC returns it, else the Fingerprint field when
// its algorithm is SHA-256; with neither it cannot tell and returns false.
func Matches(c platform.Cert, sha256hex string) bool {
	if c.PEM != "" {
		if fps, err := CertSHA256s([]byte(c.PEM)); err == nil {
			return slices.Contains(fps, sha256hex)
		}
	}
	algo := strings.ToLower(strings.ReplaceAll(c.Algorithm, "-", ""))
	if c.Fingerprint != "" && algo == "sha256" {
		fp := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(c.Fingerprint))
		return fp == sha256hex
	}
	return false
}

// AlreadyPresent returns the URI of a listed certificate holding every
// certificate of the input file, if there is one for each.
func AlreadyPresent(listed []platform.Cert, fileData []byte) (string, bool) {
	fps, err := CertSHA256s(fileData)
	if err != nil || len(fps) == 0 {
		return "", false
	}
	var uri string
	for _, fp := range fps {
		i := slices.IndexFunc(listed, func(c platform.Cert) bool { return Matches(c, fp) })
		if i < 0 {
			return "", false
		}
		uri = listed[i].URI
	}
	return uri, true
}

// ResetKeys runs the SecureBoot.ResetKeys action discovered in the SecureBoot
// resource. resetType must be one of the values the BMC announces, when it
// announces any.
func (h *Helper) ResetKeys(ctx context.Context, resetType string) (*redfish.Response, error) {
	doc, err := h.Get(ctx)
	if err != nil {
		return nil, err
	}
	act, ok := doc.Actions["#SecureBoot.ResetKeys"]
	if !ok || act.Target == "" {
		return nil, errors.New("resetting Secure Boot keys is not supported by this BMC (no ResetKeys action)")
	}
	if len(act.Allowed) > 0 && !slices.Contains(act.Allowed, resetType) {
		return nil, fmt.Errorf("reset type %q is not allowed by this BMC (allowed: %s)", resetType, strings.Join(act.Allowed, ", "))
	}
	return h.C.SendJSON(ctx, http.MethodPost, act.Target, map[string]string{"ResetKeysType": resetType})
}
