// Package redfish is a small Redfish (DMTF DSP0266) HTTP client: sessions,
// link discovery, PATCH with ETag retry, multipart upload, ExtendedInfo
// parsing and task monitoring.
package redfish

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"strings"
	"time"
)

const rootPath = "/redfish/v1/"

// Options tunes a Client. Zero values select the defaults noted below.
type Options struct {
	Timeout      time.Duration // per request, default 30s
	TaskTimeout  time.Duration // task polling budget, default 120s
	PollInterval time.Duration // task polling interval, default 2s
	VerifyTLS    bool          // false: accept self-signed BMC certificates
	CAFile       string        // PEM bundle; implies verification
	NoWait       bool          // do not follow asynchronous tasks
	Retries      int           // extra attempts on transient errors, default 0
	RetryDelay   time.Duration // first backoff step (doubles each time), default 500ms
}

// Link is a Redfish {"@odata.id": ...} reference.
type Link struct {
	ODataID string `json:"@odata.id"`
}

// Root is the part of the service root the tool needs.
type Root struct {
	Vendor  string `json:"Vendor"`
	Product string `json:"Product"`
	Links   struct {
		Sessions Link `json:"Sessions"`
	} `json:"Links"`
	Systems  Link `json:"Systems"`
	Managers Link `json:"Managers"`
}

// ManagerInfo describes the BMC itself.
type ManagerInfo struct{ Model, FirmwareVersion string }

// Response is a completed HTTP exchange.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

const (
	maxBody      = 8 << 20 // larger responses are cut off
	maxErrorBody = 512     // error text kept in reports
)

// HTTPError is returned for any status other than 200, 201, 202 or 204.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, e.Body) }

// Client talks to one BMC. It is not safe for concurrent use.
type Client struct {
	base, user, pass string
	opts             Options
	hc               *http.Client
	token, session   string
	root             *Root
	system           string
}

// New builds a client. host may be "1.2.3.4", "1.2.3.4:8443" or a full URL.
func New(host, user, pass string, opts Options) (*Client, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.TaskTimeout == 0 {
		opts.TaskTimeout = 120 * time.Second
	}
	if opts.PollInterval == 0 {
		opts.PollInterval = 2 * time.Second
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: !opts.VerifyTLS && opts.CAFile == ""} //nolint:gosec // BMCs are self-signed; opt-in verification
	if opts.CAFile != "" {
		pem, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificate found in %s", opts.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	base := host
	if !strings.Contains(host, "://") {
		base = "https://" + host
	}
	return &Client{
		base: strings.TrimRight(base, "/"), user: user, pass: pass, opts: opts,
		hc: &http.Client{Transport: tr, Timeout: opts.Timeout,
			// Never follow redirects: they could carry the session token or the login
			// body to another host. A 3xx surfaces as an HTTPError.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

// NoWait reports whether asynchronous tasks must not be followed.
func (c *Client) NoWait() bool { return c.opts.NoWait }

// resolve turns a path or absolute URL into a URL on this client's BMC.
// An absolute URL is rewritten to its path so tokens never leave the BMC host.
func (c *Client) resolve(path string) string {
	if strings.Contains(path, "://") {
		if u, err := url.Parse(path); err == nil {
			path = u.RequestURI()
		}
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return c.base + path
}

// Do sends a request with the session token (or Basic credentials). Non-2xx
// answers return both the Response and an *HTTPError.
func (c *Client) Do(ctx context.Context, method, path string, header http.Header, body []byte) (*Response, error) {
	return c.do(ctx, method, path, header, body, true)
}

// do retries transient failures: connection resets on reads (never on writes,
// which may already have been applied) and explicit "BMC busy" refusals. It never
// retries authentication or certificate errors.
// maxRetryDelay caps the exponential backoff (a variable so tests can shorten it).
var maxRetryDelay = 30 * time.Second

func (c *Client) do(ctx context.Context, method, path string, header http.Header, body []byte, auth bool) (*Response, error) {
	delay := c.opts.RetryDelay
	if delay <= 0 {
		delay = 500 * time.Millisecond
	}
	for attempt := 0; ; attempt++ {
		resp, err := c.attempt(ctx, method, path, header, body, auth)
		if err == nil || attempt >= c.opts.Retries || !retryable(ctx, method, err) {
			return resp, err
		}
		slog.Debug("retrying after transient error", "method", method, "path", path, "attempt", attempt+1, "err", err)
		select {
		case <-ctx.Done():
			return resp, err
		case <-time.After(delay):
		}
		delay = min(delay*2, maxRetryDelay)
	}
}

func retryable(ctx context.Context, method string, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	var he *HTTPError
	if errors.As(err, &he) {
		return strings.Contains(he.Body, "ActionParameterValueConflict") ||
			strings.Contains(he.Body, "UnableToModifyDuringSystemPOST")
	}
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	var ne net.Error
	var cert *tls.CertificateVerificationError
	return errors.As(err, &ne) && !ne.Timeout() && !errors.As(err, &cert)
}

func (c *Client) attempt(ctx context.Context, method, path string, header http.Header, body []byte, auth bool) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.resolve(path), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	for k, vs := range header {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if auth {
		if c.token != "" {
			req.Header.Set("X-Auth-Token", c.token)
		} else {
			req.SetBasicAuth(c.user, c.pass)
		}
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	r := &Response{Status: resp.StatusCode, Header: resp.Header, Body: data}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent:
		return r, nil
	}
	text := string(data)
	if len(text) > maxErrorBody {
		text = text[:maxErrorBody] + "…"
	}
	return r, &HTTPError{Status: resp.StatusCode, Body: text}
}

// GetJSON GETs path and decodes the JSON body into out.
func (c *Client) GetJSON(ctx context.Context, path string, out any) error {
	resp, err := c.Do(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(resp.Body, out); err != nil {
		return fmt.Errorf("JSON decode error: %w", err)
	}
	return nil
}

// SendJSON sends payload as JSON with the given method.
func (c *Client) SendJSON(ctx context.Context, method, path string, payload any) (*Response, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return c.Do(ctx, method, path, http.Header{"Content-Type": {"application/json"}}, b)
}

// Patch sends a JSON PATCH; on 428 Precondition Required it re-reads the
// resource, takes its ETag and retries once with If-Match.
func (c *Client) Patch(ctx context.Context, path string, payload any) (*Response, error) {
	resp, err := c.SendJSON(ctx, http.MethodPatch, path, payload)
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusPreconditionRequired {
		return resp, err
	}
	get, gerr := c.Do(ctx, http.MethodGet, path, nil, nil)
	if gerr != nil || get.Header.Get("ETag") == "" {
		return resp, err
	}
	b, _ := json.Marshal(payload)
	return c.Do(ctx, http.MethodPatch, path, http.Header{
		"Content-Type": {"application/json"}, "If-Match": {get.Header.Get("ETag")}}, b)
}

// Upload POSTs data as a multipart/form-data file part named field.
func (c *Client) Upload(ctx context.Context, path, field, filename string, data []byte) (*Response, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q; filename=%q`, field, filename))
	h.Set("Content-Type", "application/octet-stream")
	part, err := mw.CreatePart(h)
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(data); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	return c.Do(ctx, http.MethodPost, path, http.Header{"Content-Type": {mw.FormDataContentType()}}, buf.Bytes())
}

// Root returns the (cached) service root.
func (c *Client) Root(ctx context.Context) (*Root, error) {
	if c.root != nil {
		return c.root, nil
	}
	var r Root
	if err := c.GetJSON(ctx, rootPath, &r); err != nil {
		return nil, fmt.Errorf("service root: %w", err)
	}
	c.root = &r
	return c.root, nil
}

// Login opens a Redfish session. When the BMC refuses sessions (401, 403, 404,
// 405) the client stays on HTTP Basic and Login returns nil.
func (c *Client) Login(ctx context.Context) error {
	root, err := c.Root(ctx)
	if err != nil {
		return err
	}
	sessions := root.Links.Sessions.ODataID
	if sessions == "" {
		sessions = "/redfish/v1/SessionService/Sessions" // last-resort fallback
	}
	payload, err := json.Marshal(map[string]string{"UserName": c.user, "Password": c.pass})
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodPost, sessions, http.Header{"Content-Type": {"application/json"}}, payload, false)
	if err != nil {
		var he *HTTPError
		if errors.As(err, &he) {
			switch he.Status {
			case 401, 403, 404, 405:
				return nil
			}
		}
		return err
	}
	if tok := resp.Header.Get("X-Auth-Token"); tok != "" {
		c.token = tok
		c.session = resp.Header.Get("Location")
		if c.session == "" {
			var doc struct {
				ID string `json:"@odata.id"`
			}
			if json.Unmarshal(resp.Body, &doc) == nil {
				c.session = doc.ID
			}
		}
	}
	return nil
}

// Logout closes the session opened by Login, if any. Errors are ignored.
func (c *Client) Logout(ctx context.Context) {
	if c.session == "" {
		return
	}
	_, _ = c.do(ctx, http.MethodDelete, c.session, nil, nil, true)
	c.token, c.session = "", ""
}

type collection struct {
	Members []Link `json:"Members"`
}

// Members lists the members of a Redfish collection.
func (c *Client) Members(ctx context.Context, path string) ([]Link, error) {
	var col collection
	if err := c.GetJSON(ctx, path, &col); err != nil {
		return nil, err
	}
	return col.Members, nil
}

// SystemPath returns the URI of the first computer system, discovered from the root.
func (c *Client) SystemPath(ctx context.Context) (string, error) {
	if c.system != "" {
		return c.system, nil
	}
	root, err := c.Root(ctx)
	if err != nil {
		return "", err
	}
	coll := root.Systems.ODataID
	if coll == "" {
		coll = "/redfish/v1/Systems" // last-resort fallback
	}
	members, err := c.Members(ctx, coll)
	if err != nil {
		return "", fmt.Errorf("systems: %w", err)
	}
	if len(members) == 0 || members[0].ODataID == "" {
		return "", errors.New("no computer system found")
	}
	c.system = members[0].ODataID
	return c.system, nil
}

// Manager returns the BMC manager's model and firmware version.
func (c *Client) Manager(ctx context.Context) (ManagerInfo, error) {
	root, err := c.Root(ctx)
	if err != nil {
		return ManagerInfo{}, err
	}
	coll := root.Managers.ODataID
	if coll == "" {
		coll = "/redfish/v1/Managers" // last-resort fallback
	}
	members, err := c.Members(ctx, coll)
	if err != nil {
		return ManagerInfo{}, fmt.Errorf("managers: %w", err)
	}
	var first *ManagerInfo
	for _, m := range members {
		var doc struct {
			ManagerType     string `json:"ManagerType"`
			Model           string `json:"Model"`
			FirmwareVersion string `json:"FirmwareVersion"`
		}
		if err := c.GetJSON(ctx, m.ODataID, &doc); err != nil {
			continue
		}
		info := ManagerInfo{Model: doc.Model, FirmwareVersion: doc.FirmwareVersion}
		if doc.ManagerType == "BMC" {
			return info, nil
		}
		if first == nil {
			first = &info
		}
	}
	if first != nil {
		return *first, nil
	}
	return ManagerInfo{}, errors.New("no manager found")
}
