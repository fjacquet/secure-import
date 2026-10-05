package redfish

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sbmgr/internal/testbmc"
)

func newClient(t *testing.T, s *testbmc.Server, opts Options) *Client {
	t.Helper()
	c, err := New(s.URL, "root", "pw", opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoginUsesSessionTokenAndLogoutDeletesSession(t *testing.T) {
	s := testbmc.New(t)
	s.Redfish("Dell", "S1", "16G", "7.0.0.0")
	c := newClient(t, s, Options{})
	ctx := context.Background()
	if err := c.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(ctx, http.MethodGet, "/redfish/v1/Systems", nil, nil); err != nil {
		t.Fatal(err)
	}
	reqs := s.Requests()
	for _, r := range reqs {
		if r.Method == "POST" && r.Header.Get("Authorization") != "" {
			t.Error("session creation must not carry Basic credentials")
		}
	}
	last := reqs[len(reqs)-1]
	if last.Header.Get("X-Auth-Token") != "tok" || last.Header.Get("Authorization") != "" {
		t.Errorf("after login want X-Auth-Token only, got headers %v", last.Header)
	}
	c.Logout(ctx)
	if n := s.Count("DELETE", "/redfish/v1/SessionService/Sessions/1"); n != 1 {
		t.Errorf("session DELETE count = %d, want 1", n)
	}
}

func TestLoginFallsBackToBasic(t *testing.T) {
	s := testbmc.New(t)
	s.Redfish("Dell", "S1", "16G", "7.0.0.0")
	s.JSON("POST", "/redfish/v1/SessionService/Sessions", 404, nil)
	c := newClient(t, s, Options{})
	ctx := context.Background()
	if err := c.Login(ctx); err != nil {
		t.Fatalf("Login should fall back to Basic, got %v", err)
	}
	if _, err := c.Do(ctx, http.MethodGet, "/redfish/v1/Systems", nil, nil); err != nil {
		t.Fatal(err)
	}
	reqs := s.Requests()
	if got := reqs[len(reqs)-1].Header.Get("Authorization"); !strings.HasPrefix(got, "Basic ") {
		t.Errorf("Authorization = %q, want Basic", got)
	}
	c.Logout(ctx)
	if n := s.Count("DELETE", "/redfish/v1/SessionService/Sessions/1"); n != 0 {
		t.Errorf("no session was opened, DELETE count = %d", n)
	}
}

func TestDoReturnsHTTPErrorWithBody(t *testing.T) {
	s := testbmc.New(t)
	s.JSON("GET", "/x", 500, map[string]string{"error": "boom"})
	c := newClient(t, s, Options{})
	resp, err := c.Do(context.Background(), http.MethodGet, "/x", nil, nil)
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 500 || !strings.Contains(he.Error(), "boom") {
		t.Fatalf("err = %v, want HTTPError 500 containing boom", err)
	}
	if resp == nil || resp.Status != 500 {
		t.Errorf("response should accompany the error, got %+v", resp)
	}
}

func TestPatchRetriesWithETagOn428(t *testing.T) {
	s := testbmc.New(t)
	var patches atomic.Int32
	s.Handle("PATCH", "/x", func(w http.ResponseWriter, r *http.Request) {
		patches.Add(1)
		if r.Header.Get("If-Match") != `"abc"` {
			testbmc.WriteJSON(w, 428, nil)
			return
		}
		testbmc.WriteJSON(w, 200, map[string]any{})
	})
	s.Handle("GET", "/x", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"abc"`)
		testbmc.WriteJSON(w, 200, map[string]any{})
	})
	c := newClient(t, s, Options{})
	if _, err := c.Patch(context.Background(), "/x", map[string]bool{"a": true}); err != nil {
		t.Fatal(err)
	}
	if patches.Load() != 2 {
		t.Errorf("PATCH attempts = %d, want 2", patches.Load())
	}
}

func TestUploadSendsMultipartFileField(t *testing.T) {
	s := testbmc.New(t)
	got := make(chan [2]string, 1)
	s.Handle("POST", "/up", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			testbmc.WriteJSON(w, 400, nil)
			return
		}
		f, h, err := r.FormFile("file")
		if err != nil {
			testbmc.WriteJSON(w, 400, nil)
			return
		}
		b, _ := io.ReadAll(f)
		got <- [2]string{h.Filename, string(b)}
		testbmc.WriteJSON(w, 200, map[string]any{})
	})
	c := newClient(t, s, Options{})
	if _, err := c.Upload(context.Background(), "/up", "file", "cert.der", []byte("DER")); err != nil {
		t.Fatal(err)
	}
	if v := <-got; v[0] != "cert.der" || v[1] != "DER" {
		t.Errorf("got %v", v)
	}
}

func TestAbsoluteURLIsRewrittenToBaseHost(t *testing.T) {
	s := testbmc.New(t)
	s.Redfish("Dell", "S1", "16G", "7.0.0.0")
	c := newClient(t, s, Options{})
	if _, err := c.Do(context.Background(), http.MethodGet, "https://evil.example/redfish/v1/Systems", nil, nil); err != nil {
		t.Fatalf("absolute URL must be sent to the BMC host, got %v", err)
	}
}

func TestSystemPathAndManager(t *testing.T) {
	s := testbmc.New(t)
	s.Redfish("Dell", "System.Embedded.1", "17G Monolithic", "1.30.60.50")
	c := newClient(t, s, Options{})
	ctx := context.Background()
	sys, err := c.SystemPath(ctx)
	if err != nil || sys != "/redfish/v1/Systems/System.Embedded.1" {
		t.Fatalf("SystemPath = %q, %v", sys, err)
	}
	m, err := c.Manager(ctx)
	if err != nil || m.Model != "17G Monolithic" || m.FirmwareVersion != "1.30.60.50" {
		t.Fatalf("Manager = %+v, %v", m, err)
	}
}

func TestSanitizePath(t *testing.T) {
	cases := map[string]string{
		"":              "",
		"/redfish/v1/x": "/redfish/v1/x",
		"redfish/v1/x":  "/redfish/v1/x",
		"C:/Program Files/Git/redfish/v1/Systems/S/SecureBoot/Certificates/DB/Cust.7": "/redfish/v1/Systems/S/SecureBoot/Certificates/DB/Cust.7",
		`C:\Program Files\Git\redfish\v1\x`:                                           "/redfish/v1/x",
	}
	for in, want := range cases {
		if got := SanitizePath(in); got != want {
			t.Errorf("SanitizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	other := testbmc.New(t)
	s := testbmc.New(t)
	s.Redfish("Dell", "S1", "16G", "7.0.0.0")
	s.JSONH("GET", "/redfish/v1/Systems", 302, map[string]string{"Location": other.URL + "/leak"}, nil)
	c := newClient(t, s, Options{})
	if err := c.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(context.Background(), http.MethodGet, "/redfish/v1/Systems", nil, nil); err == nil {
		t.Error("a redirect must be an error")
	}
	if len(other.Requests()) != 0 {
		t.Error("the redirect target must never be contacted")
	}
}

func TestLogoutUsesSessionIDFromBodyWhenNoLocation(t *testing.T) {
	s := testbmc.New(t)
	s.Redfish("Dell", "S1", "16G", "7.0.0.0")
	s.JSONH("POST", "/redfish/v1/SessionService/Sessions", 201, map[string]string{"X-Auth-Token": "tok"},
		map[string]any{"@odata.id": "/redfish/v1/SessionService/Sessions/9"})
	s.JSON("DELETE", "/redfish/v1/SessionService/Sessions/9", 204, nil)
	c := newClient(t, s, Options{})
	if err := c.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Logout(context.Background())
	if s.Count("DELETE", "/redfish/v1/SessionService/Sessions/9") != 1 {
		t.Error("session must be deleted using the body's @odata.id")
	}
}

func TestHTTPErrorBodyIsTruncated(t *testing.T) {
	s := testbmc.New(t)
	s.Redfish("Dell", "S1", "16G", "7.0.0.0")
	s.Handle("GET", "/big", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(strings.Repeat("x", 100000)))
	})
	c := newClient(t, s, Options{})
	_, err := c.Do(context.Background(), http.MethodGet, "/big", nil, nil)
	if err == nil || len(err.Error()) > 1000 {
		t.Errorf("err length = %d", len(err.Error()))
	}
}

func dropFirst(n *atomic.Int32, ok func(http.ResponseWriter)) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) == 1 {
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close() // connection reset before any answer
			return
		}
		ok(w)
	}
}

func TestRetriesConnectionErrorsOnReads(t *testing.T) {
	s := testbmc.New(t)
	s.Redfish("Dell", "S1", "16G", "7.0.0.0")
	var n atomic.Int32
	s.Handle("GET", "/r", dropFirst(&n, func(w http.ResponseWriter) { testbmc.WriteJSON(w, 200, map[string]any{}) }))
	c := newClient(t, s, Options{Retries: 2, RetryDelay: time.Millisecond})
	if _, err := c.Do(context.Background(), http.MethodGet, "/r", nil, nil); err != nil || n.Load() != 2 {
		t.Errorf("err = %v, attempts = %d", err, n.Load())
	}
}

func TestDoesNotRetryWritesAfterConnectionError(t *testing.T) {
	s := testbmc.New(t)
	s.Redfish("Dell", "S1", "16G", "7.0.0.0")
	var n atomic.Int32
	s.Handle("POST", "/w", dropFirst(&n, func(w http.ResponseWriter) { testbmc.WriteJSON(w, 200, map[string]any{}) }))
	c := newClient(t, s, Options{Retries: 2, RetryDelay: time.Millisecond})
	if _, err := c.Do(context.Background(), http.MethodPost, "/w", nil, []byte("{}")); err == nil || n.Load() != 1 {
		t.Errorf("err = %v, attempts = %d: a write may have been applied, so it must not be replayed", err, n.Load())
	}
}

func TestRetriesBMCBusyAnswers(t *testing.T) {
	s := testbmc.New(t)
	s.Redfish("Dell", "S1", "16G", "7.0.0.0")
	var n atomic.Int32
	s.Handle("PATCH", "/p", func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) == 1 {
			testbmc.WriteJSON(w, 409, map[string]any{"error": map[string]any{"code": "Base.1.12.ActionParameterValueConflict"}})
			return
		}
		testbmc.WriteJSON(w, 200, map[string]any{})
	})
	c := newClient(t, s, Options{Retries: 2, RetryDelay: time.Millisecond})
	if _, err := c.Do(context.Background(), http.MethodPatch, "/p", nil, []byte("{}")); err != nil || n.Load() != 2 {
		t.Errorf("err = %v, attempts = %d", err, n.Load())
	}
}

func TestDoesNotRetryAuthenticationFailures(t *testing.T) {
	s := testbmc.New(t)
	s.Redfish("Dell", "S1", "16G", "7.0.0.0")
	s.JSON("GET", "/a", 401, map[string]any{})
	c := newClient(t, s, Options{Retries: 3, RetryDelay: time.Millisecond})
	if _, err := c.Do(context.Background(), http.MethodGet, "/a", nil, nil); err == nil || s.Count("GET", "/a") != 1 {
		t.Errorf("err = %v, attempts = %d", err, s.Count("GET", "/a"))
	}
}
