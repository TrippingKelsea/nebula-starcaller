package server_test

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	archsqlite "github.com/TrippingKelsea/nebula-starcaller/internal/archive/sqlite"
	"github.com/TrippingKelsea/nebula-starcaller/internal/auth"
	"github.com/TrippingKelsea/nebula-starcaller/internal/bundle"
	"github.com/TrippingKelsea/nebula-starcaller/internal/ca"
	"github.com/TrippingKelsea/nebula-starcaller/internal/cert"
	"github.com/TrippingKelsea/nebula-starcaller/internal/config"
	"github.com/TrippingKelsea/nebula-starcaller/internal/nebulax"
	"github.com/TrippingKelsea/nebula-starcaller/internal/server"
	storesqlite "github.com/TrippingKelsea/nebula-starcaller/internal/store/sqlite"
	"github.com/TrippingKelsea/nebula-starcaller/web"
)

func newTestServer(t *testing.T) (*httptest.Server, *storesqlite.Store) {
	t.Helper()
	s, err := storesqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	arch := archsqlite.New(s.DB())
	fake := nebulax.NewFake()

	if err := auth.EnsureBootstrap(context.Background(), s, config.Bootstrap{
		Username: "admin", Password: "supersecret",
	}); err != nil {
		t.Fatal(err)
	}

	casvc := &ca.Service{Store: s, Archive: arch, Runner: fake}
	b := &bundle.Builder{Binaries: bundle.StubProvider{}}
	certsvc := &cert.Service{Store: s, Archive: arch, Runner: fake, CAService: casvc, Bundle: b}
	sessions := auth.NewSessionManager(s, "starcaller_test", 30*time.Minute, false)

	srv, err := server.New(&server.Server{
		Store: s, Sessions: sessions, CA: casvc, Cert: certsvc,
	}, server.Assets{Templates: web.Templates, Static: web.Static})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)
	return ts, s
}

func newClient(t *testing.T) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't auto-follow
		},
	}
}

func login(t *testing.T, ts *httptest.Server, c *http.Client, user, pass string) {
	t.Helper()
	form := url.Values{"username": {user}, "password": {pass}}
	resp, err := c.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("login: status %d body=%s", resp.StatusCode, body)
	}
}

func TestUnauthenticatedRedirectsToLogin(t *testing.T) {
	ts, _ := newTestServer(t)
	c := newClient(t)
	resp, err := c.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("expected redirect, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Errorf("expected redirect to /login, got %q", loc)
	}
}

func TestLoginFlow(t *testing.T) {
	ts, _ := newTestServer(t)
	c := newClient(t)

	// Bad creds
	resp, _ := c.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"wrong"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("bad login should render form (200), got %d", resp.StatusCode)
	}

	// Good creds
	login(t, ts, c, "admin", "supersecret")

	// Now dashboard should render
	resp, _ = c.Get(ts.URL + "/")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("dashboard: %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "Certificate Authorities") {
		t.Errorf("dashboard content missing; body: %s", body)
	}
}

func TestCACreateFlow(t *testing.T) {
	ts, s := newTestServer(t)
	c := newClient(t)
	login(t, ts, c, "admin", "supersecret")

	form := url.Values{
		"name":     {"prod-root"},
		"curve":    {"P256"},
		"networks": {"10.42.0.0/16"},
		"groups":   {"servers\nworkstations"},
		"duration":    {"8760h"},
		"default_ttl": {"720h"},
	}
	resp, err := c.PostForm(ts.URL+"/ca", form)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected redirect after CA create, got %d body=%s", resp.StatusCode, body)
	}
	resp.Body.Close()

	cas, _ := s.ListCAs(context.Background())
	if len(cas) != 1 || cas[0].Name != "prod-root" {
		t.Errorf("expected 1 CA named prod-root, got %+v", cas)
	}
	// Redirect target should be the detail page
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/ca/") {
		t.Errorf("unexpected redirect: %q", loc)
	}
	// Follow it
	resp2, _ := c.Get(ts.URL + loc)
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if !strings.Contains(string(body), "prod-root") {
		t.Errorf("detail page missing name; body: %s", body)
	}
}

func TestCertIssueAndDownload(t *testing.T) {
	ts, s := newTestServer(t)
	c := newClient(t)
	login(t, ts, c, "admin", "supersecret")

	// Create CA first
	_, err := c.PostForm(ts.URL+"/ca", url.Values{
		"name":     {"r"},
		"networks": {"10.42.0.0/16"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cas, _ := s.ListCAs(context.Background())
	caID := cas[0].ID

	// Issue a cert
	resp, err := c.PostForm(ts.URL+"/ca/"+caID+"/certs", url.Values{
		"name":     {"web-01"},
		"networks": {"10.42.0.5/16"},
		"host_role": {"host"},
		"os":       {"linux"},
		"arch":     {"amd64"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected redirect after issue, got %d body=%s", resp.StatusCode, body)
	}
	resp.Body.Close()

	certs, _ := s.ListCerts(context.Background(), caID)
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	certID := certs[0].ID

	// Download bundle
	resp, err = c.Get(ts.URL + "/certs/" + certID + "/bundle")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download: got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/gzip" {
		t.Errorf("expected application/gzip, got %q", got)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Disposition"), `attachment; filename="starcaller-web-01-`) {
		t.Errorf("bad content disposition: %q", resp.Header.Get("Content-Disposition"))
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Error("empty bundle")
	}
	// gzip magic bytes
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		t.Errorf("bundle is not gzip: %x", body[:4])
	}
}

func TestBlocklistEndpoint(t *testing.T) {
	ts, s := newTestServer(t)
	c := newClient(t)
	login(t, ts, c, "admin", "supersecret")

	_, _ = c.PostForm(ts.URL+"/ca", url.Values{"name": {"r"}, "networks": {"10.0.0.0/16"}})
	cas, _ := s.ListCAs(context.Background())
	caID := cas[0].ID

	resp, err := c.Get(ts.URL + "/ca/" + caID + "/blocklist")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("blocklist: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "pki:") {
		t.Errorf("expected YAML output, got %q", body)
	}
}

func TestHealthz(t *testing.T) {
	ts, _ := newTestServer(t)
	c := newClient(t)
	resp, _ := c.Get(ts.URL + "/healthz")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Errorf("healthz: got %q", body)
	}
}

func TestLogout(t *testing.T) {
	ts, _ := newTestServer(t)
	c := newClient(t)
	login(t, ts, c, "admin", "supersecret")
	resp, _ := c.PostForm(ts.URL+"/logout", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("logout redirect: %d", resp.StatusCode)
	}
	// Subsequent request should redirect to login
	resp, _ = c.Get(ts.URL + "/")
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Errorf("expected unauth after logout, got %d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
}
