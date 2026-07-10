package server_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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

// findNebulaCert duplicated from nebulax_integration_test — internal test packages don't share helpers.
func findNebulaCertE2E() string {
	if v := os.Getenv("NEBULA_CERT_BINARY"); v != "" {
		if fi, err := os.Stat(v); err == nil && !fi.IsDir() {
			return v
		}
	}
	if v := os.Getenv("NEBULA_VERSION"); v != "" {
		home, _ := os.UserHomeDir()
		p := filepath.Join(home, "Home-Lab/bin/Nebula", v, "nebula-cert")
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	for _, c := range []string{"/usr/local/bin/nebula-cert", "/usr/bin/nebula-cert"} {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}

// TestFullStack_RealNebulaCert exercises the entire stack (HTTP -> service ->
// real nebula-cert binary -> archived bundle -> download) against a live
// nebula-cert. Skipped when the binary is not available.
func TestFullStack_RealNebulaCert(t *testing.T) {
	bin := findNebulaCertE2E()
	if bin == "" {
		t.Skip("nebula-cert not available for e2e test")
	}

	s, err := storesqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	arch := archsqlite.New(s.DB())

	if err := auth.EnsureBootstrap(context.Background(), s, config.Bootstrap{
		Username: "admin", Password: "supersecret",
	}); err != nil {
		t.Fatal(err)
	}

	runner := &nebulax.Real{Binary: bin}
	casvc := &ca.Service{Store: s, Archive: arch, Runner: runner}
	b := &bundle.Builder{Binaries: bundle.StubProvider{}}
	certsvc := &cert.Service{Store: s, Archive: arch, Runner: runner, CAService: casvc, Bundle: b}
	sessions := auth.NewSessionManager(s, "sc_test", 30*time.Minute, false)

	srv, err := server.New(&server.Server{
		Store: s, Sessions: sessions, CA: casvc, Cert: certsvc,
	}, server.Assets{Templates: web.Templates, Static: web.Static})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Login
	if resp, err := c.PostForm(ts.URL+"/login",
		url.Values{"username": {"admin"}, "password": {"supersecret"}}); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
	}

	// Create CA (real nebula-cert runs here)
	{
		resp, err := c.PostForm(ts.URL+"/ca", url.Values{
			"name":        {"e2e-root"},
			"curve":       {"P256"},
			"networks":    {"10.77.0.0/16"},
			"groups":      {"servers"},
			"duration":    {"24h"},
			"default_ttl": {"1h"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusSeeOther {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("CA create: %d body=%s", resp.StatusCode, body)
		}
		resp.Body.Close()
	}

	cas, _ := s.ListCAs(context.Background())
	if len(cas) != 1 {
		t.Fatalf("expected 1 CA, got %d", len(cas))
	}
	caRec := cas[0]
	if !strings.Contains(caRec.CertPEM, "NEBULA ECDSA P256 CERTIFICATE") &&
		!strings.Contains(caRec.CertPEM, "NEBULA CERTIFICATE") {
		t.Errorf("CA cert doesn't look like a nebula cert: %s", caRec.CertPEM)
	}

	// Issue cert (real nebula-cert sign runs here)
	{
		resp, err := c.PostForm(ts.URL+"/ca/"+caRec.ID+"/certs", url.Values{
			"name":     {"e2e-host"},
			"networks": {"10.77.0.5/16"},
			"groups":   {"servers"},
			"host_role": {"host"},
			"os":       {"linux"},
			"arch":     {"amd64"},
			"ttl":      {"30m"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusSeeOther {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("cert issue: %d body=%s", resp.StatusCode, body)
		}
		resp.Body.Close()
	}

	certs, _ := s.ListCerts(context.Background(), caRec.ID)
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	certRec := certs[0]
	if certRec.Fingerprint == "" {
		t.Error("cert should have fingerprint from real nebula-cert")
	}

	// Download bundle and inspect
	resp, err := c.Get(ts.URL + "/certs/" + certRec.ID + "/bundle")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bundle download: %d", resp.StatusCode)
	}
	tarball, _ := io.ReadAll(resp.Body)

	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		seen[filepath.Base(h.Name)] = true
	}
	for _, expect := range []string{"README.md", "install.sh", "config.yml", "host.crt", "host.key", "ca.crt"} {
		if !seen[expect] {
			t.Errorf("bundle missing %s (saw %v)", expect, seen)
		}
	}
}
