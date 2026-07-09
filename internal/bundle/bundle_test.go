package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/TrippingKelsea/nebula-starcaller/internal/domain"
)

func readTarGz(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		buf, _ := io.ReadAll(tr)
		out[h.Name] = buf
	}
	return out
}

func TestBundleContents(t *testing.T) {
	b := &Builder{Binaries: StubProvider{}}
	data, err := b.Build(context.Background(), Input{
		HostName:    "web-01",
		CertPEM:     []byte("HOSTCERT"),
		KeyPEM:      []byte("HOSTKEY"),
		TrustBundle: []byte("CAPEM"),
		HostRole:    domain.HostRoleHost,
		Platform:    domain.Platform{OS: "linux", Arch: "amd64"},
		Networks:    []string{"10.0.0.5/16"},
		Groups:      []string{"servers"},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	files := readTarGz(t, data)

	// Should contain README, install.sh, config.yml, nebula, nebula-cert, pki/*
	required := []string{"README.md", "install.sh", "config.yml", "nebula", "nebula-cert", "pki/host.crt", "pki/host.key", "pki/ca.crt"}
	for _, name := range required {
		found := false
		for k := range files {
			if strings.HasSuffix(k, "/"+name) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing %s in bundle", name)
		}
	}

	// PKI file bytes should match input exactly
	for k, v := range files {
		if strings.HasSuffix(k, "/pki/host.crt") && string(v) != "HOSTCERT" {
			t.Errorf("host.crt mismatch")
		}
		if strings.HasSuffix(k, "/pki/host.key") && string(v) != "HOSTKEY" {
			t.Errorf("host.key mismatch")
		}
		if strings.HasSuffix(k, "/pki/ca.crt") && string(v) != "CAPEM" {
			t.Errorf("ca.crt mismatch")
		}
	}

	// config.yml should mention the hostname and network
	for k, v := range files {
		if strings.HasSuffix(k, "/config.yml") {
			s := string(v)
			if !strings.Contains(s, "web-01") {
				t.Errorf("config.yml missing hostname")
			}
			if !strings.Contains(s, "am_lighthouse: false") {
				t.Errorf("config.yml should mark non-lighthouse")
			}
			if !strings.Contains(s, "am_relay: false") {
				t.Errorf("config.yml should mark non-relay")
			}
		}
	}
}

func TestBundleLighthouse(t *testing.T) {
	b := &Builder{Binaries: StubProvider{}}
	data, err := b.Build(context.Background(), Input{
		HostName: "lighthouse-1",
		CertPEM: []byte("C"), KeyPEM: []byte("K"), TrustBundle: []byte("CA"),
		HostRole: domain.HostRoleLighthouse,
		Platform: domain.Platform{OS: "linux", Arch: "amd64"},
		Networks: []string{"10.0.0.1/16"},
	})
	if err != nil {
		t.Fatal(err)
	}
	files := readTarGz(t, data)
	for k, v := range files {
		if strings.HasSuffix(k, "/config.yml") {
			if !strings.Contains(string(v), "am_lighthouse: true") {
				t.Errorf("expected am_lighthouse=true")
			}
			if !strings.Contains(string(v), "port: 4242") {
				t.Errorf("expected listen port 4242 for lighthouse")
			}
		}
	}
}

func TestBundleUnsupportedPlatformStillProducesReadme(t *testing.T) {
	// DirProvider with empty root returns ErrUnsupported for both binaries.
	b := &Builder{Binaries: DirProvider{Root: "/does/not/exist"}}
	data, err := b.Build(context.Background(), Input{
		HostName: "solaris-thing",
		CertPEM: []byte("C"), KeyPEM: []byte("K"), TrustBundle: []byte("CA"),
		Platform: domain.Platform{OS: "solaris", Arch: "amd64"},
		Networks: []string{"10.0.0.9/16"},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	files := readTarGz(t, data)
	// Should have config, README, pki/* but no nebula binary
	for k := range files {
		if strings.HasSuffix(k, "/nebula") || strings.HasSuffix(k, "/nebula.exe") {
			t.Errorf("unexpected nebula binary for unsupported platform: %s", k)
		}
	}
	// README should include the "no binary" note
	for k, v := range files {
		if strings.HasSuffix(k, "/README.md") {
			if !strings.Contains(string(v), "no nebula binary") {
				t.Errorf("README should note missing binary")
			}
		}
	}
}

func TestSanitizeHostName(t *testing.T) {
	// Verify sanitizer doesn't break through path components
	cases := map[string]string{
		"web-01":       "web-01",
		"HOST/WITH/../": "host-with----",
		"a b c":        "a-b-c",
	}
	for in, want := range cases {
		got := sanitize(in)
		if got != want {
			t.Errorf("sanitize(%q) = %q; want %q", in, got, want)
		}
	}
}
