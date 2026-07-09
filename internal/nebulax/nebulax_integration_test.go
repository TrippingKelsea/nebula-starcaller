package nebulax

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// findNebulaCert tries typical locations for a real nebula-cert binary.
// Returns "" if none found — tests should skip.
func findNebulaCert() string {
	candidates := []string{
		os.Getenv("NEBULA_CERT_BINARY"),
	}
	if v := os.Getenv("NEBULA_VERSION"); v != "" {
		home, _ := os.UserHomeDir()
		candidates = append(candidates, filepath.Join(home, "Home-Lab/bin/Nebula", v, "nebula-cert"))
	}
	// Common install paths
	candidates = append(candidates,
		"/usr/local/bin/nebula-cert",
		"/usr/bin/nebula-cert",
	)
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}

func TestReal_CAThenSignThenPrint(t *testing.T) {
	bin := findNebulaCert()
	if bin == "" {
		t.Skip("real nebula-cert not found; skipping integration test")
	}
	ctx := context.Background()
	r := &Real{Binary: bin}

	ca, err := r.CA(ctx, CAReq{
		Name: "starcaller-test-root", Curve: "P256",
		Networks: []string{"10.99.0.0/16"},
		Duration: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("CA: %v", err)
	}
	if !ca.Info.Details.IsCA {
		t.Error("expected IsCA=true on new root")
	}
	if len(ca.CertPEM) == 0 || len(ca.KeyPEM) == 0 {
		t.Fatal("empty PEM output")
	}

	signed, err := r.Sign(ctx, SignReq{
		CACertPEM: ca.CertPEM, CAKeyPEM: ca.KeyPEM,
		Name: "host-01",
		Networks: []string{"10.99.0.10/16"},
		Duration: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if signed.Info.Details.IsCA {
		t.Error("signed cert should not be a CA")
	}
	if signed.Info.Details.Issuer != ca.Info.Fingerprint {
		t.Errorf("issuer mismatch: got %q want %q", signed.Info.Details.Issuer, ca.Info.Fingerprint)
	}
	if signed.Fingerprint == "" {
		t.Error("no fingerprint on signed cert")
	}
	// Round-trip Print on the signed cert
	info, err := r.Print(ctx, signed.CertPEM)
	if err != nil {
		t.Fatalf("Print: %v", err)
	}
	if info.Fingerprint != signed.Fingerprint {
		t.Errorf("print fingerprint mismatch: %q vs %q", info.Fingerprint, signed.Fingerprint)
	}
}
