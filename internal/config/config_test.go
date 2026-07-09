package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("default config should validate: %v", err)
	}
}

func TestValidateMissingFields(t *testing.T) {
	cases := map[string]func(c *Config){
		"listen":       func(c *Config) { c.Listen = "" },
		"data_dir":     func(c *Config) { c.DataDir = "" },
		"nebula_cert":  func(c *Config) { c.NebulaCert = "" },
		"session_ttl":  func(c *Config) { c.SessionTTL = 0 },
		"rp_id":        func(c *Config) { c.WebAuthn.RPID = "" },
		"rp_origins":   func(c *Config) { c.WebAuthn.RPOrigins = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := Default()
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatalf("expected validation error for %s", name)
			}
		})
	}
}

func TestLoadEnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	content := []byte(`
listen: "0.0.0.0:9000"
data_dir: "/tmp/from-file"
bootstrap:
  username: file-admin
  password: file-pass
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	envKeys := []string{
		"STARCALLER_LISTEN", "STARCALLER_DATA_DIR",
		"STARCALLER_BOOTSTRAP_USERNAME", "STARCALLER_BOOTSTRAP_PASSWORD",
		"STARCALLER_SESSION_TTL", "STARCALLER_DEV_MODE",
	}
	for _, k := range envKeys {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}

	t.Setenv("STARCALLER_LISTEN", "127.0.0.1:7777")
	t.Setenv("STARCALLER_BOOTSTRAP_USERNAME", "env-admin")
	t.Setenv("STARCALLER_SESSION_TTL", "30m")
	t.Setenv("STARCALLER_DEV_MODE", "true")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != "127.0.0.1:7777" {
		t.Errorf("Listen: env should override file, got %q", cfg.Listen)
	}
	if cfg.DataDir != "/tmp/from-file" {
		t.Errorf("DataDir: file should apply when env unset, got %q", cfg.DataDir)
	}
	if cfg.Bootstrap.Username != "env-admin" {
		t.Errorf("bootstrap.username env override failed, got %q", cfg.Bootstrap.Username)
	}
	if cfg.Bootstrap.Password != "file-pass" {
		t.Errorf("bootstrap.password should come from file, got %q", cfg.Bootstrap.Password)
	}
	if cfg.SessionTTL != 30*time.Minute {
		t.Errorf("SessionTTL: expected 30m, got %v", cfg.SessionTTL)
	}
	if !cfg.DevMode {
		t.Errorf("DevMode: expected true")
	}
}

func TestLoadMissingFileIsOK(t *testing.T) {
	cfg, err := Load("/nonexistent/config.yml")
	if err != nil {
		t.Fatalf("missing file should not error, got %v", err)
	}
	if cfg.Listen == "" {
		t.Errorf("expected defaults to apply")
	}
}

func TestLoadEmptyPathUsesDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\"): %v", err)
	}
	if cfg.Listen != Default().Listen {
		t.Errorf("expected default Listen, got %q", cfg.Listen)
	}
}

func TestSplitCommaTrims(t *testing.T) {
	got := splitComma("  a , b,c  ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("len: got %v want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("i=%d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestDBPath(t *testing.T) {
	c := Default()
	c.DataDir = "/data"
	if c.DBPath() != "/data/starcaller.db" {
		t.Errorf("DBPath: got %q", c.DBPath())
	}
}
