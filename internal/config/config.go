package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen      string        `yaml:"listen"`
	DataDir     string        `yaml:"data_dir"`
	NebulaCert  string        `yaml:"nebula_cert"`
	BinariesDir string        `yaml:"binaries_dir"`
	SessionTTL  time.Duration `yaml:"session_ttl"`
	CSRFKey     string        `yaml:"csrf_key"`
	CookieName  string        `yaml:"cookie_name"`
	Bootstrap   Bootstrap     `yaml:"bootstrap"`
	WebAuthn    WebAuthn      `yaml:"webauthn"`
	DevMode     bool          `yaml:"dev_mode"`
}

type Bootstrap struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Email    string `yaml:"email"`
}

type WebAuthn struct {
	RPID          string   `yaml:"rp_id"`
	RPDisplayName string   `yaml:"rp_display_name"`
	RPOrigins     []string `yaml:"rp_origins"`
}

func Default() Config {
	return Config{
		Listen:      "127.0.0.1:8080",
		DataDir:     "/var/lib/starcaller",
		NebulaCert:  "nebula-cert",
		BinariesDir: "/opt/starcaller/binaries",
		SessionTTL:  12 * time.Hour,
		CookieName:  "starcaller_session",
		WebAuthn: WebAuthn{
			RPID:          "localhost",
			RPDisplayName: "Nebula Starcaller",
			RPOrigins:     []string{"http://localhost:8080"},
		},
	}
}

// Load reads config from the file at path (may be empty) and then overlays
// environment variables. Env always wins.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		if err := loadFile(path, &cfg); err != nil && !errors.Is(err, os.ErrNotExist) {
			return cfg, fmt.Errorf("load config file %s: %w", path, err)
		}
	}
	applyEnv(&cfg)
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func loadFile(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, cfg)
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("STARCALLER_LISTEN"); v != "" {
		cfg.Listen = v
	}
	if v := os.Getenv("STARCALLER_DATA_DIR"); v != "" {
		cfg.DataDir = v
	}
	if v := os.Getenv("STARCALLER_NEBULA_CERT"); v != "" {
		cfg.NebulaCert = v
	}
	if v := os.Getenv("STARCALLER_BINARIES_DIR"); v != "" {
		cfg.BinariesDir = v
	}
	if v := os.Getenv("STARCALLER_SESSION_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.SessionTTL = d
		}
	}
	if v := os.Getenv("STARCALLER_CSRF_KEY"); v != "" {
		cfg.CSRFKey = v
	}
	if v := os.Getenv("STARCALLER_COOKIE_NAME"); v != "" {
		cfg.CookieName = v
	}
	if v := os.Getenv("STARCALLER_DEV_MODE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.DevMode = b
		}
	}
	if v := os.Getenv("STARCALLER_BOOTSTRAP_USERNAME"); v != "" {
		cfg.Bootstrap.Username = v
	}
	if v := os.Getenv("STARCALLER_BOOTSTRAP_PASSWORD"); v != "" {
		cfg.Bootstrap.Password = v
	}
	if v := os.Getenv("STARCALLER_BOOTSTRAP_EMAIL"); v != "" {
		cfg.Bootstrap.Email = v
	}
	if v := os.Getenv("STARCALLER_RP_ID"); v != "" {
		cfg.WebAuthn.RPID = v
	}
	if v := os.Getenv("STARCALLER_RP_DISPLAY_NAME"); v != "" {
		cfg.WebAuthn.RPDisplayName = v
	}
	if v := os.Getenv("STARCALLER_RP_ORIGINS"); v != "" {
		cfg.WebAuthn.RPOrigins = splitComma(v)
	}
}

func splitComma(s string) []string {
	out := []string{}
	start := 0
	for i, r := range s {
		if r == ',' {
			out = append(out, trim(s[start:i]))
			start = i + 1
		}
	}
	out = append(out, trim(s[start:]))
	return out
}

func trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func (c Config) Validate() error {
	if c.Listen == "" {
		return errors.New("listen address is required")
	}
	if c.DataDir == "" {
		return errors.New("data_dir is required")
	}
	if c.NebulaCert == "" {
		return errors.New("nebula_cert is required")
	}
	if c.SessionTTL <= 0 {
		return errors.New("session_ttl must be > 0")
	}
	if c.WebAuthn.RPID == "" {
		return errors.New("webauthn.rp_id is required")
	}
	if len(c.WebAuthn.RPOrigins) == 0 {
		return errors.New("webauthn.rp_origins must have at least one entry")
	}
	return nil
}

// DBPath returns the SQLite database file path derived from DataDir.
func (c Config) DBPath() string {
	return filepath.Join(c.DataDir, "starcaller.db")
}
