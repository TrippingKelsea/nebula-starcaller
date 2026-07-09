// Package bundle assembles a downloadable host installation archive.
package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/TrippingKelsea/nebula-starcaller/internal/domain"
)

// BinaryProvider knows how to load the nebula binary for a given platform.
type BinaryProvider interface {
	Nebula(p domain.Platform) ([]byte, error)     // may return (nil, ErrUnsupported)
	NebulaCert(p domain.Platform) ([]byte, error) // best-effort; may return nil
}

// Input holds the material a builder needs to produce a bundle.
type Input struct {
	HostName    string
	CertPEM     []byte
	KeyPEM      []byte
	TrustBundle []byte
	HostRole    domain.HostRole
	Platform    domain.Platform
	Networks    []string
	Groups      []string
	// Optional; if nil we fall back to the BinaryProvider.
	NebulaBinary     []byte
	NebulaCertBinary []byte
}

var ErrUnsupported = errors.New("bundle: unsupported platform")

// DirProvider loads binaries from a filesystem directory shaped as:
//   <dir>/<os>-<arch>/nebula
//   <dir>/<os>-<arch>/nebula-cert
type DirProvider struct {
	Root string
}

func (d DirProvider) Nebula(p domain.Platform) ([]byte, error) {
	return d.load(p, "nebula")
}

func (d DirProvider) NebulaCert(p domain.Platform) ([]byte, error) {
	return d.load(p, "nebula-cert")
}

func (d DirProvider) load(p domain.Platform, name string) ([]byte, error) {
	if p.OS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(d.Root, p.String(), name)
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrUnsupported
	}
	return b, err
}

// StubProvider is used in tests. Returns non-empty fake bytes for any platform.
type StubProvider struct{}

func (StubProvider) Nebula(p domain.Platform) ([]byte, error) {
	return []byte("#!/bin/sh\necho fake nebula for " + p.String() + "\n"), nil
}
func (StubProvider) NebulaCert(p domain.Platform) ([]byte, error) {
	return []byte("#!/bin/sh\necho fake nebula-cert for " + p.String() + "\n"), nil
}

// Builder assembles bundles.
type Builder struct {
	Binaries BinaryProvider
}

func (b *Builder) Build(ctx context.Context, in Input) ([]byte, error) {
	if in.HostName == "" {
		return nil, errors.New("bundle: HostName required")
	}
	if in.HostRole == "" {
		in.HostRole = domain.HostRoleHost
	}
	nebulaBin, err := b.Binaries.Nebula(in.Platform)
	if err != nil && !errors.Is(err, ErrUnsupported) {
		return nil, fmt.Errorf("load nebula binary: %w", err)
	}
	nebulaCertBin, _ := b.Binaries.NebulaCert(in.Platform) // best-effort

	configYML, err := renderConfig(in)
	if err != nil {
		return nil, err
	}
	installSH, err := renderInstall(in)
	if err != nil {
		return nil, err
	}
	readme := renderReadme(in, nebulaBin == nil)

	prefix := fmt.Sprintf("starcaller-%s-%s", sanitize(in.HostName),
		time.Now().UTC().Format("20060102T150405Z"))

	var gzbuf bytes.Buffer
	gz := gzip.NewWriter(&gzbuf)
	tw := tar.NewWriter(gz)

	addFile := func(name string, data []byte, mode int64) error {
		if err := tw.WriteHeader(&tar.Header{
			Name: filepath.Join(prefix, name),
			Mode: mode, Size: int64(len(data)),
			ModTime: time.Now(),
		}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}

	if err := addFile("README.md", readme, 0o644); err != nil {
		return nil, err
	}
	if err := addFile("install.sh", installSH, 0o755); err != nil {
		return nil, err
	}
	if err := addFile("config.yml", configYML, 0o644); err != nil {
		return nil, err
	}
	if nebulaBin != nil {
		binName := "nebula"
		if in.Platform.OS == "windows" {
			binName = "nebula.exe"
		}
		if err := addFile(binName, nebulaBin, 0o755); err != nil {
			return nil, err
		}
	} else {
		log.Printf("bundle: no nebula binary bundled for %s", in.Platform)
	}
	if nebulaCertBin != nil {
		binName := "nebula-cert"
		if in.Platform.OS == "windows" {
			binName = "nebula-cert.exe"
		}
		if err := addFile(binName, nebulaCertBin, 0o755); err != nil {
			return nil, err
		}
	}
	if err := addFile("pki/host.crt", in.CertPEM, 0o644); err != nil {
		return nil, err
	}
	if err := addFile("pki/host.key", in.KeyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := addFile("pki/ca.crt", in.TrustBundle, 0o644); err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return gzbuf.Bytes(), nil
}

func sanitize(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			out = append(out, c)
		default:
			out = append(out, '-')
		}
	}
	return strings.ToLower(string(out))
}

// ---- templates ----

var configTmpl = template.Must(template.New("cfg").Parse(configYMLTemplate))
var installTmpl = template.Must(template.New("inst").Parse(installSHTemplate))

func renderConfig(in Input) ([]byte, error) {
	var buf bytes.Buffer
	data := map[string]any{
		"HostName": in.HostName,
		"Networks": in.Networks,
		"Groups":   in.Groups,
		"IsLighthouse": in.HostRole == domain.HostRoleLighthouse,
		"IsRelay":      in.HostRole == domain.HostRoleRelay,
	}
	if err := configTmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func renderInstall(in Input) ([]byte, error) {
	var buf bytes.Buffer
	data := map[string]any{
		"HostName": in.HostName,
		"Platform": in.Platform.String(),
		"IsLinux":  in.Platform.OS == "linux",
	}
	if err := installTmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func renderReadme(in Input, missingBinary bool) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Nebula installation for %s\n\n", in.HostName)
	fmt.Fprintf(&b, "Generated by Nebula Starcaller.\n\n")
	fmt.Fprintf(&b, "Platform: %s\n\n", in.Platform)
	if missingBinary {
		fmt.Fprintf(&b, "> NOTE: no nebula binary is bundled for this platform. Download it from\n")
		fmt.Fprintf(&b, "> https://github.com/slackhq/nebula/releases and place it alongside this file\n")
		fmt.Fprintf(&b, "> before running install.sh.\n\n")
	}
	fmt.Fprintf(&b, "## Contents\n\n")
	fmt.Fprintf(&b, "- `nebula` — runtime binary\n")
	fmt.Fprintf(&b, "- `nebula-cert` — cert utility (for local inspection / rotation)\n")
	fmt.Fprintf(&b, "- `config.yml` — Nebula host configuration\n")
	fmt.Fprintf(&b, "- `pki/host.crt`, `pki/host.key` — this host's identity\n")
	fmt.Fprintf(&b, "- `pki/ca.crt` — trusted CA(s)\n\n")
	fmt.Fprintf(&b, "## Install (Linux, systemd)\n\n")
	fmt.Fprintf(&b, "```sh\nsudo ./install.sh\n```\n\n")
	fmt.Fprintf(&b, "The installer is idempotent — safe to re-run on rotation.\n")
	return b.Bytes()
}

const configYMLTemplate = `# Nebula config for {{.HostName}}
# Generated by Nebula Starcaller.

pki:
  ca: /etc/nebula/ca.crt
  cert: /etc/nebula/host.crt
  key: /etc/nebula/host.key

static_host_map: {}

lighthouse:
  am_lighthouse: {{.IsLighthouse}}
  interval: 60
  hosts: []

listen:
  host: "[::]"
  port: {{if .IsLighthouse}}4242{{else}}0{{end}}

punchy:
  punch: true
  respond: true

relay:
  am_relay: {{.IsRelay}}
  use_relays: true

tun:
  disabled: false
  dev: nebula1
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500
  mtu: 1300

logging:
  level: info
  format: text

firewall:
  outbound_action: drop
  inbound_action: drop
  conntrack:
    tcp_timeout: 12m
    udp_timeout: 3m
    default_timeout: 10m

  outbound:
    - port: any
      proto: any
      host: any

  inbound:
    - port: any
      proto: icmp
      host: any
{{range .Groups}}    - port: any
      proto: any
      groups:
        - {{.}}
{{end}}
`

const installSHTemplate = `#!/bin/sh
# Nebula Starcaller install script for {{.HostName}} ({{.Platform}})
set -eu

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nebula"
UNIT_PATH="/etc/systemd/system/nebula.service"

echo ">> nebula-starcaller: installing {{.HostName}}"

sudo() { if [ "$(id -u)" -eq 0 ]; then "$@"; else command sudo "$@"; fi; }

script_dir="$(cd "$(dirname "$0")" && pwd)"

# Binary
if [ -f "$script_dir/nebula" ]; then
    sudo install -m 0755 "$script_dir/nebula" "$INSTALL_DIR/nebula"
    echo "installed nebula -> $INSTALL_DIR/nebula"
else
    echo "warning: no nebula binary in bundle; skipping"
fi

# Config + PKI
sudo mkdir -p "$CONFIG_DIR"
sudo install -m 0644 "$script_dir/config.yml" "$CONFIG_DIR/config.yml"
sudo install -m 0644 "$script_dir/pki/host.crt" "$CONFIG_DIR/host.crt"
sudo install -m 0600 "$script_dir/pki/host.key" "$CONFIG_DIR/host.key"
sudo install -m 0644 "$script_dir/pki/ca.crt"   "$CONFIG_DIR/ca.crt"

{{if .IsLinux}}
# systemd unit (only if systemd is present)
if command -v systemctl >/dev/null 2>&1; then
    UNIT="[Unit]
Description=Nebula overlay networking tool
Wants=basic.target network-online.target
After=basic.target network.target network-online.target
Before=sshd.service

[Service]
SyslogIdentifier=nebula
ExecReload=/bin/kill -HUP \$MAINPID
ExecStart=$INSTALL_DIR/nebula -config $CONFIG_DIR/config.yml
Restart=always

[Install]
WantedBy=multi-user.target
"
    echo "$UNIT" | sudo tee "$UNIT_PATH" >/dev/null
    sudo systemctl daemon-reload
    sudo systemctl enable --now nebula.service
    echo "systemd unit enabled: nebula.service"
else
    echo "systemctl not found; skipping systemd setup"
fi
{{end}}

echo ">> nebula-starcaller: install complete"
echo "check status with: systemctl status nebula.service"
`
