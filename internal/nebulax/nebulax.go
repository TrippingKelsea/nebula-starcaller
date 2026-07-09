// Package nebulax is a thin, test-mockable wrapper around the nebula-cert
// binary. It handles temp-file hygiene and JSON output parsing.
package nebulax

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// Runner shells out to nebula-cert. Tests can substitute a fake.
type Runner interface {
	CA(ctx context.Context, req CAReq) (CAResult, error)
	Sign(ctx context.Context, req SignReq) (SignResult, error)
	Print(ctx context.Context, certPEM []byte) (CertInfo, error)
}

type Real struct {
	Binary string // "nebula-cert" or absolute path
	// TempParent is where scratch dirs live. Empty => secure default (tmpfs).
	TempParent string
}

// SecureTempParent returns /dev/shm on Linux (tmpfs; RAM-backed) or the OS tmp
// dir on other platforms. On non-Linux we log a warning at first use.
func SecureTempParent() string {
	if runtime.GOOS == "linux" {
		if fi, err := os.Stat("/dev/shm"); err == nil && fi.IsDir() {
			return "/dev/shm"
		}
	}
	return os.TempDir()
}

type CAReq struct {
	Name           string
	Curve          string // "25519" or "P256"
	Networks       []string
	UnsafeNetworks []string
	Groups         []string
	Duration       time.Duration
}

type CAResult struct {
	CertPEM     []byte
	KeyPEM      []byte
	Fingerprint string
	Info        CertInfo
}

type SignReq struct {
	CACertPEM      []byte
	CAKeyPEM       []byte
	Name           string
	Networks       []string
	UnsafeNetworks []string
	Groups         []string
	Duration       time.Duration
}

type SignResult struct {
	CertPEM     []byte
	KeyPEM      []byte
	Fingerprint string
	Info        CertInfo
}

// CertInfo mirrors the JSON output of `nebula-cert print`.
type CertInfo struct {
	Curve       string   `json:"curve"`
	Fingerprint string   `json:"fingerprint"`
	Details     struct {
		IsCA           bool     `json:"isCa"`
		Issuer         string   `json:"issuer"`
		Name           string   `json:"name"`
		Networks       []string `json:"networks"`
		UnsafeNetworks []string `json:"unsafeNetworks"`
		Groups         []string `json:"groups"`
		NotAfter       string   `json:"notAfter"`
		NotBefore      string   `json:"notBefore"`
	} `json:"details"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
	Version   int    `json:"version"`
}

// NotBeforeTime parses the not-before timestamp. Returns zero on error.
func (i CertInfo) NotBeforeTime() time.Time { return parseNebulaTime(i.Details.NotBefore) }

// NotAfterTime parses the not-after timestamp. Returns zero on error.
func (i CertInfo) NotAfterTime() time.Time { return parseNebulaTime(i.Details.NotAfter) }

func parseNebulaTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func (r *Real) tempDir() (string, func(), error) {
	parent := r.TempParent
	if parent == "" {
		parent = SecureTempParent()
	}
	name := "starcaller-" + randomHex(8)
	dir := filepath.Join(parent, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, err
	}
	cleanup := func() {
		// Best-effort: overwrite any file contents before unlink.
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if fi, e := os.Stat(path); e == nil {
				overwrite(path, fi.Size())
			}
			return nil
		})
		os.RemoveAll(dir)
	}
	return dir, cleanup, nil
}

// overwrite blindly writes zeros to a file. Best-effort; not a guarantee on
// modern filesystems (COW, etc.) but useful against casual recovery.
func overwrite(path string, size int64) {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer f.Close()
	buf := make([]byte, 4096)
	remaining := size
	for remaining > 0 {
		n := int64(len(buf))
		if remaining < n {
			n = remaining
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return
		}
		remaining -= n
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// CA invokes `nebula-cert ca` and reads back cert + key.
func (r *Real) CA(ctx context.Context, req CAReq) (CAResult, error) {
	dir, cleanup, err := r.tempDir()
	if err != nil {
		return CAResult{}, err
	}
	defer cleanup()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	args := []string{"ca",
		"-name", req.Name,
		"-out-crt", certPath, "-out-key", keyPath,
	}
	if req.Curve != "" {
		args = append(args, "-curve", req.Curve)
	}
	if len(req.Networks) > 0 {
		args = append(args, "-networks", joinCSV(req.Networks))
	}
	if len(req.UnsafeNetworks) > 0 {
		args = append(args, "-unsafe-networks", joinCSV(req.UnsafeNetworks))
	}
	if len(req.Groups) > 0 {
		args = append(args, "-groups", joinCSV(req.Groups))
	}
	if req.Duration > 0 {
		args = append(args, "-duration", req.Duration.String())
	}
	if err := runCmd(ctx, r.binary(), args...); err != nil {
		return CAResult{}, fmt.Errorf("nebula-cert ca: %w", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return CAResult{}, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return CAResult{}, err
	}
	info, err := r.Print(ctx, certPEM)
	if err != nil {
		return CAResult{}, err
	}
	return CAResult{CertPEM: certPEM, KeyPEM: keyPEM, Fingerprint: info.Fingerprint, Info: info}, nil
}

// Sign invokes `nebula-cert sign` and reads back the signed cert + key.
func (r *Real) Sign(ctx context.Context, req SignReq) (SignResult, error) {
	dir, cleanup, err := r.tempDir()
	if err != nil {
		return SignResult{}, err
	}
	defer cleanup()
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	if err := writeFileMode(caCert, req.CACertPEM, 0o600); err != nil {
		return SignResult{}, err
	}
	if err := writeFileMode(caKey, req.CAKeyPEM, 0o600); err != nil {
		return SignResult{}, err
	}
	outCert := filepath.Join(dir, "host.crt")
	outKey := filepath.Join(dir, "host.key")
	args := []string{"sign",
		"-ca-crt", caCert, "-ca-key", caKey,
		"-name", req.Name,
		"-networks", joinCSV(req.Networks),
		"-out-crt", outCert, "-out-key", outKey,
	}
	if len(req.UnsafeNetworks) > 0 {
		args = append(args, "-unsafe-networks", joinCSV(req.UnsafeNetworks))
	}
	if len(req.Groups) > 0 {
		args = append(args, "-groups", joinCSV(req.Groups))
	}
	if req.Duration > 0 {
		args = append(args, "-duration", req.Duration.String())
	}
	if err := runCmd(ctx, r.binary(), args...); err != nil {
		return SignResult{}, fmt.Errorf("nebula-cert sign: %w", err)
	}
	certPEM, err := os.ReadFile(outCert)
	if err != nil {
		return SignResult{}, err
	}
	keyPEM, err := os.ReadFile(outKey)
	if err != nil {
		return SignResult{}, err
	}
	info, err := r.Print(ctx, certPEM)
	if err != nil {
		return SignResult{}, err
	}
	return SignResult{CertPEM: certPEM, KeyPEM: keyPEM, Fingerprint: info.Fingerprint, Info: info}, nil
}

// Print runs `nebula-cert print -json -path <tmpfile>` and returns the parsed info.
func (r *Real) Print(ctx context.Context, certPEM []byte) (CertInfo, error) {
	dir, cleanup, err := r.tempDir()
	if err != nil {
		return CertInfo{}, err
	}
	defer cleanup()
	p := filepath.Join(dir, "cert.crt")
	if err := writeFileMode(p, certPEM, 0o600); err != nil {
		return CertInfo{}, err
	}
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, r.binary(), "print", "-json", "-path", p)
	cmd.Stdout = &out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return CertInfo{}, fmt.Errorf("nebula-cert print: %w (stderr: %s)", err, stderr.String())
	}
	// nebula-cert -json emits either a single object or an array; handle both.
	raw := bytes.TrimSpace(out.Bytes())
	if len(raw) > 0 && raw[0] == '[' {
		var many []CertInfo
		if err := json.Unmarshal(raw, &many); err != nil {
			return CertInfo{}, fmt.Errorf("nebula-cert print: parse json array: %w", err)
		}
		if len(many) == 0 {
			return CertInfo{}, errors.New("nebula-cert print: empty array")
		}
		return many[0], nil
	}
	var info CertInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return CertInfo{}, fmt.Errorf("nebula-cert print: parse json: %w", err)
	}
	return info, nil
}

func (r *Real) binary() string {
	if r.Binary == "" {
		return "nebula-cert"
	}
	return r.Binary
}

func runCmd(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := stderr.String()
		if msg == "" {
			return err
		}
		return errors.New(msg)
	}
	return nil
}

func writeFileMode(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

func joinCSV(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ","
		}
		out += x
	}
	return out
}
