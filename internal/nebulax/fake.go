package nebulax

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Fake is an in-memory Runner for unit tests. It does not invoke any external
// binary. It produces deterministic-ish fake PEM blobs and fingerprints so
// tests can assert on identity relationships.
type Fake struct {
	mu       sync.Mutex
	nextSerial int
	// CAsByFP maps CA fingerprint -> latest CA cert bytes so Sign can look
	// up the issuer for CertInfo.Issuer.
	CAsByFP map[string][]byte
}

func NewFake() *Fake {
	return &Fake{CAsByFP: map[string][]byte{}}
}

func (f *Fake) next() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextSerial++
	return f.nextSerial
}

func (f *Fake) CA(ctx context.Context, req CAReq) (CAResult, error) {
	if req.Name == "" {
		return CAResult{}, fmt.Errorf("fake: name required")
	}
	n := f.next()
	fp := fmt.Sprintf("fake-fp-ca-%03d", n)
	certPEM := []byte(fmt.Sprintf("-----BEGIN NEBULA CERTIFICATE-----\nFAKE CA %s\n-----END NEBULA CERTIFICATE-----\n", req.Name))
	keyPEM := []byte(fmt.Sprintf("-----BEGIN NEBULA ECDSA %s PRIVATE KEY-----\nFAKE %s\n-----END NEBULA ECDSA %s PRIVATE KEY-----\n", req.Curve, req.Name, req.Curve))
	now := time.Now().UTC()
	info := CertInfo{
		Curve: req.Curve, Fingerprint: fp, Version: 2,
	}
	info.Details.IsCA = true
	info.Details.Name = req.Name
	info.Details.Networks = req.Networks
	info.Details.UnsafeNetworks = req.UnsafeNetworks
	info.Details.Groups = req.Groups
	info.Details.NotBefore = now.Format(time.RFC3339)
	info.Details.NotAfter = now.Add(req.Duration).Format(time.RFC3339)
	f.mu.Lock()
	f.CAsByFP[fp] = certPEM
	f.mu.Unlock()
	return CAResult{CertPEM: certPEM, KeyPEM: keyPEM, Fingerprint: fp, Info: info}, nil
}

func (f *Fake) Sign(ctx context.Context, req SignReq) (SignResult, error) {
	if req.Name == "" {
		return SignResult{}, fmt.Errorf("fake: name required")
	}
	if len(req.Networks) == 0 {
		return SignResult{}, fmt.Errorf("fake: networks required")
	}
	// Locate issuer by scanning stored CA PEMs. Cheap enough for tests.
	var issuer string
	f.mu.Lock()
	for fp, pem := range f.CAsByFP {
		if string(pem) == string(req.CACertPEM) {
			issuer = fp
			break
		}
	}
	f.mu.Unlock()
	n := f.next()
	fp := fmt.Sprintf("fake-fp-cert-%03d", n)
	certPEM := []byte(fmt.Sprintf("-----BEGIN NEBULA CERTIFICATE-----\nFAKE CERT %s (issuer=%s)\n-----END NEBULA CERTIFICATE-----\n", req.Name, issuer))
	keyPEM := []byte(fmt.Sprintf("-----BEGIN NEBULA P256 PRIVATE KEY-----\nFAKE %s\n-----END NEBULA P256 PRIVATE KEY-----\n", req.Name))
	now := time.Now().UTC()
	info := CertInfo{Fingerprint: fp, Version: 2}
	info.Details.IsCA = false
	info.Details.Issuer = issuer
	info.Details.Name = req.Name
	info.Details.Networks = req.Networks
	info.Details.UnsafeNetworks = req.UnsafeNetworks
	info.Details.Groups = req.Groups
	info.Details.NotBefore = now.Format(time.RFC3339)
	info.Details.NotAfter = now.Add(req.Duration).Format(time.RFC3339)
	return SignResult{CertPEM: certPEM, KeyPEM: keyPEM, Fingerprint: fp, Info: info}, nil
}

func (f *Fake) Print(ctx context.Context, certPEM []byte) (CertInfo, error) {
	return CertInfo{Fingerprint: "unknown"}, nil
}
