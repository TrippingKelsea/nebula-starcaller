// Package archive stores opaque blobs (CA keys, cert bytes, bundle tarballs)
// separately from the structured Store so backends can differ.
package archive

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("archive: not found")

// Kind identifies what a blob is. Not enforced beyond metadata.
type Kind string

const (
	KindCAKey     Kind = "ca-key"
	KindCertKey   Kind = "cert-key"
	KindCertPEM   Kind = "cert-pem"
	KindBundle    Kind = "bundle"
	KindTrustBundle Kind = "trust-bundle"
)

type Blob struct {
	ID          string
	Kind        Kind
	ContentType string
	Data        []byte
}

type Archive interface {
	Put(ctx context.Context, b Blob) (string, error) // returns ID (may be assigned)
	Get(ctx context.Context, id string) (Blob, error)
	Delete(ctx context.Context, id string) error
	Close() error
}
