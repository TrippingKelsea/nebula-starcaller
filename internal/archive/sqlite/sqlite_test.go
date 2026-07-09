package sqlite

import (
	"context"
	"errors"
	"testing"

	"github.com/TrippingKelsea/nebula-starcaller/internal/archive"
	storesqlite "github.com/TrippingKelsea/nebula-starcaller/internal/store/sqlite"
)

func newTestArchive(t *testing.T) *Archive {
	t.Helper()
	s, err := storesqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return New(s.DB())
}

func TestArchivePutGet(t *testing.T) {
	ctx := context.Background()
	a := newTestArchive(t)

	id, err := a.Put(ctx, archive.Blob{Kind: archive.KindCertPEM, Data: []byte("hello")})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if id == "" {
		t.Fatal("expected generated ID")
	}

	got, err := a.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got.Data) != "hello" || got.Kind != archive.KindCertPEM {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestArchiveExplicitID(t *testing.T) {
	ctx := context.Background()
	a := newTestArchive(t)
	id, err := a.Put(ctx, archive.Blob{ID: "my-id", Kind: archive.KindBundle, Data: []byte{0xde, 0xad}})
	if err != nil || id != "my-id" {
		t.Errorf("Put with ID: id=%q err=%v", id, err)
	}
}

func TestArchiveGetNotFound(t *testing.T) {
	ctx := context.Background()
	a := newTestArchive(t)
	if _, err := a.Get(ctx, "nope"); !errors.Is(err, archive.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestArchiveDelete(t *testing.T) {
	ctx := context.Background()
	a := newTestArchive(t)
	id, _ := a.Put(ctx, archive.Blob{Kind: archive.KindCAKey, Data: []byte("secret")})
	if err := a.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := a.Delete(ctx, id); !errors.Is(err, archive.ErrNotFound) {
		t.Errorf("delete twice: expected NotFound, got %v", err)
	}
}
