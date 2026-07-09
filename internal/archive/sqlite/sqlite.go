// Package sqlite is a SQLite-backed implementation of archive.Archive.
// It re-uses the schema's `archive` table which is created by the store package.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/TrippingKelsea/nebula-starcaller/internal/archive"
)

type Archive struct {
	db *sql.DB
}

// New returns an Archive backed by the given (already-open, schema-applied) DB.
// The store package owns schema creation; we simply share the handle.
func New(db *sql.DB) *Archive {
	return &Archive{db: db}
}

func (a *Archive) Close() error { return nil } // db owned elsewhere

func (a *Archive) Put(ctx context.Context, b archive.Blob) (string, error) {
	if b.ID == "" {
		b.ID = uuid.NewString()
	}
	if b.ContentType == "" {
		b.ContentType = "application/octet-stream"
	}
	_, err := a.db.ExecContext(ctx, `
		INSERT INTO archive (id, kind, content_type, size, data, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, b.ID, string(b.Kind), b.ContentType, len(b.Data), b.Data, time.Now().UTC().Unix())
	if err != nil {
		return "", err
	}
	return b.ID, nil
}

func (a *Archive) Get(ctx context.Context, id string) (archive.Blob, error) {
	var b archive.Blob
	var kind, contentType string
	var size int64
	err := a.db.QueryRowContext(ctx,
		`SELECT id, kind, content_type, size, data FROM archive WHERE id = ?`, id,
	).Scan(&b.ID, &kind, &contentType, &size, &b.Data)
	if errors.Is(err, sql.ErrNoRows) {
		return b, archive.ErrNotFound
	}
	if err != nil {
		return b, err
	}
	b.Kind = archive.Kind(kind)
	b.ContentType = contentType
	return b, nil
}

func (a *Archive) Delete(ctx context.Context, id string) error {
	res, err := a.db.ExecContext(ctx, `DELETE FROM archive WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return archive.ErrNotFound
	}
	return nil
}
