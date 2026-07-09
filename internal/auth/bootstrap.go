package auth

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/TrippingKelsea/nebula-starcaller/internal/config"
	"github.com/TrippingKelsea/nebula-starcaller/internal/domain"
	"github.com/TrippingKelsea/nebula-starcaller/internal/store"
)

// EnsureBootstrap creates the pre-defined admin user if no users exist.
// Idempotent — after the first user exists, this is a no-op and bootstrap
// vars are logged as ignored.
func EnsureBootstrap(ctx context.Context, s store.Store, cfg config.Bootstrap) error {
	n, err := s.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		if cfg.Username != "" {
			log.Printf("auth: users already exist; ignoring STARCALLER_BOOTSTRAP_* config")
		}
		return nil
	}
	if cfg.Username == "" || cfg.Password == "" {
		return errors.New("auth: no users exist and bootstrap username/password not configured")
	}
	hash, err := HashPassword(cfg.Password)
	if err != nil {
		return err
	}
	u := domain.User{
		ID: uuid.NewString(), Username: cfg.Username, Email: cfg.Email,
		PasswordHash: hash,
		Roles: []domain.Role{domain.RoleAdmin},
		ForceWebAuthnEnrollment: true,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.CreateUser(ctx, u); err != nil {
		return err
	}
	log.Printf("auth: bootstrap admin %q created", u.Username)
	return nil
}

// Login verifies username+password, returns the user on success.
func Login(ctx context.Context, s store.Store, username, password string) (domain.User, error) {
	u, err := s.GetUserByUsername(ctx, username)
	if err != nil {
		// Return a generic error to avoid username enumeration.
		return domain.User{}, ErrPasswordMismatch
	}
	if err := VerifyPassword(u.PasswordHash, password); err != nil {
		return domain.User{}, ErrPasswordMismatch
	}
	now := time.Now().UTC()
	u.LastLoginAt = &now
	_ = s.UpdateUser(ctx, u)
	return u, nil
}
