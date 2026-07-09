package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/TrippingKelsea/nebula-starcaller/internal/domain"
	"github.com/TrippingKelsea/nebula-starcaller/internal/store"
)

var (
	ErrNoSession      = errors.New("auth: no session")
	ErrSessionExpired = errors.New("auth: session expired")
)

type SessionManager struct {
	store      store.Store
	cookieName string
	ttl        time.Duration
	secure     bool
}

func NewSessionManager(s store.Store, cookieName string, ttl time.Duration, secure bool) *SessionManager {
	return &SessionManager{store: s, cookieName: cookieName, ttl: ttl, secure: secure}
}

// Issue creates a new session for a user and writes the session cookie on w.
func (m *SessionManager) Issue(ctx context.Context, w http.ResponseWriter, r *http.Request, userID string) (domain.Session, error) {
	id, err := randomID(32)
	if err != nil {
		return domain.Session{}, err
	}
	now := time.Now().UTC()
	sess := domain.Session{
		ID: id, UserID: userID,
		CreatedAt: now, ExpiresAt: now.Add(m.ttl),
		IP: clientIP(r), UserAgent: r.UserAgent(),
	}
	if err := m.store.CreateSession(ctx, sess); err != nil {
		return domain.Session{}, err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    id,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteStrictMode,
	})
	return sess, nil
}

// Get returns the session referenced by the request's cookie, or an error.
func (m *SessionManager) Get(ctx context.Context, r *http.Request) (domain.Session, error) {
	c, err := r.Cookie(m.cookieName)
	if err != nil {
		return domain.Session{}, ErrNoSession
	}
	sess, err := m.store.GetSession(ctx, c.Value)
	if err != nil {
		return domain.Session{}, ErrNoSession
	}
	if time.Now().UTC().After(sess.ExpiresAt) {
		return domain.Session{}, ErrSessionExpired
	}
	return sess, nil
}

// Revoke deletes the session referenced by the request cookie and clears the cookie.
func (m *SessionManager) Revoke(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie(m.cookieName)
	if err != nil {
		return nil // no session
	}
	_ = m.store.DeleteSession(ctx, c.Value)
	http.SetCookie(w, &http.Cookie{
		Name: m.cookieName, Value: "", Path: "/",
		Expires: time.Unix(0, 0), HttpOnly: true,
		Secure: m.secure, SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func randomID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return v
	}
	return r.RemoteAddr
}
