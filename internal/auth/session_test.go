package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TrippingKelsea/nebula-starcaller/internal/config"
	storesqlite "github.com/TrippingKelsea/nebula-starcaller/internal/store/sqlite"
)

func TestSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_ = EnsureBootstrap(ctx, s, config.Bootstrap{Username: "admin", Password: "p"})
	u, _ := s.GetUserByUsername(ctx, "admin")

	m := NewSessionManager(s, "starcaller_test", 30*time.Minute, false)

	// Issue
	req := httptest.NewRequest("GET", "http://example/", nil)
	req.RemoteAddr = "1.2.3.4"
	w := httptest.NewRecorder()
	sess, err := m.Issue(ctx, w, req, u.ID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if sess.ID == "" {
		t.Fatal("empty session id")
	}
	resp := w.Result()
	if len(resp.Cookies()) == 0 {
		t.Fatal("no cookie set")
	}
	c := resp.Cookies()[0]
	if !c.HttpOnly {
		t.Error("cookie should be HttpOnly")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Error("cookie should be SameSite=Strict")
	}

	// Get
	req2 := httptest.NewRequest("GET", "http://example/", nil)
	req2.AddCookie(c)
	got, err := m.Get(ctx, req2)
	if err != nil || got.UserID != u.ID {
		t.Errorf("Get: %+v err=%v", got, err)
	}

	// No cookie => ErrNoSession
	empty := httptest.NewRequest("GET", "http://example/", nil)
	if _, err := m.Get(ctx, empty); err != ErrNoSession {
		t.Errorf("no cookie: expected ErrNoSession, got %v", err)
	}

	// Revoke
	w2 := httptest.NewRecorder()
	if err := m.Revoke(ctx, w2, req2); err != nil {
		t.Errorf("Revoke: %v", err)
	}
	if _, err := m.Get(ctx, req2); err != ErrNoSession {
		t.Errorf("after revoke: expected ErrNoSession, got %v", err)
	}
}

func TestSessionExpiredIsRejected(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_ = EnsureBootstrap(ctx, s, config.Bootstrap{Username: "admin", Password: "p"})
	u, _ := s.GetUserByUsername(ctx, "admin")

	m := NewSessionManager(s, "sc", -time.Minute, false) // negative TTL => already expired
	req := httptest.NewRequest("GET", "http://example/", nil)
	w := httptest.NewRecorder()
	_, err := m.Issue(ctx, w, req, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	c := w.Result().Cookies()[0]
	req2 := httptest.NewRequest("GET", "http://example/", nil)
	req2.AddCookie(c)
	if _, err := m.Get(ctx, req2); err != ErrSessionExpired {
		t.Errorf("expected ErrSessionExpired, got %v", err)
	}
}

func newStoreForSession(t *testing.T) *storesqlite.Store {
	// Duplicate helper because bootstrap_test.go's newStore has different name — kept for clarity
	return newStore(t)
}

var _ = newStoreForSession // silence unused
