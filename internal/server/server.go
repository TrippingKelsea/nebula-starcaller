// Package server wires HTTP routes to services.
package server

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/TrippingKelsea/nebula-starcaller/internal/auth"
	"github.com/TrippingKelsea/nebula-starcaller/internal/ca"
	"github.com/TrippingKelsea/nebula-starcaller/internal/cert"
	"github.com/TrippingKelsea/nebula-starcaller/internal/store"
)

type Server struct {
	Store    store.Store
	Sessions *auth.SessionManager
	CA       *ca.Service
	Cert     *cert.Service
	WebAuthn *auth.WebAuthnService // may be nil during MVP

	// views maps view name (e.g., "dashboard.html") to a fully parsed
	// template set that has both `base` and the view's `body` defined.
	views  map[string]*template.Template
	static fs.FS
}

// Assets holds the embedded HTML templates and static files.
type Assets struct {
	Templates embed.FS
	Static    embed.FS
}

func New(s *Server, a Assets) (*Server, error) {
	funcs := template.FuncMap{
		"join": func(sep string, xs []string) string {
			out := ""
			for i, x := range xs {
				if i > 0 {
					out += sep
				}
				out += x
			}
			return out
		},
	}
	// Read the base template once.
	baseBytes, err := fs.ReadFile(a.Templates, "templates/base.html")
	if err != nil {
		return nil, fmt.Errorf("read base.html: %w", err)
	}
	// Enumerate view files and parse each into its own set with base.
	entries, err := fs.ReadDir(a.Templates, "templates")
	if err != nil {
		return nil, err
	}
	views := make(map[string]*template.Template, len(entries))
	for _, e := range entries {
		if e.IsDir() || e.Name() == "base.html" {
			continue
		}
		body, err := fs.ReadFile(a.Templates, "templates/"+e.Name())
		if err != nil {
			return nil, err
		}
		t := template.New(e.Name()).Funcs(funcs)
		if _, err := t.Parse(string(baseBytes)); err != nil {
			return nil, fmt.Errorf("parse base.html for %s: %w", e.Name(), err)
		}
		if _, err := t.Parse(string(body)); err != nil {
			return nil, fmt.Errorf("parse %s: %w", e.Name(), err)
		}
		views[e.Name()] = t
	}
	static, err := fs.Sub(a.Static, "static")
	if err != nil {
		return nil, err
	}
	s.views = views
	s.static = static
	return s, nil
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.NoCache)

	// Static assets
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(s.static))))

	// Public
	r.Get("/login", s.handleLoginForm)
	r.Post("/login", s.handleLoginSubmit)
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	// Authenticated
	r.Group(func(r chi.Router) {
		r.Use(s.requireAuth)
		r.Get("/", s.handleDashboard)
		r.Post("/logout", s.handleLogout)

		// CAs
		r.Get("/ca", s.handleCAList)
		r.Get("/ca/new", s.handleCANewForm)
		r.Post("/ca", s.handleCACreate)
		r.Get("/ca/{caID}", s.handleCADetail)
		r.Post("/ca/{caID}/retire", s.handleCARetire)
		r.Get("/ca/{caID}/blocklist", s.handleBlocklist)

		// Certs
		r.Get("/ca/{caID}/certs/new", s.handleCertNewForm)
		r.Post("/ca/{caID}/certs", s.handleCertIssue)
		r.Get("/certs/{certID}", s.handleCertDetail)
		r.Get("/certs/{certID}/bundle", s.handleCertDownload)
		r.Post("/certs/{certID}/rotate", s.handleCertRotate)
		r.Post("/certs/{certID}/revoke", s.handleCertRevoke)

		// Audit
		r.Get("/audit", s.handleAudit)
	})

	return r
}
