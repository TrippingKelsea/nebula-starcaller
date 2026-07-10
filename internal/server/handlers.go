package server

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/TrippingKelsea/nebula-starcaller/internal/auth"
	"github.com/TrippingKelsea/nebula-starcaller/internal/ca"
	"github.com/TrippingKelsea/nebula-starcaller/internal/cert"
	"github.com/TrippingKelsea/nebula-starcaller/internal/domain"
)

// render executes a named view template into w. The view template set has
// its own `body` so definitions don't collide across views.
func (s *Server) render(w http.ResponseWriter, name string, data any) {
	t, ok := s.views[name]
	if !ok {
		log.Printf("render: unknown view %s", name)
		http.Error(w, "unknown view", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base", data); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(w, "template render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

type page struct {
	Title string
	User  domain.User
	Flash string
	Data  any
}

func (s *Server) newPage(r *http.Request, title string, data any) page {
	p := page{Title: title, Data: data}
	if u, ok := auth.UserFrom(r.Context()); ok {
		p.User = u
	}
	return p
}

// ---- login / logout ----

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, "login.html", page{Title: "Sign in"})
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	u, err := auth.Login(r.Context(), s.Store, username, password)
	if err != nil {
		s.render(w, "login.html", page{Title: "Sign in", Flash: "invalid credentials"})
		return
	}
	if _, err := s.Sessions.Issue(r.Context(), w, r, u.ID); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	_ = s.Store.AppendAudit(r.Context(), domain.AuditEvent{
		At: time.Now().UTC(), Actor: u.ID, Action: "user.login", Subject: u.ID,
		IP: r.RemoteAddr, UserAgent: r.UserAgent(),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	_ = s.Sessions.Revoke(r.Context(), w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- dashboard ----

type dashboardData struct {
	CAs         []domain.CA
	RecentCerts []domain.Cert
	Users       int
	Audit       []domain.AuditEvent
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cas, _ := s.CA.List(ctx)
	var recent []domain.Cert
	for _, c := range cas {
		list, _ := s.Cert.List(ctx, c.ID)
		if len(list) > 5 {
			list = list[:5]
		}
		recent = append(recent, list...)
	}
	users, _ := s.Store.CountUsers(ctx)
	audit, _ := s.Store.ListAudit(ctx, 10)
	s.render(w, "dashboard.html", s.newPage(r, "Dashboard", dashboardData{
		CAs: cas, RecentCerts: recent, Users: users, Audit: audit,
	}))
}

// ---- CA CRUD ----

func (s *Server) handleCAList(w http.ResponseWriter, r *http.Request) {
	cas, err := s.CA.List(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, "ca_list.html", s.newPage(r, "CAs", cas))
}

func (s *Server) handleCANewForm(w http.ResponseWriter, r *http.Request) {
	groups, _ := s.Store.ListGroups(r.Context())
	s.render(w, "ca_new.html", s.newPage(r, "Create CA", groups))
}

func (s *Server) handleCACreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	dur, _ := time.ParseDuration(defaultString(r.FormValue("duration"), "8760h"))
	ttl, _ := time.ParseDuration(defaultString(r.FormValue("default_ttl"), "720h"))
	curve := domain.Curve(defaultString(r.FormValue("curve"), string(domain.Curve25519)))
	in := ca.CreateInput{
		Name:           strings.TrimSpace(r.FormValue("name")),
		Description:    r.FormValue("description"),
		Curve:          curve,
		Networks:       splitLines(r.FormValue("networks")),
		UnsafeNetworks: splitLines(r.FormValue("unsafe_networks")),
		Groups:         splitLines(r.FormValue("groups")),
		Duration:       dur,
		DefaultCertTTL: ttl,
	}
	c, err := s.CA.Create(r.Context(), in, u.ID)
	if err != nil {
		s.render(w, "ca_new.html", s.newPage(r, "Create CA", err.Error()))
		return
	}
	http.Redirect(w, r, "/ca/"+c.ID, http.StatusSeeOther)
}

type caDetailData struct {
	CA    domain.CA
	Certs []domain.Cert
}

func (s *Server) handleCADetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "caID")
	c, err := s.CA.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	certs, _ := s.Cert.List(r.Context(), id)
	s.render(w, "ca_detail.html", s.newPage(r, c.Name, caDetailData{CA: c, Certs: certs}))
}

func (s *Server) handleCARetire(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFrom(r.Context())
	if !auth.HasRole(u, domain.RoleAdmin) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "caID")
	if err := s.CA.Retire(r.Context(), id, u.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/ca/"+id, http.StatusSeeOther)
}

func (s *Server) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "caID")
	yml, err := s.Cert.Blocklist(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(yml))
}

// ---- Cert issue / detail / lifecycle ----

func (s *Server) handleCertNewForm(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "caID")
	c, err := s.CA.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.render(w, "cert_new.html", s.newPage(r, "Issue cert from "+c.Name, c))
}

func (s *Server) handleCertIssue(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	caID := chi.URLParam(r, "caID")
	ttl, _ := time.ParseDuration(defaultString(r.FormValue("ttl"), ""))
	in := cert.IssueInput{
		CAID:           caID,
		Name:           strings.TrimSpace(r.FormValue("name")),
		Networks:       splitLines(r.FormValue("networks")),
		UnsafeNetworks: splitLines(r.FormValue("unsafe_networks")),
		Groups:         splitLines(r.FormValue("groups")),
		HostRole:       domain.HostRole(defaultString(r.FormValue("host_role"), string(domain.HostRoleHost))),
		Platform: domain.Platform{
			OS:   defaultString(r.FormValue("os"), "linux"),
			Arch: defaultString(r.FormValue("arch"), "amd64"),
		},
		TTL: ttl,
	}
	c, _, err := s.Cert.Issue(r.Context(), in, u.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Redirect to detail; user can download from there
	http.Redirect(w, r, "/certs/"+c.ID, http.StatusSeeOther)
}

type certDetailData struct {
	Cert domain.Cert
	CA   domain.CA
}

func (s *Server) handleCertDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "certID")
	c, err := s.Cert.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	caRec, _ := s.CA.Get(r.Context(), c.IssuingCAID)
	s.render(w, "cert_detail.html", s.newPage(r, c.Name, certDetailData{Cert: c, CA: caRec}))
}

func (s *Server) handleCertDownload(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "certID")
	u, _ := auth.UserFrom(r.Context())
	data, err := s.Cert.DownloadBundle(r.Context(), id, u.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	c, _ := s.Cert.Get(r.Context(), id)
	filename := fmt.Sprintf("starcaller-%s-%s.tar.gz",
		strings.ReplaceAll(c.Name, "/", "-"),
		c.CreatedAt.Format("20060102T150405Z"))
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}

func (s *Server) handleCertRotate(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFrom(r.Context())
	id := chi.URLParam(r, "certID")
	newCert, _, err := s.Cert.Rotate(r.Context(), id, u.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/certs/"+newCert.ID, http.StatusSeeOther)
}

func (s *Server) handleCertRevoke(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFrom(r.Context())
	if !auth.HasRole(u, domain.RoleAdmin, domain.RoleOperator) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "certID")
	reason := r.FormValue("reason")
	if err := s.Cert.Revoke(r.Context(), id, reason, u.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/certs/"+id, http.StatusSeeOther)
}

// ---- audit ----

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFrom(r.Context())
	if !auth.HasRole(u, domain.RoleAdmin) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	events, _ := s.Store.ListAudit(r.Context(), 200)
	s.render(w, "audit.html", s.newPage(r, "Audit log", events))
}

// ---- utils ----

func defaultString(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	// Accept newline or comma separated. Trim, drop empties.
	replaced := strings.ReplaceAll(s, ",", "\n")
	parts := strings.Split(replaced, "\n")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
