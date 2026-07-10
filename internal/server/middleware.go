package server

import (
	"net/http"

	"github.com/TrippingKelsea/nebula-starcaller/internal/auth"
)

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.Sessions.Get(r.Context(), r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		u, err := s.Store.GetUserByID(r.Context(), sess.UserID)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		ctx := auth.WithUser(r.Context(), u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
