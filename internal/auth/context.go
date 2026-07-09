package auth

import (
	"context"

	"github.com/TrippingKelsea/nebula-starcaller/internal/domain"
)

type ctxKey int

const userKey ctxKey = 1

func WithUser(ctx context.Context, u domain.User) context.Context {
	return context.WithValue(ctx, userKey, u)
}

func UserFrom(ctx context.Context) (domain.User, bool) {
	u, ok := ctx.Value(userKey).(domain.User)
	return u, ok
}

// HasRole reports whether the user has any of the given roles.
func HasRole(u domain.User, roles ...domain.Role) bool {
	for _, r := range roles {
		for _, ur := range u.Roles {
			if r == ur {
				return true
			}
		}
	}
	return false
}
