package authenticate // import "github.com/pomerium/pomerium/authenticate"

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
)

// VerifySession is the middleware used to enforce a valid authentication
// session state is attached to the users's request context.
func (a *Authenticate) VerifySession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, err := sessions.FromContext(r.Context())
		if errors.Is(err, sessions.ErrExpired) {
			if err := a.refresh(w, r, state); err != nil {
				log.FromRequest(r).Debug().Str("cause", err.Error()).Msg("authenticate: refresh failed")
				a.sessionStore.ClearSession(w, r)
				a.redirectToIdentityProvider(w, r)
				return
			}

		} else if err != nil {
			log.FromRequest(r).Err(err).Msg("authenticate: unexpected session state")
			a.sessionStore.ClearSession(w, r)
			a.redirectToIdentityProvider(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Authenticate) refresh(w http.ResponseWriter, r *http.Request, s *sessions.State) error {
	newSession, err := a.provider.Refresh(r.Context(), s.AccessToken)
	if err != nil {
		return fmt.Errorf("authenticate: refresh failed: %w", err)
	}

	// keep existing state but update access token, expiry, and groups
	if err := s.RefreshState(newSession); err != nil {
		return fmt.Errorf("authenticate: refresh struct update failed: %w", err)
	}

	if err := a.sessionStore.SaveSession(w, r, s); err != nil {
		return fmt.Errorf("authenticate: refresh save failed: %w", err)
	}
	return nil

}
