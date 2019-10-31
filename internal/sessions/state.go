package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"errors"
	"fmt"
	"strings"
	"time"

	oidc "github.com/pomerium/go-oidc"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/pomerium/internal/log"
)

const (
	// DefaultLeeway defines the default leeway for matching NotBefore/Expiry claims.
	DefaultLeeway = 1.0 * time.Minute
)

// timeNow is time.Now but pulled out as a variable for tests.
var timeNow = time.Now

// State is our object that keeps track of a user's session state
type State struct {
	// Public claim values (as specified in RFC 7519).
	Issuer    string           `json:"iss,omitempty"`
	Subject   string           `json:"sub,omitempty"`
	Audience  jwt.Audience     `json:"aud,omitempty"`
	Expiry    *jwt.NumericDate `json:"exp,omitempty"`
	NotBefore *jwt.NumericDate `json:"nbf,omitempty"`
	IssuedAt  *jwt.NumericDate `json:"iat,omitempty"`
	ID        string           `json:"jti,omitempty"`

	// core pomerium identity claims ; not standard to RFC 7519
	Email  string   `json:"email"`
	Groups []string `json:"groups,omitempty"`
	User   string   `json:"user,omitempty"` // google

	// commonly supported IdP information
	// https://www.iana.org/assignments/jwt/jwt.xhtml#claims
	Name          string `json:"name,omitempty"`           // google
	GivenName     string `json:"given_name,omitempty"`     // google
	FamilyName    string `json:"family_name,omitempty"`    // google
	Picture       string `json:"picture,omitempty"`        // google
	EmailVerified bool   `json:"email_verified,omitempty"` // google

	// Impersonate-able fields
	ImpersonateEmail  string   `json:"impersonate_email,omitempty"`
	ImpersonateGroups []string `json:"impersonate_groups,omitempty"`

	AccessToken *oauth2.Token `json:"access_token,omitempty"`

	idToken *oidc.IDToken
}

func StateFromIDToken(idToken *oidc.IDToken, audience string) (*State, error) {
	if idToken == nil {
		return nil, errors.New("sessions: no oidc jwt id token for new identity")
	}
	s := &State{}
	if err := idToken.Claims(s); err != nil {
		return nil, fmt.Errorf("sessions: couldn't unmarshal extra claims %w", err)
	}
	log.Info().Interface("s", s).Msg("StateFromIDToken")
	s.Audience = append(s.Audience, audience)
	s.idToken = idToken

	return s, nil
}

func (s State) RouteState(issuer string, audience string, validFor time.Duration) State {
	newState := s
	newState.Issuer = issuer
	newState.Audience = append(s.Audience, audience)

	newExpiration := timeNow().Add(validFor)
	// we should not create a derived identity that is longer lived than it's parent
	if s.AccessToken != nil && newExpiration.After(s.AccessToken.Expiry) {
		newExpiration = s.AccessToken.Expiry
	}
	newState.Expiry = jwt.NewNumericDate(timeNow().Add(validFor))
	newState.IssuedAt = jwt.NewNumericDate(timeNow())
	newState.NotBefore = newState.IssuedAt
	newState.AccessToken = nil
	return newState
}

// Verify returns an error if the users's session state is not valid.
func (s *State) Verify(audience string) error {
	if s.NotBefore != nil && timeNow().Add(DefaultLeeway).Before(s.NotBefore.Time()) {
		return ErrNotValidYet
	}

	if s.Expiry != nil && timeNow().Add(-DefaultLeeway).After(s.Expiry.Time()) {
		return ErrExpired
	}

	if s.IssuedAt != nil && timeNow().Add(DefaultLeeway).Before(s.IssuedAt.Time()) {
		return ErrIssuedInTheFuture
	}

	// if we have an associated access token, check if that token has expired as well
	if s.AccessToken != nil && timeNow().Add(-DefaultLeeway).After(s.AccessToken.Expiry) {
		return ErrExpired
	}

	if len(s.Audience) != 0 {
		if !s.Audience.Contains(audience) {
			return ErrInvalidAudience
		}

	}
	return nil
}

// RefreshState updates the state fields that are changed after a successful refresh
func (s *State) RefreshState(newState *State) error {
	if newState.AccessToken == nil {
		return errors.New("sessions: access token cannot be nill")
	}
	s.AccessToken = newState.AccessToken
	s.Expiry = jwt.NewNumericDate(newState.AccessToken.Expiry)
	s.Groups = newState.Groups
	return nil
}

// ForceRefresh sets the refresh deadline to now.
func (s *State) ForceRefresh() {
	s.idToken.Expiry = time.Now().Add(-time.Hour).Truncate(time.Second)
}

// Impersonating returns if the request is impersonating.
func (s *State) Impersonating() bool {
	return s.ImpersonateEmail != "" || len(s.ImpersonateGroups) != 0
}

// RequestEmail is the email to make the request as.
func (s *State) RequestEmail() string {
	if s.ImpersonateEmail != "" {
		return s.ImpersonateEmail
	}
	return s.Email
}

// RequestGroups returns the groups of the Groups making the request; uses
// impersonating user if set.
func (s *State) RequestGroups() string {
	if len(s.ImpersonateGroups) != 0 {
		return strings.Join(s.ImpersonateGroups, ",")
	}
	return strings.Join(s.Groups, ",")
}
