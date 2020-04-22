// Package onelogin implements OpenID Connect for OneLogin
//
// https://www.pomerium.io/docs/identity-providers/one-login.html
package onelogin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	oidc "github.com/coreos/go-oidc"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/identity"
	pom_oidc "github.com/pomerium/pomerium/internal/identity/oidc"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/version"
)

const (
	// Name identifies the OneLogin identity provider
	Name = "onelogin"

	defaultProviderURL      = "https://openid-connect.onelogin.com/oidc"
	defaultOneloginGroupURL = "https://openid-connect.onelogin.com/oidc/me"
)

var defaultScopes = []string{oidc.ScopeOpenID, "profile", "email", "groups", "offline_access"}

// OneLoginProvider is an OneLogin implementation of the Authenticator interface.
type OneLoginProvider struct {
	*pom_oidc.OpenIDProvider
}

// New instantiates an OpenID Connect (OIDC) provider for OneLogin.
func New(ctx context.Context, o *identity.Options) (*OneLoginProvider, error) {
	var p OneLoginProvider
	var err error
	if o.ProviderURL == "" {
		o.ProviderURL = defaultProviderURL
	}
	if len(o.Scopes) == 0 {
		o.Scopes = defaultScopes
	}
	genericOidc, err := pom_oidc.New(ctx, o)
	if err != nil {
		return nil, fmt.Errorf("%s: failed creating oidc provider: %w", Name, err)
	}
	p.OpenIDProvider = genericOidc
	p.UserGroupFn = p.UserGroups
	return &p, nil
}

// UserGroups returns a slice of group names a given user is in.
// https://developers.onelogin.com/openid-connect/api/user-info
func (p *OneLoginProvider) UserGroups(ctx context.Context, s *sessions.State) ([]string, error) {
	if s == nil || s.AccessToken == nil {
		return nil, errors.New("identity/onelogin: session cannot be nil")
	}
	var response struct {
		User              string    `json:"sub"`
		Email             string    `json:"email"`
		PreferredUsername string    `json:"preferred_username"`
		Name              string    `json:"name"`
		UpdatedAt         time.Time `json:"updated_at"`
		GivenName         string    `json:"given_name"`
		FamilyName        string    `json:"family_name"`
		Groups            []string  `json:"groups"`
	}
	headers := map[string]string{"Authorization": fmt.Sprintf("Bearer %s", s.AccessToken.AccessToken)}
	err := httputil.Client(ctx, http.MethodGet, defaultOneloginGroupURL, version.UserAgent(), headers, nil, &response)
	if err != nil {
		return nil, err
	}
	return response.Groups, nil
}
