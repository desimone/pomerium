// Package identity provides support for making OpenID Connect (OIDC)
// and OAuth2 authenticated HTTP requests with third party identity providers.
package identity

import (
	"context"
	"net/url"

	"github.com/pomerium/pomerium/internal/sessions"

	"golang.org/x/oauth2"
)

// Authenticator is an interface representing the ability to authenticate with an identity provider.
type Authenticator interface {
	Authenticate(context.Context, string) (*sessions.State, error)
	Refresh(context.Context, *sessions.State) (*sessions.State, error)
	Revoke(context.Context, *oauth2.Token) error
	GetSignInURL(state string) string
	LogOut() (*url.URL, error)
}

// Options contains the fields required for an OAuth 2.0 Authorization Request that
// requests that the End-User be authenticated by the Authorization Server.
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type Options struct {
	ProviderName string

	// ProviderURL is the endpoint to look for .well-known/openid-configuration
	ProviderURL string

	// OAuth2 Configuration settings
	RedirectURL  *url.URL
	ClientID     string
	ClientSecret string
	Scopes       []string

	// ServiceAccount can be set for those providers that require additional
	// credentials or tokens to do follow up API calls (e.g. Google)
	ServiceAccount string
}
