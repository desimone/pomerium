// Package gitlab implements OpenID Connect for Gitlab
//
// https://www.pomerium.io/docs/identity-providers/gitlab.html
package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/identity"
	pom_oidc "github.com/pomerium/pomerium/internal/identity/oidc"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/version"
)

// Name identifies the GitLab identity provider
const Name = "gitlab"

var defaultScopes = []string{oidc.ScopeOpenID, "api", "read_user", "profile", "email"}

const (
	defaultProviderURL = "https://gitlab.com"
	groupPath          = "/api/v4/groups"
)

// GitLabProvider is a Gitlab implementation of the Authenticator interface.
type GitLabProvider struct {
	*pom_oidc.OpenIDProvider

	userGroupURL string
}

// New instantiates an OpenID Connect (OIDC) provider for Gitlab.
func New(ctx context.Context, o *identity.Options) (*GitLabProvider, error) {
	var p GitLabProvider
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
	p.userGroupURL = o.ProviderURL + groupPath

	return &p, nil
}

// UserGroups returns a slice of groups for the user.
//
// Returns 20 results at a time because the API results are paginated.
// https://docs.gitlab.com/ee/api/groups.html#list-groups
func (p *GitLabProvider) UserGroups(ctx context.Context, s *sessions.State) ([]string, error) {
	if s == nil || s.AccessToken == nil {
		return nil, errors.New("gitlab: user session cannot be empty")
	}

	var response []struct {
		ID                             json.Number `json:"id"`
		Name                           string      `json:"name,omitempty"`
		Path                           string      `json:"path,omitempty"`
		Description                    string      `json:"description,omitempty"`
		Visibility                     string      `json:"visibility,omitempty"`
		ShareWithGroupLock             bool        `json:"share_with_group_lock,omitempty"`
		RequireTwoFactorAuthentication bool        `json:"require_two_factor_authentication,omitempty"`
		SubgroupCreationLevel          string      `json:"subgroup_creation_level,omitempty"`
		FullName                       string      `json:"full_name,omitempty"`
		FullPath                       string      `json:"full_path,omitempty"`
	}
	headers := map[string]string{"Authorization": fmt.Sprintf("Bearer %s", s.AccessToken.AccessToken)}
	err := httputil.Client(ctx, http.MethodGet, p.userGroupURL, version.UserAgent(), headers, nil, &response)
	if err != nil {
		return nil, err
	}

	var groups []string
	log.Debug().Interface("response", response).Msg("gitlab: groups")
	for _, group := range response {
		groups = append(groups, group.ID.String())
	}

	return groups, nil
}
