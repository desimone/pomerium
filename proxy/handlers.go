package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"
	"github.com/pomerium/csrf"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/templates"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// registerDashboardHandlers returns the proxy service's ServeMux
func (p *Proxy) registerDashboardHandlers(r *mux.Router) *mux.Router {
	// dashboard subrouter
	h := r.PathPrefix(dashboardURL).Subrouter()

	c := r.PathPrefix(dashboardURL + "/callback").Subrouter()
	// verify that the caller of our callback url is trust
	c.Use(middleware.ValidateSignature(p.SharedKey))
	c.HandleFunc("/", p.Callback).Methods(http.MethodGet)

	// 1. Retrieve the user session and add it to the request context
	h.Use(sessions.RetrieveSession(p.sessionStore))
	// 2. AuthN - Verify the user is authenticated. Set email, group, & id headers
	h.Use(p.AuthenticateSession)
	// 3. Enforce CSRF protections for any non-idempotent http method
	h.Use(csrf.Protect(
		p.cookieSecret,
		csrf.Secure(p.cookieOptions.Secure),
		csrf.CookieName(fmt.Sprintf("%s_csrf", p.cookieOptions.Name)),
		csrf.ErrorHandler(http.HandlerFunc(httputil.CSRFFailureHandler)),
	))
	h.HandleFunc("/", p.UserDashboard).Methods(http.MethodGet)
	h.HandleFunc("/impersonate", p.Impersonate).Methods(http.MethodPost)
	h.HandleFunc("/sign_out", p.SignOut).Methods(http.MethodGet, http.MethodPost)
	return r
}

// RobotsTxt sets the User-Agent header in the response to be "Disallow"
func (p *Proxy) RobotsTxt(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User-agent: *\nDisallow: /")
}

// SignOut redirects the request to the sign out url. It's the responsibility
// of the authenticate service to revoke the remote session and clear
// the local session state.
func (p *Proxy) SignOut(w http.ResponseWriter, r *http.Request) {
	redirectURL := &url.URL{Scheme: "https", Host: r.Host, Path: "/"}
	if uri, err := urlutil.ParseAndValidateURL(r.FormValue("redirect_uri")); err == nil && uri.String() != "" {
		redirectURL = uri
	}
	uri := urlutil.SignedRedirectURL(p.SharedKey, p.authenticateSignoutURL, redirectURL)
	// clear our route-scoped session
	p.sessionStore.ClearSession(w, r)
	http.Redirect(w, r, uri.String(), http.StatusFound)
}

// UserDashboard lets users investigate, and refresh their current session.
// It also contains certain administrative actions like user impersonation.
// Nota bene: This endpoint does authentication, not authorization.
func (p *Proxy) UserDashboard(w http.ResponseWriter, r *http.Request) {
	session, err := sessions.FromContext(r.Context())
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}

	isAdmin, err := p.AuthorizeClient.IsAdmin(r.Context(), session)
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}

	templates.New().ExecuteTemplate(w, "dashboard.html", map[string]interface{}{
		"Session":   session,
		"IsAdmin":   isAdmin,
		"csrfField": csrf.TemplateField(r),
	})
}

// Impersonate takes the result of a form and adds user impersonation details
// to the user's current user sessions state if the user is currently an
// administrative user. Requests are redirected back to the user dashboard.
func (p *Proxy) Impersonate(w http.ResponseWriter, r *http.Request) {
	session, err := sessions.FromContext(r.Context())
	if err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}
	isAdmin, err := p.AuthorizeClient.IsAdmin(r.Context(), session)
	if err != nil || !isAdmin {
		errStr := fmt.Sprintf("%s is not an administrator", session.RequestEmail())
		httpErr := httputil.Error(errStr, http.StatusForbidden, err)
		httputil.ErrorResponse(w, r, httpErr)
		return
	}
	// OK to impersonation
	session.ImpersonateEmail = r.FormValue("email")
	session.ImpersonateGroups = strings.Split(r.FormValue("group"), ",")
	groups := r.FormValue("group")
	if groups != "" {
		session.ImpersonateGroups = strings.Split(groups, ",")
	}
	if err := p.sessionStore.SaveSession(w, r, session); err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}
	http.Redirect(w, r, dashboardURL, http.StatusFound)
}

func (p *Proxy) registerFwdAuthHandlers() http.Handler {
	r := httputil.NewRouter()
	r.StrictSlash(true)
	r.Use(sessions.RetrieveSession(p.sessionStore))
	r.HandleFunc("/", p.VerifyAndSignin).Queries("uri", "{uri}").Methods(http.MethodGet)
	r.HandleFunc("/verify", p.VerifyOnly).Queries("uri", "{uri}").Methods(http.MethodGet)
	return r
}

// VerifyAndSignin checks a user's credentials for an arbitrary host. If the user
// is properly authenticated and is authorized to access the supplied host,
// a `200` http status code is returned. If the user is not authenticated, they
// will be redirected to the authenticate service to sign in with their identity
// provider. If the user is unauthorized, a `401` error is returned.
func (p *Proxy) VerifyAndSignin(w http.ResponseWriter, r *http.Request) {
	uri, err := urlutil.ParseAndValidateURL(r.FormValue("uri"))
	if err != nil || uri.String() == "" {
		httputil.ErrorResponse(w, r, httputil.Error("bad verification uri given", http.StatusBadRequest, nil))
		return
	}
	if err := p.authenticate(w, r); err != nil {
		uri := urlutil.SignedRedirectURL(p.SharedKey, p.authenticateSigninURL, urlutil.GetAbsoluteURL(r))
		http.Redirect(w, r, uri.String(), http.StatusFound)
	}
	if err := p.authorize(r, uri); err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("", http.StatusUnauthorized, err))
		return
	}
	// check the queryparams to see if this check immediately followed
	// authentication. If so, redirect back to the originally requested hostname.
	if isCallback := r.URL.Query().Get(callbackQueryParam); isCallback == "true" {
		q := uri.Query()
		q.Del(callbackQueryParam)
		uri.RawQuery = q.Encode()
		http.Redirect(w, r, uri.String(), http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
}

// VerifyOnly checks a user's credentials for an arbitrary host. If the user
// is properly authenticated and is authorized to access the supplied host,
// a `200` http status code is returned otherwise a `401` error is returned.
func (p *Proxy) VerifyOnly(w http.ResponseWriter, r *http.Request) {
	uri, err := urlutil.ParseAndValidateURL(r.FormValue("uri"))
	if err != nil || uri.String() == "" {
		httputil.ErrorResponse(w, r, httputil.Error("bad verification uri given", http.StatusBadRequest, nil))
		return
	}
	if err := p.authenticate(w, r); err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("", http.StatusUnauthorized, err))
		return
	}
	if err := p.authorize(r, uri); err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("", http.StatusUnauthorized, err))
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
}

func (p *Proxy) authorize(r *http.Request, uri *url.URL) error {
	// attempt to retrieve the user session from the request context, validity
	// of the identity session is asserted by the middleware chain
	s, err := sessions.FromContext(r.Context())
	if err != nil {
		return err
	}
	// query the authorization service to see if the session's user has
	// the appropriate authorization to access the given hostname
	authorized, err := p.AuthorizeClient.Authorize(r.Context(), uri.Host, s)
	if err != nil {
		return err
	} else if !authorized {
		return fmt.Errorf("%s is not authorized for %s", s.RequestEmail(), uri.String())
	}
	return nil
}

func (p *Proxy) Callback(w http.ResponseWriter, r *http.Request) {
	redirectURL, err := urlutil.ParseAndValidateURL(r.FormValue("redirect_uri"))
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("malformed redirect_uri", http.StatusBadRequest, err))
		return
	}
	encryptedJWT, err := base64.URLEncoding.DecodeString(redirectURL.Query().Get("jwt"))
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("", http.StatusBadRequest, err))
		return
	}
	rawJWT, err := cryptutil.Decrypt(p.sharedCipher, encryptedJWT, nil)
	if err != nil {
		httputil.ErrorResponse(w, r, httputil.Error("", http.StatusBadRequest, err))
		return
	}

	if err = p.sessionStore.SaveSession(w, r, rawJWT); err != nil {
		httputil.ErrorResponse(w, r, err)
		return
	}
	// cleanup encrypted jwt token and redirect
	q := redirectURL.Query()
	q.Del("jwt")
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}
