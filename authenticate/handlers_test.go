package authenticate

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/templates"
)

func testAuthenticate() *Authenticate {
	var auth Authenticate
	auth.RedirectURL, _ = url.Parse("https://auth.example.com/oauth/callback")
	auth.sharedKey = "IzY7MOZwzfOkmELXgozHDKTxoT3nOYhwkcmUVINsRww="
	auth.cookieSecret = []byte(auth.sharedKey)
	auth.cookieOptions = &sessions.CookieOptions{Name: "name"}
	auth.templates = templates.New()
	return &auth
}

func TestAuthenticate_RobotsTxt(t *testing.T) {
	auth := testAuthenticate()
	req, err := http.NewRequest("GET", "/robots.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(auth.RobotsTxt)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	expected := fmt.Sprintf("User-agent: *\nDisallow: /")
	if rr.Body.String() != expected {
		t.Errorf("handler returned wrong body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestAuthenticate_Handler(t *testing.T) {
	auth := testAuthenticate()

	h := auth.Handler()
	if h == nil {
		t.Error("handler cannot be nil")
	}
	req := httptest.NewRequest("GET", "/robots.txt", nil)
	req.Header.Set("Accept", "application/json")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	expected := fmt.Sprintf("User-agent: *\nDisallow: /")

	body := rr.Body.String()
	if body != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expected)
	}
}

func TestAuthenticate_SignIn(t *testing.T) {
	t.Parallel()
	aead, err := chacha20poly1305.NewX(cryptutil.NewKey())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		state       string
		redirectURI string
		session     sessions.SessionStore
		provider    identity.MockProvider
		encoder     sessions.Encoder
		wantCode    int
	}{
		{"good",
			"state=example",
			"https://some.example",
			&sessions.MockSessionStore{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}},
			identity.MockProvider{},
			&cryptutil.MockEncoder{},
			http.StatusFound},
		{"session not valid",
			"state=example",
			"https://some.example",
			&sessions.MockSessionStore{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(-10 * time.Second)}}},
			identity.MockProvider{},
			&cryptutil.MockEncoder{},
			http.StatusFound},
		{"bad redirect uri query",
			"state=example",
			"%gh&%ij",
			&sessions.MockSessionStore{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}},
			identity.MockProvider{},
			&cryptutil.MockEncoder{},
			http.StatusBadRequest},
		{"bad marshal",
			"state=example",
			"https://some.example",
			&sessions.MockSessionStore{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}},
			identity.MockProvider{},
			&cryptutil.MockEncoder{MarshalError: errors.New("error")},
			http.StatusBadRequest},
		{"session error",
			"state=example",
			"https://some.example",
			&sessions.MockSessionStore{LoadError: errors.New("error")},
			identity.MockProvider{},
			&cryptutil.MockEncoder{},
			http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticate{
				sessionStore:  tt.session,
				provider:      tt.provider,
				RedirectURL:   uriParseHelper("https://some.example"),
				sharedKey:     "secret",
				sharedEncoder: tt.encoder,
				sharedCipher:  aead,
				cookieOptions: &sessions.CookieOptions{
					Name:   "cookie",
					Domain: "foo",
				},
			}
			uri := &url.URL{Host: "corp.some.example", Scheme: "https", Path: "/"}
			uri.RawQuery = fmt.Sprintf("%s&redirect_uri=%s", tt.state, tt.redirectURI)
			r := httptest.NewRequest(http.MethodGet, uri.String(), nil)
			r.Header.Set("Accept", "application/json")
			state, err := tt.session.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, err)
			r = r.WithContext(ctx)

			w := httptest.NewRecorder()

			a.SignIn(w, r)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v %s", status, tt.wantCode, uri)
				t.Errorf("\n%+v", w.Body)
			}
		})
	}
}

func uriParseHelper(s string) *url.URL {
	uri, _ := url.Parse(s)
	return uri
}

func TestAuthenticate_SignOut(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		method string

		ctxError    error
		redirectURL string
		sig         string
		ts          string

		provider     identity.Authenticator
		sessionStore sessions.SessionStore
		wantCode     int
		wantBody     string
	}{
		{"good post", http.MethodPost, nil, "https://corp.pomerium.io/", "sig", "ts", identity.MockProvider{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, http.StatusFound, ""},
		{"failed revoke", http.MethodPost, nil, "https://corp.pomerium.io/", "sig", "ts", identity.MockProvider{RevokeError: errors.New("OH NO")}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, http.StatusBadRequest, "could not revoke"},
		{"load session error", http.MethodPost, nil, "https://corp.pomerium.io/", "sig", "ts", identity.MockProvider{RevokeError: errors.New("OH NO")}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, http.StatusBadRequest, "could not revoke"},
		{"bad redirect uri", http.MethodPost, nil, "corp.pomerium.io/", "sig", "ts", identity.MockProvider{}, &sessions.MockSessionStore{Session: &sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, http.StatusBadRequest, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticate{
				sessionStore: tt.sessionStore,
				provider:     tt.provider,
				templates:    templates.New(),
			}
			u, _ := url.Parse("/sign_out")
			params, _ := url.ParseQuery(u.RawQuery)
			params.Add("sig", tt.sig)
			params.Add("ts", tt.ts)
			params.Add("redirect_uri", tt.redirectURL)
			u.RawQuery = params.Encode()
			r := httptest.NewRequest(tt.method, u.String(), nil)
			state, _ := tt.sessionStore.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)
			w := httptest.NewRecorder()

			a.SignOut(w, r)
			if status := w.Code; status != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.wantCode)
			}
			if body := w.Body.String(); !strings.Contains(body, tt.wantBody) {
				t.Errorf("handler returned wrong body Body: got \n%s \n%s", body, tt.wantBody)
			}
		})
	}
}

func TestAuthenticate_OAuthCallback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string

		ts            int64
		stateOvveride string
		extraMac      string
		extraState    string
		paramErr      string
		code          string
		redirectURI   string

		authenticateURL string
		session         sessions.SessionStore
		provider        identity.MockProvider

		want     string
		wantCode int
	}{
		{"good", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "https://corp.pomerium.io", http.StatusFound},
		{"failed authenticate", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateError: errors.New("error")}, "", http.StatusInternalServerError},
		{"failed save session", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{SaveError: errors.New("error")}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "", http.StatusInternalServerError},
		{"provider returned error", http.MethodGet, time.Now().Unix(), "", "", "", "idp error", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "", http.StatusBadRequest},
		{"empty code", http.MethodGet, time.Now().Unix(), "", "", "", "", "", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "", http.StatusBadRequest},
		{"invalid redirect uri", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "", http.StatusBadRequest},
		{"bad redirect uri", http.MethodGet, time.Now().Unix(), "", "", "", "", "code", "http://^^^", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad timing - too soon", http.MethodGet, time.Now().Add(1 * time.Hour).Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad timing - expired", http.MethodGet, time.Now().Add(-1 * time.Hour).Unix(), "", "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad base64", http.MethodGet, time.Now().Unix(), "", "", "^", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"too many seperators", http.MethodGet, time.Now().Unix(), "", "", "|ok|now|what", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad hmac", http.MethodGet, time.Now().Unix(), "", "NOTMAC", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "https://corp.pomerium.io", http.StatusBadRequest},
		{"bad hmac", http.MethodGet, time.Now().Unix(), base64.URLEncoding.EncodeToString([]byte("malformed_state")), "", "", "", "code", "https://corp.pomerium.io", "https://authenticate.pomerium.io", &sessions.MockSessionStore{}, identity.MockProvider{AuthenticateResponse: sessions.State{Email: "user@pomerium.io", AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Second)}}}, "https://corp.pomerium.io", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aead, err := chacha20poly1305.NewX(cryptutil.NewKey())
			if err != nil {
				t.Fatal(err)
			}
			authURL, _ := url.Parse(tt.authenticateURL)
			a := &Authenticate{
				RedirectURL:  authURL,
				sessionStore: tt.session,
				provider:     tt.provider,
				cookieCipher: aead,
			}
			u, _ := url.Parse("/oauthGet")
			params, _ := url.ParseQuery(u.RawQuery)
			params.Add("error", tt.paramErr)
			params.Add("code", tt.code)
			nonce := cryptutil.NewBase64Key() // mock csrf

			// (nonce|timestamp|redirect_url|encrypt(redirect_url),mac(nonce,ts))
			b := []byte(fmt.Sprintf("%s|%d|%s", nonce, tt.ts, tt.extraMac))

			enc := cryptutil.Encrypt(a.cookieCipher, []byte(tt.redirectURI), b)
			b = append(b, enc...)
			encodedState := base64.URLEncoding.EncodeToString(b)
			if tt.extraState != "" {
				encodedState += tt.extraState
			}
			if tt.stateOvveride != "" {
				encodedState = tt.stateOvveride
			}
			params.Add("state", encodedState)

			u.RawQuery = params.Encode()

			r := httptest.NewRequest(tt.method, u.String(), nil)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()

			a.OAuthCallback(w, r)
			if w.Result().StatusCode != tt.wantCode {
				t.Errorf("Authenticate.OAuthCallback() error = %v, wantErr %v\n%v", w.Result().StatusCode, tt.wantCode, w.Body.String())
				return
			}
		})
	}
}

// // func TestAuthenticate_ExchangeToken(t *testing.T) {
// // 	t.Parallel()
// // 	tests := []struct {
// // 		name      string
// // 		method    string
// // 		idToken   string
// // 		restStore sessions.SessionStore
// // 		encoder   sessions.Encoder
// // 		provider  identity.MockProvider
// // 		want      string
// // 	}{
// // 		{"good", http.MethodPost, "token", &sessions.MockSessionStore{}, &cryptutil.MockEncoder{}, identity.MockProvider{IDTokenToSessionResponse: sessions.State{IDToken: "ok"}}, ""},
// // 		{"could not exchange identity for session", http.MethodPost, "token", &sessions.MockSessionStore{}, &cryptutil.MockEncoder{}, identity.MockProvider{IDTokenToSessionError: errors.New("error")}, ""},
// // 		{"missing token", http.MethodPost, "", &sessions.MockSessionStore{}, &cryptutil.MockEncoder{}, identity.MockProvider{IDTokenToSessionResponse: sessions.State{IDToken: "ok"}}, "missing id token"},
// // 		{"malformed form", http.MethodPost, "token", &sessions.MockSessionStore{}, &cryptutil.MockEncoder{}, identity.MockProvider{IDTokenToSessionResponse: sessions.State{IDToken: "ok"}}, ""},
// // 		{"can't marshal token", http.MethodPost, "token", &sessions.MockSessionStore{}, &cryptutil.MockEncoder{MarshalError: errors.New("can't marshal token")}, identity.MockProvider{IDTokenToSessionResponse: sessions.State{IDToken: "ok"}}, "can't marshal token"},
// // 	}
// // 	for _, tt := range tests {
// // 		t.Run(tt.name, func(t *testing.T) {
// // 			aead, err := chacha20poly1305.NewX(cryptutil.NewKey())
// // 			if err != nil {
// // 				t.Fatal(err)
// // 			}
// // 			a := &Authenticate{
// // 				encoder:      tt.encoder,
// // 				provider:     tt.provider,
// // 				sessionStore: tt.restStore,
// // 				cipher:       aead,
// // 			}
// // 			form := url.Values{}
// // 			if tt.idToken != "" {
// // 				form.Add("id_token", tt.idToken)
// // 			}
// // 			rawForm := form.Encode()

// // 			if tt.name == "malformed form" {
// // 				rawForm = "example=%zzzzz"
// // 			}
// // 			r := httptest.NewRequest(tt.method, "/", strings.NewReader(rawForm))
// // 			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
// // 			r.Header.Set("Accept", "application/json")

// // 			w := httptest.NewRecorder()

// // 			a.ExchangeToken(w, r)
// // 			got := w.Body.String()
// // 			if !strings.Contains(got, tt.want) {
// // 				t.Errorf("Authenticate.ExchangeToken() = %v, want %v", got, tt.want)
// // 			}
// // 		})
// // 	}
// // }
