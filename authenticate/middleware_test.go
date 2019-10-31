package authenticate

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/sessions"
)

func TestAuthenticate_SessionValidatorMiddleware(t *testing.T) {
	t.Parallel()
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprintln(w, "RVSI FILIVS CAISAR")
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name     string
		session  sessions.SessionStore
		ctxError error
		provider identity.Authenticator

		wantStatus int
	}{
		{"good", &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, nil, identity.MockProvider{RefreshResponse: sessions.State{AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Minute)}}}, http.StatusOK},
		{"invalid session", &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}}, errors.New("hi"), identity.MockProvider{}, http.StatusFound},
		{"good refersh expired", &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, sessions.ErrExpired, identity.MockProvider{RefreshResponse: sessions.State{AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Minute)}}}, http.StatusOK},
		{"expired,refresh error", &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, sessions.ErrExpired, identity.MockProvider{RefreshError: errors.New("error")}, http.StatusFound},
		{"expired,save error", &sessions.MockSessionStore{SaveError: errors.New("error"), Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, sessions.ErrExpired, identity.MockProvider{RefreshResponse: sessions.State{AccessToken: &oauth2.Token{Expiry: time.Now().Add(10 * time.Minute)}}}, http.StatusFound},
		{"good refersh expired", &sessions.MockSessionStore{Session: &sessions.State{Email: "user@test.example", Expiry: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))}}, sessions.ErrExpired, identity.MockProvider{RefreshResponse: sessions.State{AccessToken: nil}}, http.StatusFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aead, err := chacha20poly1305.NewX(cryptutil.NewKey())
			if err != nil {
				t.Fatal(err)
			}
			a := Authenticate{
				sharedKey:    "80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ=",
				cookieSecret: []byte("80ldlrU2d7w+wVpKNfevk6fmb8otEx6CqOfshj2LwhQ="),
				RedirectURL:  uriParseHelper("https://authenticate.corp.beyondperimeter.com"),
				sessionStore: tt.session,
				provider:     tt.provider,
				cookieCipher: aead,
			}
			r := httptest.NewRequest("GET", "/", nil)
			state, _ := tt.session.LoadSession(r)
			ctx := r.Context()
			ctx = sessions.NewContext(ctx, state, tt.ctxError)
			r = r.WithContext(ctx)

			r.Header.Set("Accept", "application/json")

			w := httptest.NewRecorder()

			got := a.VerifySession(fn)
			got.ServeHTTP(w, r)
			if status := w.Code; status != tt.wantStatus {
				t.Errorf("VerifySession() error = %v, wantErr %v\n%v", w.Result().StatusCode, tt.wantStatus, w.Body.String())

			}
		})
	}
}
