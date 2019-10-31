package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/encoding/ecjson"

	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/pomerium/internal/cryptutil"
)

// type MockEncoder struct {
// }

// func (a MockEncoder) Marshal(s interface{}) (string, error) { return "", errors.New("error") }
// func (a MockEncoder) Unmarshal(s string, i interface{}) error {
// 	if s == "unmarshal error" || s == "error" {
// 		return errors.New("error")
// 	}
// 	return nil
// }

// func TestNewCookieStore(t *testing.T) {
// 	cipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	encoder := ecjson.New(cipher)
// 	tests := []struct {
// 		name    string
// 		opts    *CookieOptions
// 		want    *CookieStore
// 		wantErr bool
// 	}{
// 		{"good",
// 			&CookieOptions{
// 				Name:           "_cookie",
// 				Secure:   true,
// 				HTTPOnly: true,
// 				Domain:   "pomerium.io",
// 				Expire:   10 * time.Second,
// 			},
// 			&CookieStore{
// 				Name:           "_cookie",
// 				Secure:   true,
// 				HTTPOnly: true,
// 				Domain:   "pomerium.io",
// 				Expire:   10 * time.Second,
// 			},
// 			false},
// 		{"missing name",
// 			&CookieOptions{
// 				Name:           "",
// 				Secure:   true,
// 				HTTPOnly: true,
// 				Domain:   "pomerium.io",
// 				Expire:   10 * time.Second,
// 			},
// 			nil,
// 			true},
// 		{"missing cipher",
// 			&CookieOptions{
// 				Name:           "_pomerium",
// 				Secure:   true,
// 				HTTPOnly: true,
// 				Domain:   "pomerium.io",
// 				Expire:   10 * time.Second,
// 			},
// 			nil,
// 			true},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			got, err := NewCookieStore(tt.opts,encoder)
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("NewCookieStore() error = %v, wantErr %v", err, tt.wantErr)
// 				return
// 			}
// 			cmpOpts := []cmp.Option{
// 				cmpopts.IgnoreUnexported(cryptutil.EncryptedCompressedJSON{}),
// 			}

// 			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
// 				t.Errorf("NewCookieStore() = %s", diff)
// 			}
// 		})
// 	}
// }

func TestCookieStore_makeCookie(t *testing.T) {
	cipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())

	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	tests := []struct {
		name   string
		domain string

		cookieDomain string
		cookieName   string
		value        string
		expiration   time.Duration
		want         *http.Cookie
		wantCSRF     *http.Cookie
	}{
		{"good", "http://httpbin.corp.pomerium.io", "", "_pomerium", "value", 0, &http.Cookie{Name: "_pomerium", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}, &http.Cookie{Name: "_pomerium_csrf", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}},
		{"domains with https", "https://httpbin.corp.pomerium.io", "", "_pomerium", "value", 0, &http.Cookie{Name: "_pomerium", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}, &http.Cookie{Name: "_pomerium_csrf", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}},
		{"domain with port", "http://httpbin.corp.pomerium.io:443", "", "_pomerium", "value", 0, &http.Cookie{Name: "_pomerium", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}, &http.Cookie{Name: "_pomerium_csrf", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}},
		{"expiration set", "http://httpbin.corp.pomerium.io:443", "", "_pomerium", "value", 10 * time.Second, &http.Cookie{Expires: now.Add(10 * time.Second), Name: "_pomerium", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}, &http.Cookie{Expires: now.Add(10 * time.Second), Name: "_pomerium_csrf", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}},
		{"good", "http://httpbin.corp.pomerium.io", "pomerium.io", "_pomerium", "value", 0, &http.Cookie{Name: "_pomerium", Value: "value", Path: "/", Domain: "pomerium.io", Secure: true, HttpOnly: true}, &http.Cookie{Name: "_pomerium_csrf", Value: "value", Path: "/", Domain: "httpbin.corp.pomerium.io", Secure: true, HttpOnly: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tt.domain, nil)

			s, err := NewCookieStore(
				&CookieOptions{
					Name:     "_pomerium",
					Secure:   true,
					HTTPOnly: true,
					Domain:   tt.cookieDomain,
					Expire:   10 * time.Second,
				},
				ecjson.New(cipher))
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(s.makeCookie(r, tt.cookieName, tt.value, tt.expiration, now), tt.want); diff != "" {
				t.Errorf("CookieStore.makeCookie() = \n%s", diff)
			}
			if diff := cmp.Diff(s.makeSessionCookie(r, tt.value, tt.expiration, now), tt.want); diff != "" {
				t.Errorf("CookieStore.makeSessionCookie() = \n%s", diff)
			}

		})
	}
}

// func TestCookieStore_SaveSession(t *testing.T) {
// 	c, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	cipher := ecjson.New(c)

// 	hugeString := make([]byte, 4097)
// 	if _, err := rand.Read(hugeString); err != nil {
// 		t.Fatal(err)
// 	}
// 	tests := []struct {
// 		name        string
// 		State       *State
// 		cipher      Encoder
// 		wantErr     bool
// 		wantLoadErr bool
// 	}{
// 		{"good", &State{AccessToken: "token1234", RefreshToken: "refresh4321", RefreshDeadline: time.Now().Add(1 * time.Hour).Truncate(time.Second).UTC(), Email: "user@domain.com", User: "user"}, cipher, false, false},
// 		{"bad cipher", &State{AccessToken: "token1234", RefreshToken: "refresh4321", RefreshDeadline: time.Now().Add(1 * time.Hour).Truncate(time.Second).UTC(), Email: "user@domain.com", User: "user"}, MockEncoder{}, true, true},
// 		{"huge cookie", &State{AccessToken: fmt.Sprintf("%x", hugeString), RefreshToken: "refresh4321", RefreshDeadline: time.Now().Add(1 * time.Hour).Truncate(time.Second).UTC(), Email: "user@domain.com", User: "user"}, cipher, false, false},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			s := &CookieStore{
// 				Name:     "_pomerium",
// 				Secure:   true,
// 				HTTPOnly: true,
// 				Domain:   "pomerium.io",
// 				Expire:   10 * time.Second,
// 				// Encoder:        tt.cipher,
// 			}

// 			r := httptest.NewRequest("GET", "/", nil)
// 			w := httptest.NewRecorder()

// 			if err := s.SaveSession(w, r, tt.State); (err != nil) != tt.wantErr {
// 				t.Errorf("CookieStore.SaveSession() error = %v, wantErr %v", err, tt.wantErr)
// 			}
// 			r = httptest.NewRequest("GET", "/", nil)
// 			for _, cookie := range w.Result().Cookies() {
// 				// t.Log(cookie)
// 				r.AddCookie(cookie)
// 			}

// 			state, err := s.LoadSession(r)
// 			if (err != nil) != tt.wantLoadErr {
// 				t.Errorf("LoadSession() error = %v, wantErr %v", err, tt.wantLoadErr)
// 				return
// 			}
// 			if err == nil {
// 				if diff := cmp.Diff(state, tt.State); diff != "" {
// 					t.Errorf("CookieStore.LoadSession() got = %s", diff)
// 				}
// 			}
// 		})
// 	}
// }

// func TestMockSessionStore(t *testing.T) {
// 	tests := []struct {
// 		name        string
// 		mockCSRF    *MockSessionStore
// 		saveSession *State
// 		wantLoadErr bool
// 		wantSaveErr bool
// 	}{
// 		{"basic",
// 			&MockSessionStore{
// 				ResponseSession: "test",
// 				Session:         &State{AccessToken: "AccessToken"},
// 				SaveError:       nil,
// 				LoadError:       nil,
// 			},
// 			&State{AccessToken: "AccessToken"},
// 			false,
// 			false},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			ms := tt.mockCSRF

// 			err := ms.SaveSession(nil, nil, tt.saveSession)
// 			if (err != nil) != tt.wantSaveErr {
// 				t.Errorf("MockCSRFStore.GetCSRF() error = %v, wantSaveErr %v", err, tt.wantSaveErr)
// 				return
// 			}
// 			got, err := ms.LoadSession(nil)
// 			if (err != nil) != tt.wantLoadErr {
// 				t.Errorf("MockCSRFStore.GetCSRF() error = %v, wantLoadErr %v", err, tt.wantLoadErr)
// 				return
// 			}
// 			if !reflect.DeepEqual(got, tt.mockCSRF.Session) {
// 				t.Errorf("MockCSRFStore.GetCSRF() = %v, want %v", got, tt.mockCSRF.Session)
// 			}
// 			ms.ClearSession(nil, nil)
// 			if ms.ResponseSession != "" {
// 				t.Errorf("ResponseSession not empty! %s", ms.ResponseSession)
// 			}
// 		})
// 	}
// }
