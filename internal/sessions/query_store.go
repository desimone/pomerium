package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"net/http"
)

const (
	defaultQueryParamKey = "pomerium_session"
)

// QueryParamStore implements the load session store interface using http
// query strings / query parameters.
type QueryParamStore struct {
	queryParamKey string
	encoder       Unmarshaler
}

// NewQueryParamStore returns a new query param store for loading sessions from
// query strings / query parameters.
func NewQueryParamStore(enc Encoder) *QueryParamStore {
	return &QueryParamStore{
		queryParamKey: defaultQueryParamKey,
		encoder:       enc,
	}
}

// LoadSession tries to retrieve the token string from URL query parameters.
//
// NOTA BENE: By default, most servers _DO_ log query params, the leaking or
// accidental logging of which should be considered a security issue.
func (qp *QueryParamStore) LoadSession(r *http.Request) (*State, error) {
	cipherText := r.URL.Query().Get(qp.queryParamKey)
	if cipherText == "" {
		return nil, ErrNoSessionFound
	}
	var session State
	if err := qp.encoder.Unmarshal([]byte(cipherText), &session); err != nil {
		return nil, ErrMalformed
	}
	return &session, nil
}
