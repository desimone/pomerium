// Package JWS represents content secured with digitalsignatures
// using JSON-based data structures as specified by rfc7515
package jws // import "github.com/pomerium/pomerium/internal/encoding/jws"

import (
	"encoding/base64"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/pomerium/internal/cryptutil"
)

type JSONWebSigner struct {
	Signer jose.Signer
	Issuer string

	key interface{}
}

// NewHS256Signer creates a SHA256 JWT signer from a 32 byte key.
func NewHS256Signer(key []byte, issuer string) (*JSONWebSigner, error) {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, err
	}
	return &JSONWebSigner{Signer: sig, key: key, Issuer: issuer}, nil
}

// NewES256Signer creates a NIST P-256 (aka secp256r1 aka prime256v1) JWT signer
// from a base64 encoded private key.
//
// RSA is not supported due to performance considerations of needing to sign each request.
// Go's P-256 is constant-time and SHA-256 is faster on 64-bit machines and immune
// to length extension attacks.
// See : https://cloud.google.com/iot/docs/how-tos/credentials/keys
func NewES256Signer(privKey, issuer string) (*JSONWebSigner, error) {
	decodedSigningKey, err := base64.StdEncoding.DecodeString(privKey)
	if err != nil {
		return nil, err
	}
	key, err := cryptutil.DecodePrivateKey(decodedSigningKey)
	if err != nil {
		return nil, err
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, err
	}
	return &JSONWebSigner{Signer: sig, key: key, Issuer: issuer}, nil
}

func (c *JSONWebSigner) Marshal(x interface{}) ([]byte, error) {
	s, err := jwt.Signed(c.Signer).Claims(x).CompactSerialize()
	return []byte(s), err
}

func (c *JSONWebSigner) Unmarshal(value []byte, s interface{}) error {
	tok, err := jwt.ParseSigned(string(value))
	if err != nil {
		return err
	}
	if err := tok.Claims(c.key, s); err != nil {
		return err
	}
	return nil
}
