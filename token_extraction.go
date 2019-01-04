package auth0

import (
	"errors"
	"strings"

	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	// ErrTokenNotFound is returned by the ValidateRequest if the token was not
	// found in the request.
	ErrTokenNotFound = errors.New("Token not found")
)

// RequestTokenExtractor can extract a JWT
// from a request.
type RequestTokenExtractor interface {
	Extract(bearer string) (*jwt.JSONWebToken, error)
}

// RequestTokenExtractorFunc function conforming
// to the RequestTokenExtractor interface.
type RequestTokenExtractorFunc func(bearer string) (*jwt.JSONWebToken, error)

// Extract calls f(r)
func (f RequestTokenExtractorFunc) Extract(bearer string) (*jwt.JSONWebToken, error) {
	return f(bearer)
}

// FromMultiple combines multiple extractors by chaining.
func FromMultiple(extractors ...RequestTokenExtractor) RequestTokenExtractor {
	return RequestTokenExtractorFunc(func(bearer string) (*jwt.JSONWebToken, error) {
		for _, e := range extractors {
			token, err := e.Extract(bearer)
			if err == ErrTokenNotFound {
				continue
			} else if err != nil {
				return nil, err
			}
			return token, nil
		}
		return nil, ErrTokenNotFound
	})
}

func FromBearer(bearer string) (*jwt.JSONWebToken, error) {
	raw := ""
	if len(bearer) > 7 && strings.EqualFold(bearer[0:7], "BEARER ") {
		raw = bearer[7:]
	} else if len(bearer) > 6 && strings.EqualFold(bearer[0:6], "TOKEN ") {
		raw = bearer[6:]
	}
	if raw == "" {
		return nil, ErrTokenNotFound
	}
	return jwt.ParseSigned(raw)
}
