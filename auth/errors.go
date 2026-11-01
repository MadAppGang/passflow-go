package auth

import (
	"errors"
	"net/http"
	"strings"
)

var (
	// ErrMissingToken means the request presented no bearer token.
	ErrMissingToken = errors.New("passflow auth: missing bearer token")
	// ErrInvalidToken matches every [VerifyError].
	ErrInvalidToken = errors.New("passflow auth: invalid token")
	// ErrKeySetUnavailable means the key set could not be used to decide about a token. It says
	// nothing about the token.
	ErrKeySetUnavailable = errors.New("passflow auth: key set unavailable")
)

// Reason says why a token was rejected.
type Reason string

// The rejection reasons, shared with @passflow/node.
const (
	ReasonExpired     Reason = "expired"
	ReasonNotYetValid Reason = "not_yet_valid"
	ReasonExpMissing  Reason = "exp_missing"
	ReasonIssuer      Reason = "issuer"
	ReasonAudience    Reason = "audience"
	ReasonType        Reason = "type"
	ReasonSignature   Reason = "signature"
	ReasonAlg         Reason = "alg"
	ReasonKIDMissing  Reason = "kid_missing"
	ReasonKeyUnknown  Reason = "key_unknown"
	ReasonCrit        Reason = "crit"
	ReasonMalformed   Reason = "malformed"
)

// String returns the reason code.
func (r Reason) String() string {
	return string(r)
}

// VerifyError is the rejection of a token. Read it with errors.As into a *VerifyError, or match it
// with errors.Is against [ErrInvalidToken]. It never carries anything from the token: Err is
// either nil or one of the JWT library's fixed sentinel errors.
type VerifyError struct {
	Reason Reason
	Err    error
}

// Error returns the reason code and nothing from the token.
func (e *VerifyError) Error() string {
	return ErrInvalidToken.Error() + ": " + e.Reason.String()
}

// Is matches [ErrInvalidToken].
func (e *VerifyError) Is(target error) bool {
	return target == ErrInvalidToken
}

// Unwrap returns the underlying sentinel, if there is one.
func (e *VerifyError) Unwrap() error {
	return e.Err
}

// BearerToken returns the bearer token of a request, or [ErrMissingToken]. The scheme is matched
// case-insensitively, as RFC 9110 requires, and surrounding whitespace is removed.
func BearerToken(r *http.Request) (string, error) {
	const scheme = "bearer"
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(header) <= len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", ErrMissingToken
	}
	rest := header[len(scheme):]
	if rest[0] != ' ' && rest[0] != '\t' {
		return "", ErrMissingToken
	}
	return strings.TrimSpace(rest), nil
}
