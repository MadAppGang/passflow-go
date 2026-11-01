package auth

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerCacheControl = "Cache-Control"
	noStore            = "no-store"

	challengeMissingToken = "Bearer"
	challengeInvalidToken = `Bearer error="invalid_token"`
	challengeStepUp       = `Bearer error="insufficient_user_authentication"`
)

// Challenge is an RFC 9470 step-up challenge.
type Challenge struct {
	// ACRValues is a space-separated list of RFC 9470 acr tokens. It is written unescaped, exactly
	// as the server writes it, so it must never hold untrusted input.
	ACRValues string
	// MaxAge is truncated to whole seconds and omitted when that is not positive.
	MaxAge time.Duration
}

// String returns the exact WWW-Authenticate value. The parameter order is fixed: error, acr_values,
// max_age.
func (c Challenge) String() string {
	var b strings.Builder
	b.WriteString(challengeStepUp)
	if c.ACRValues != "" {
		b.WriteString(`, acr_values="`)
		b.WriteString(c.ACRValues)
		b.WriteByte('"')
	}
	if seconds := int64(c.MaxAge / time.Second); seconds > 0 {
		b.WriteString(", max_age=")
		b.WriteString(strconv.FormatInt(seconds, 10))
	}
	return b.String()
}

// Write answers 401 with the challenge, Cache-Control: no-store and an empty body.
func (c Challenge) Write(w http.ResponseWriter) {
	writeRejection(w, http.StatusUnauthorized, c.String())
}

// writeRejection is the single place a rejection's status and headers are set. An empty challenge
// sends no WWW-Authenticate header.
func writeRejection(w http.ResponseWriter, status int, challenge string) {
	if challenge != "" {
		w.Header().Set(ChallengeHeader, challenge)
	}
	w.Header().Set(headerCacheControl, noStore)
	w.WriteHeader(status)
}
