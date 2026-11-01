package auth

import (
	"errors"
	"net/http"
	"time"
)

// Authenticate verifies the presented token and puts its claims in the request context, replacing
// any already there. A missing token is a 401 Bearer, a rejected token a 401 invalid_token, and an
// unavailable key set a 503 with no challenge.
func (v *Verifier) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticated, _, ok := v.authenticate(w, r)
		if !ok {
			return
		}
		next.ServeHTTP(w, authenticated)
	})
}

// Require answers with a step-up challenge unless the claims [Verifier.Authenticate] put in the
// request context meet min. It trusts those claims without asking who produced them. Without any
// claims in the context it answers 500: that is a wiring mistake, and neither a challenge nor a
// plain 401 would be true. It panics at construction if min parses to level 0.
func Require(min ACR) func(http.Handler) http.Handler {
	return composable("Require", acrCheck(min))
}

// RequireFresh answers with a step-up challenge unless the claims [Verifier.Authenticate] put in
// the request context were authenticated within maxAge. It trusts those claims in the same way as
// [Require], and answers 500 without any. maxAge is truncated to whole seconds, and it panics at
// construction if that is below 1. The age is compared in whole seconds too.
func RequireFresh(maxAge time.Duration) func(http.Handler) http.Handler {
	return composable("RequireFresh", freshnessCheck(maxAge))
}

// Require is the one-line form of the package-level [Require]. It reuses claims in the request
// context only when this verifier produced that exact object. Otherwise it verifies the presented
// token itself, so a token outside this verifier's policy is an authentication failure and never a
// step-up, and the handler sees this verifier's claims.
func (v *Verifier) Require(min ACR) func(http.Handler) http.Handler {
	return v.onDemand(acrCheck(min))
}

// RequireFresh is the one-line form of the package-level [RequireFresh], with the same rule for
// claims as [Verifier.Require].
func (v *Verifier) RequireFresh(maxAge time.Duration) func(http.Handler) http.Handler {
	return v.onDemand(freshnessCheck(maxAge))
}

// check answers the request and returns false unless the claims pass.
type check func(w http.ResponseWriter, c *Claims) bool

func acrCheck(min ACR) check {
	if min.Level() == 0 {
		panic("passflow auth: Require needs a level above 0")
	}
	challenge := Challenge{ACRValues: min.String()}
	return func(w http.ResponseWriter, c *Claims) bool {
		if c.ACR.Satisfies(min) {
			return true
		}
		challenge.Write(w)
		return false
	}
}

func freshnessCheck(maxAge time.Duration) check {
	seconds := int64(maxAge / time.Second)
	if seconds < 1 {
		panic("passflow auth: RequireFresh needs at least one whole second")
	}
	// The enforced value and the emitted value are the same number.
	limit := time.Duration(seconds) * time.Second
	challenge := Challenge{MaxAge: limit}
	return func(w http.ResponseWriter, c *Claims) bool {
		if !c.AuthTime.IsZero() && !staleSince(c, limit) {
			return true
		}
		challenge.Write(w)
		return false
	}
}

// staleSince compares whole seconds, as auth_time and the Node library do: an age of 300.5 s is 300.
func staleSince(c *Claims, limit time.Duration) bool {
	verifiedAt := c.VerifiedAt
	if verifiedAt.IsZero() {
		verifiedAt = time.Now()
	}
	return verifiedAt.Truncate(time.Second).Sub(c.AuthTime) > limit
}

func composable(name string, passes check) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, ok := ClaimsFromContext(r.Context())
			if !ok {
				w.Header().Set(headerCacheControl, noStore)
				http.Error(w, "passflow auth: "+name+" used without Authenticate", http.StatusInternalServerError)
				return
			}
			if passes(w, c) {
				next.ServeHTTP(w, r)
			}
		})
	}
}

func (v *Verifier) onDemand(passes check) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, ok := ClaimsFromContext(r.Context())
			if !ok || !c.VerifiedBy(v) {
				if r, c, ok = v.authenticate(w, r); !ok {
					return
				}
			}
			if passes(w, c) {
				next.ServeHTTP(w, r)
			}
		})
	}
}

// authenticate verifies the presented token and returns the request carrying its claims. It has
// answered the request when ok is false.
func (v *Verifier) authenticate(w http.ResponseWriter, r *http.Request) (*http.Request, *Claims, bool) {
	token, err := BearerToken(r)
	if err != nil {
		writeRejection(w, http.StatusUnauthorized, challengeMissingToken)
		return nil, nil, false
	}
	claims, err := v.Verify(r.Context(), token)
	if err != nil {
		if errors.Is(err, ErrKeySetUnavailable) {
			writeRejection(w, http.StatusServiceUnavailable, "")
		} else {
			writeRejection(w, http.StatusUnauthorized, challengeInvalidToken)
		}
		return nil, nil, false
	}
	return r.WithContext(ContextWithClaims(r.Context(), claims)), claims, true
}
