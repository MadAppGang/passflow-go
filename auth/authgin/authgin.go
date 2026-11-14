// Package authgin adapts [github.com/usepassflow/go/auth] to Gin.
//
// A Gin group takes one Authenticate upstream, and Require and RequireFresh act on the claims it
// produced:
//
//	protected := router.Group("/", authgin.Authenticate(verifier))
//	protected.GET("/invoices", authgin.Require(auth.AAL2), handler)
//
// Responses are the ones the auth package writes, so they carry the same status codes and the same
// challenges.
package authgin

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/usepassflow/go/auth"
)

// Authenticate verifies the presented token with v and puts its claims in the request context,
// replacing any already there. See [auth.Verifier.Authenticate].
func Authenticate(v *auth.Verifier) gin.HandlerFunc {
	return wrap(v.Authenticate)
}

// Require answers with a step-up challenge unless the claims Authenticate produced meet min. See
// [auth.Require], including its panic on a level that parses to 0.
func Require(min auth.ACR) gin.HandlerFunc {
	return wrap(auth.Require(min))
}

// RequireFresh answers with a step-up challenge unless the claims Authenticate produced were
// authenticated within maxAge. See [auth.RequireFresh], including its panic below one whole second.
func RequireFresh(maxAge time.Duration) gin.HandlerFunc {
	return wrap(auth.RequireFresh(maxAge))
}

// Claims returns the claims Authenticate put in the request context.
func Claims(c *gin.Context) (*auth.Claims, bool) {
	return auth.ClaimsFromContext(c.Request.Context())
}

// wrap runs net/http middleware in a Gin chain. gin.WrapH does not fit: it never calls c.Next and
// it loses the context the middleware sets. The next handler keeps the middleware's request and
// continues the chain. If the middleware never called it, the middleware has answered, so the chain
// stops there.
func wrap(middleware func(http.Handler) http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		nextRan := false
		middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			nextRan = true
			c.Request = r
			c.Next()
		})).ServeHTTP(c.Writer, c.Request)
		if !nextRan {
			c.Abort()
		}
	}
}
