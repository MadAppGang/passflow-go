// Package auth protects HTTP endpoints with verified Passflow access tokens.
//
// A [Verifier] checks a token against one trust policy: issuer, audiences, token types and the
// issuer's key set. Its middleware then answers in one of three ways:
//
//   - An authentication failure is a 401 with a plain RFC 6750 challenge.
//   - Authentication that is too weak or too old is a 401 with the RFC 9470 step-up challenge.
//   - A key set that cannot be reached is a 503 with no challenge.
//
// The browser SDK acts only on the step-up challenge: it upgrades the session and replays the
// request. A plain 401 and a 503 reach the caller's code unchanged. The three stay distinct because
// no dialog can fix an expired token, and an outage is not a bad token.
//
// Two forms protect a route. The verifier methods take one line and authenticate on demand:
//
//	mux.Handle("GET /invoices", verifier.Require(auth.AAL2)(handler))
//
// The composable functions act on the claims an Authenticate upstream produced:
//
//	protected := verifier.Authenticate(auth.Require(auth.AAL2)(handler))
//
// A browser on another origin can read the challenge only if the response exposes the header, so
// add [CORSExposedHeaders] to the CORS configuration. Without it the SDK sees a bare 401.
//
// The package never logs, and no error, response or panic carries anything from a token.
package auth
