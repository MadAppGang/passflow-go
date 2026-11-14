# passflow-go

Go libraries for services that accept [Passflow](https://github.com/usepassflow/passflow) tokens. `auth` protects an HTTP endpoint with a verified access token. When the token's authentication is too weak or too old, it answers with the RFC 9470 step-up challenge that the Passflow browser SDK understands.

```bash
go get github.com/usepassflow/go/auth
```

Requires Go 1.27 or newer, and its only dependency is `github.com/golang-jwt/jwt/v5` v5.3.1.

## Use it

```go
verifier, err := auth.NewVerifier(auth.Config{
	Issuer:    "https://auth.example.com",
	Audiences: []string{"7f3a9c21d4b8e6"}, // Passflow application IDs that may call this API
})
if err != nil {
	log.Fatal(err)
}

mux := http.NewServeMux()
mux.Handle("GET /invoices", verifier.Require(auth.AAL2)(http.HandlerFunc(invoices)))
mux.Handle("POST /transfers", verifier.RequireFresh(5*time.Minute)(http.HandlerFunc(transfers)))
```

`Require` demands an assurance level (`acr`) and `RequireFresh` demands a recent authentication (`auth_time`, compared in whole seconds), and both verify the token on demand. On Chi or any router built on `net/http`, put `verifier.Authenticate` upstream and use the package-level `auth.Require` and `auth.RequireFresh` behind it, which act on the claims it produced. Read the claims in a handler with `auth.ClaimsFromContext(r.Context())`.

The Passflow documentation has a step-by-step Go tutorial (`docs/tutorials/go-backend.md`) and a runnable API in `examples/resource-server`.

### Gin

The Gin adapter is a separate module, so the core module's dependencies stay at one:

```bash
go get github.com/usepassflow/go/auth/authgin
```

```go
protected := router.Group("/", authgin.Authenticate(verifier))
protected.GET("/invoices", authgin.Require(auth.AAL2), invoices)
```

## Responses and CORS

| Situation | Status | `WWW-Authenticate` |
|---|---|---|
| No token, or not a `Bearer` token | 401 | `Bearer` |
| Invalid or expired token | 401 | `Bearer error="invalid_token"` |
| Token below the required level | 401 | `Bearer error="insufficient_user_authentication", acr_values="2"` |
| Authentication too old | 401 | `Bearer error="insufficient_user_authentication", max_age=300` |
| Key set unavailable | 503 | none |

Every rejection carries `Cache-Control: no-store` and an empty body. Nothing from the token, the request or the key set URL appears in any error or response. The package writes no logs. The package-level `Require` without an `Authenticate` upstream answers 500, because that is a wiring mistake and neither a challenge nor a plain 401 would be true.

The browser SDK acts only on the step-up challenge: it upgrades the session and replays the request. A plain 401 and a 503 reach your code unchanged. The responses stay distinct because no dialog can fix an expired token, and an outage is not a bad token.

A browser on another origin can read the challenge only if the response names the header, and `*` does not cover it on a credentialed request. Without it the SDK sees a bare 401 and cannot start the step-up, so add `auth.CORSExposedHeaders()` to your CORS configuration:

```go
cors.Options{
	AllowedOrigins:   []string{"https://app.example.com"},
	AllowCredentials: true,
	ExposedHeaders:   auth.CORSExposedHeaders(), // adds WWW-Authenticate, keeps any you pass in
}
```

## Key set behaviour

The key set URL is `{Issuer}/.well-known/jwks.json`, Passflow's fixed path, and the OIDC discovery document is not fetched. Set `Config.JWKSURL` when your deployment publishes another one. The URL must use `https`, except for a loopback host or when `AllowInsecureJWKSURL` is set. The snippet below shows a custom `JWKSURL` and the cache options with their defaults:

```go
auth.Config{
	JWKSURL: "https://keys.example.com/passflow/jwks.json", // default: Issuer + "/.well-known/jwks.json"
	JWKS: auth.JWKSOptions{
		MinRefreshInterval: 30 * time.Second, // at most one background refresh, unknown-kid fetch or retry per interval
		MaxAge:             10 * time.Minute, // a set this old starts a background refresh and keeps answering
		MaxStale:           time.Hour,        // how long a stale set is trusted after the last success
		MaxBytes:           1 << 20,          // response body cap
	},
}
```

- A key is looked up by `kid` and by the key type its algorithm requires. An unknown `kid` causes at most one refetch per `MinRefreshInterval`, and a bad signature never causes one.
- A set older than `MaxAge` keeps answering while a background refresh runs, so a hanging key set endpoint delays no request whose key is in the set. The cost is that a key removed from the set can verify for the length of one more fetch. A request waits for a fetch only when there is no set, when the set is past `MaxStale`, or when its `kid` is not in the set. It joins a fetch already in flight, and it never causes a second one.
- A reload counts only when all of it succeeds: status 200, a body within `MaxBytes`, a JSON key set, and every usable key checked (public, members in canonical base64url, RSA of at least 2048 bits with an odd exponent from 3 to 2^31-1, or P-256 with 32-byte coordinates, no duplicate `kid`). A key that carries private material fails the reload. Anything else is one failed attempt, and a working set stays in place.
- While reloads fail or hang, the stale set is trusted until `MaxStale` after the last successful fetch. After that, every request gets a 503 until a reload succeeds.
- A 503 never carries a challenge, so a key rotation during an outage does not look like a bad token.

The Node package, `@passflow/node`, applies the same rules with the same defaults, in milliseconds.

**Rotation window.** A token signed by a key published less than `MinRefreshInterval` after the previous fetch attempt is rejected as `key_unknown` until the gate opens, at most 30 seconds per instance. Passflow signs with one key today, so only a deployment that rotates keys needs to call `verifier.Refresh(ctx)` from its rotation hook, once the new key is published. `Refresh` ignores the gate and returns the result of a fetch that starts after the call, so a nil error means the new key is in the set. If a fetch is already in flight, `Refresh` waits for it first and ignores its result:

```go
if err := verifier.Refresh(ctx); err != nil {
	log.Printf("key set reload failed: %v", err) // the previous key set stays in place
}
```

## Releases, the mirror and the license

A release is two tags in the Passflow repository, pushed in this order:

1. `sdk/go/passflow-go/vX.Y.Z`, which the mirror workflow publishes here as `vX.Y.Z`.
2. `sdk/go/passflow-go/auth/authgin/vX.Y.Z`, published as `auth/authgin/vX.Y.Z`, after the Go proxy lists the first tag.

The order matters because `authgin/go.mod` requires a core version that must already exist, and the workflow checks that requirement against the proxy and fails the run if it does not resolve.

This repository is a read-only mirror: each commit here is a snapshot published from the Passflow source repository, and pull requests are not merged here because the next sync would overwrite them. To report a problem or ask for a change, email [support@passflow.cloud](mailto:support@passflow.cloud).

The module is MIT licensed, as [LICENSE](LICENSE) states, and that license is separate from the Passflow server's.
