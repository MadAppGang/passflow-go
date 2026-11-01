package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultLeeway   = 30 * time.Second
	jwksPath        = "/.well-known/jwks.json"
	tokenTypeAccess = "access"
)

// Config is one trust policy. A zero value means the default, for every optional field.
type Config struct {
	// Issuer is required and matched exactly.
	Issuer string
	// Audiences are the Passflow application IDs that may call this API. At least one is required,
	// none may be empty, and a token's aud must contain at least one of them.
	Audiences []string
	// JWKSURL defaults to Issuer + "/.well-known/jwks.json", Passflow's fixed path. The OIDC
	// discovery document is not fetched. It must use https unless the host is loopback or
	// AllowInsecureJWKSURL is set.
	JWKSURL string
	// AllowInsecureJWKSURL permits http on a non-loopback host, for private networks.
	AllowInsecureJWKSURL bool
	// Leeway applies to exp and nbf only. Default 30s.
	Leeway time.Duration
	// TokenTypes are the accepted values of the type claim. Nil means {"access"}. An empty,
	// non-nil slice is rejected, because it accepts nothing.
	TokenTypes []string
	// HTTPClient fetches the key set. Default: a client with a 10s timeout. Redirects are never
	// followed, on any client: a redirect could lead off the checked URL.
	HTTPClient *http.Client
	// Now is the clock. Default time.Now. A background key set refresh reads it too, so it must be
	// safe for concurrent use.
	Now func() time.Time
	// JWKS tunes the key set cache.
	JWKS JWKSOptions
}

// Verifier verifies tokens against one trust policy. It is safe for concurrent use.
type Verifier struct {
	audiences  []string
	tokenTypes []string
	now        func() time.Time
	parser     *jwt.Parser
	keys       *keySet

	// verifyHook is called once at the top of every Verify. It is nil in production: tests set it
	// to count verifications.
	verifyHook func()
}

// NewVerifier validates a configuration and makes no network call. A rejection names the option in
// its corpus spelling (issuer, audiences, jwks_url, leeway, token_types, min_refresh_interval,
// max_age, max_stale, max_bytes), and states the rule without repeating the configured value.
func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, configError("issuer", "Issuer is required")
	}
	if len(cfg.Audiences) == 0 || slices.Contains(cfg.Audiences, "") {
		return nil, configError("audiences", "Audiences needs at least one value and no empty value")
	}

	jwksURL := cfg.JWKSURL
	if jwksURL == "" {
		jwksURL = strings.TrimRight(cfg.Issuer, "/") + jwksPath
	}
	if err := validateJWKSURL(jwksURL, cfg.AllowInsecureJWKSURL); err != nil {
		return nil, err
	}

	if cfg.Leeway < 0 {
		return nil, configError("leeway", "Leeway must not be negative")
	}
	leeway := cfg.Leeway
	if leeway == 0 {
		leeway = defaultLeeway
	}

	tokenTypes := []string{tokenTypeAccess}
	if cfg.TokenTypes != nil {
		if len(cfg.TokenTypes) == 0 || slices.Contains(cfg.TokenTypes, "") {
			return nil, configError("token_types", "TokenTypes needs at least one value and no empty value")
		}
		tokenTypes = slices.Clone(cfg.TokenTypes)
	}

	opts, err := resolveJWKSOptions(cfg.JWKS)
	if err != nil {
		return nil, err
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	return &Verifier{
		audiences:  slices.Clone(cfg.Audiences),
		tokenTypes: tokenTypes,
		now:        now,
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{algRS256, algES256}),
			jwt.WithExpirationRequired(),
			jwt.WithIssuer(cfg.Issuer),
			jwt.WithLeeway(leeway),
			jwt.WithTimeFunc(now),
		),
		keys: &keySet{
			url:    jwksURL,
			client: noRedirectClient(cfg.HTTPClient),
			now:    now,
			opts:   opts,
		},
	}, nil
}

func configError(option, rule string) error {
	return fmt.Errorf("passflow auth: config %s: %s", option, rule)
}

func resolveJWKSOptions(o JWKSOptions) (JWKSOptions, error) {
	if o.MinRefreshInterval == 0 {
		o.MinRefreshInterval = defaultMinRefreshInterval
	}
	if o.MaxAge == 0 {
		o.MaxAge = defaultMaxAge
	}
	if o.MaxStale == 0 {
		o.MaxStale = defaultMaxStale
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = defaultMaxBytes
	}
	switch {
	case o.MinRefreshInterval < 0:
		return o, configError("min_refresh_interval", "JWKS.MinRefreshInterval must not be negative")
	case o.MaxAge < 0:
		return o, configError("max_age", "JWKS.MaxAge must not be negative")
	case o.MaxStale < o.MaxAge:
		return o, configError("max_stale", "JWKS.MaxStale must be at least JWKS.MaxAge")
	case o.MaxBytes < 1:
		return o, configError("max_bytes", "JWKS.MaxBytes must be at least 1")
	}
	return o, nil
}

// validateJWKSURL holds the root of trust to https, except for a loopback host or an explicit
// opt-in. The error states the rule and never the URL.
func validateJWKSURL(raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return configError("jwks_url", "JWKSURL must be an absolute URL")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowInsecure || isLoopbackHost(u.Hostname()) {
			return nil
		}
		return configError("jwks_url", "JWKSURL must use https unless the host is loopback or AllowInsecureJWKSURL is set")
	default:
		return configError("jwks_url", "JWKSURL must use https or http")
	}
}

// isLoopbackHost applies the shared rule to a hostname with the port and IPv6 brackets removed. A
// name that merely contains "localhost" is not loopback, and neither is an IPv4-mapped IPv6 address.
func isLoopbackHost(hostname string) bool {
	host := strings.ToLower(hostname)
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if strings.Contains(host, ":") {
		return ip.Equal(net.IPv6loopback)
	}
	return ip.IsLoopback()
}

// noRedirectClient returns a client that reports a redirect as its own response, which is then a
// failed fetch. An injected client is copied, so the caller's is not modified.
func noRedirectClient(injected *http.Client) *http.Client {
	var client http.Client
	if injected != nil {
		client = *injected
	} else {
		client.Timeout = defaultHTTPTimeout
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &client
}

// Refresh fetches the key set regardless of the refresh gate, in a fetch that starts after the call,
// so a nil error means a key published before the call is in the set. A fetch already in flight may
// predate that key, so Refresh waits for it first and ignores its result. Use it as a warm-up or from
// a key rotation hook. It returns an error wrapping [ErrKeySetUnavailable] on failure or when ctx
// ends, and the previous key set stays in place.
func (v *Verifier) Refresh(ctx context.Context) error {
	return v.keys.refresh(ctx)
}

// Verify checks a token and returns its claims. A rejected token gives a [*VerifyError]. An error
// wrapping [ErrKeySetUnavailable] says nothing about the token and must not be read as a rejection.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	if v.verifyHook != nil {
		v.verifyHook()
	}

	header, err := inspectHeader(token)
	if err != nil {
		return nil, err
	}

	key, err := v.keys.resolve(ctx, header.kid, header.kind)
	if errors.Is(err, errKeyUnknown) {
		return nil, rejection(ReasonKeyUnknown)
	}
	if err != nil {
		return nil, err
	}

	raw := jwt.MapClaims{}
	_, err = v.parser.ParseWithClaims(token, raw, func(parsed *jwt.Token) (any, error) {
		// The key was chosen from the inspected header, so the library must read the same one.
		if parsed.Method.Alg() != header.alg || parsed.Header["kid"] != any(header.kid) {
			return nil, errors.New("header changed between inspection and parsing")
		}
		return key, nil
	})
	if err != nil {
		return nil, classifyParseError(err, raw)
	}

	// iat is never compared with the clock: a future value is skew, not a threat. A value that is not
	// a number is not a NumericDate at all. MapClaims reports a present string, null or array here.
	if _, err := raw.GetIssuedAt(); err != nil {
		return nil, rejection(ReasonMalformed)
	}

	audience, err := raw.GetAudience()
	if err != nil || !containsAny(audience, v.audiences) {
		return nil, rejection(ReasonAudience)
	}

	claims := newClaims(raw)
	if !slices.Contains(v.tokenTypes, claims.Type) {
		return nil, rejection(ReasonType)
	}

	claims.VerifiedAt = v.now()
	claims.verifiedBy = v
	claims.self = claims
	return claims, nil
}

func rejection(reason Reason) error {
	return &VerifyError{Reason: reason}
}

// classifyParseError maps the library's error to a reason, keeping only its fixed sentinels: the
// library's composite errors can quote a character of the token.
func classifyParseError(err error, raw jwt.MapClaims) error {
	switch {
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return &VerifyError{Reason: ReasonSignature, Err: jwt.ErrTokenSignatureInvalid}
	case errors.Is(err, jwt.ErrTokenExpired):
		return &VerifyError{Reason: ReasonExpired, Err: jwt.ErrTokenExpired}
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return &VerifyError{Reason: ReasonNotYetValid, Err: jwt.ErrTokenNotValidYet}
	case !errors.Is(err, jwt.ErrTokenInvalidClaims):
		return &VerifyError{Reason: ReasonMalformed, Err: jwt.ErrTokenMalformed}
	}

	// A missing and a mistyped claim share the library's sentinels across claims, so look at the
	// claim itself. Only exp, nbf and iss are validated by the library.
	if exp, expErr := raw.GetExpirationTime(); expErr != nil || exp == nil {
		return &VerifyError{Reason: ReasonExpMissing, Err: jwt.ErrTokenRequiredClaimMissing}
	}
	if _, nbfErr := raw.GetNotBefore(); nbfErr != nil {
		return &VerifyError{Reason: ReasonNotYetValid, Err: jwt.ErrInvalidType}
	}
	return &VerifyError{Reason: ReasonIssuer, Err: jwt.ErrTokenInvalidIssuer}
}

func containsAny(values, wanted []string) bool {
	for _, value := range values {
		if slices.Contains(wanted, value) {
			return true
		}
	}
	return false
}
