package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	defaultMinRefreshInterval = 30 * time.Second
	defaultMaxAge             = 10 * time.Minute
	defaultMaxStale           = time.Hour
	defaultMaxBytes           = int64(1 << 20)
	defaultHTTPTimeout        = 10 * time.Second

	// fetchTimeout bounds one reload, on its own context: the request that started it may end
	// while other requests still wait for the result, and a background refresh has no request.
	fetchTimeout = 10 * time.Second

	minRSAModulusBits = 2048
	p256CoordinateLen = 32
	maxRSAExponent    = math.MaxInt32
)

// JWKSOptions tunes the key set cache. A zero value means the default, for every field.
type JWKSOptions struct {
	// MinRefreshInterval bounds background refreshes, fetch attempts for an unknown kid, and retries
	// after a failure. Default 30s.
	MinRefreshInterval time.Duration
	// MaxAge is how old a key set may be before a request starts a background refresh. That request
	// and the ones after it keep answering from the current set. Default 10m.
	MaxAge time.Duration
	// MaxStale is how long after the last successful fetch a key set may still be used while
	// refreshes fail or hang. Past it, requests wait for a fetch. It must be at least MaxAge.
	// Default 1h.
	MaxStale time.Duration
	// MaxBytes caps the size of a key set response. Default 1 MiB.
	MaxBytes int64
}

// keyKind is the key type an algorithm requires.
type keyKind int

const (
	keyKindRSA keyKind = iota + 1
	keyKindP256
)

type publicKey struct {
	kind keyKind
	key  any
}

// errKeyUnknown means the key set is good and the kid is not in it. Verify turns it into a
// VerifyError.
var errKeyUnknown = errors.New("passflow auth: key unknown")

// reload is one fetch in flight. err is set before done closes.
type reload struct {
	done chan struct{}
	err  error
}

// keySet is the key cache. A request may wait on a fetch, but mu is never held across a fetch or a
// wait.
type keySet struct {
	url    string
	client *http.Client
	now    func() time.Time
	opts   JWKSOptions

	mu                sync.Mutex
	keys              map[string]publicKey // nil until the first successful fetch
	lastSuccess       time.Time
	lastAttempt       time.Time
	lastAttemptFailed bool
	inFlight          *reload
}

// resolve returns the key for (kid, kind), or an error that wraps ErrKeySetUnavailable or is
// errKeyUnknown.
func (s *keySet) resolve(ctx context.Context, kid string, kind keyKind) (any, error) {
	flight, err := s.ensureFresh(ctx)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	if key, ok := s.lookupLocked(kid, kind); ok {
		s.mu.Unlock()
		return key, nil
	}

	// The kid is not in the set with the key type the algorithm requires. A fetch this request
	// already waited for or started decides the answer, even one that has since ended, so one request
	// never costs two fetches. Otherwise it joins the fetch in flight, or the gate decides. The lookup
	// above and the gate below share one hold of mu, and a fetch publishes under mu, so the gate never
	// answers for a set this lookup did not see.
	if flight == nil {
		if s.inFlight == nil && s.gateClosedLocked(s.now()) {
			failed := s.lastAttemptFailed
			s.mu.Unlock()
			if failed {
				return nil, unavailable("outage")
			}
			return nil, errKeyUnknown
		}
		flight = s.startLocked()
	}
	s.mu.Unlock()
	if err := s.wait(ctx, flight); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if key, ok := s.lookupLocked(kid, kind); ok {
		return key, nil
	}
	return nil, errKeyUnknown
}

// ensureFresh decides whether the key set may be used, and returns the fetch this request waited for
// or started, if any. A set within MaxStale answers at once: past MaxAge it also starts a background
// refresh, so a hanging endpoint stalls no request. Only a request with no usable set waits. An
// error means there is no such set and a fetch did not produce one, or the request's context ended.
func (s *keySet) ensureFresh(ctx context.Context) (*reload, error) {
	s.mu.Lock()
	now := s.now()
	// A failed attempt never moves lastSuccess, so repeated failures cannot extend this deadline.
	if s.keys != nil && now.Sub(s.lastSuccess) <= s.opts.MaxStale {
		defer s.mu.Unlock()
		if now.Sub(s.lastSuccess) > s.opts.MaxAge && s.inFlight == nil && !s.gateClosedLocked(now) {
			return s.startLocked(), nil
		}
		return nil, nil
	}

	if s.inFlight == nil && s.retryGatedLocked(now) {
		s.mu.Unlock()
		return nil, unavailable("stale")
	}
	flight := s.startLocked()
	s.mu.Unlock()
	if err := s.wait(ctx, flight); err != nil {
		return nil, err
	}
	return flight, nil
}

// gateClosedLocked reports whether the last attempt, successful or not, was too recent for a
// background refresh or a fetch for an unknown kid.
func (s *keySet) gateClosedLocked(now time.Time) bool {
	return now.Sub(s.lastAttempt) < s.opts.MinRefreshInterval
}

// retryGatedLocked reports whether the last attempt failed recently enough to forbid another. A
// request with no usable set is not gated after a success: nothing else can answer it.
func (s *keySet) retryGatedLocked(now time.Time) bool {
	return s.lastAttemptFailed && s.gateClosedLocked(now)
}

func (s *keySet) lookupLocked(kid string, kind keyKind) (any, bool) {
	k, ok := s.keys[kid]
	if !ok || k.kind != kind {
		return nil, false
	}
	return k.key, true
}

// refresh bypasses the gate and returns the result of a fetch that started after this call. A fetch
// already in flight may have read the key set before the caller changed it, so its result proves
// nothing: wait it out, then start a new one. Fetches are single-flight, so one in flight by then
// began after that wait, and joining it is safe.
func (s *keySet) refresh(ctx context.Context) error {
	s.mu.Lock()
	earlier := s.inFlight
	s.mu.Unlock()
	if earlier != nil {
		if err := s.wait(ctx, earlier); err != nil && ctx.Err() != nil {
			return err
		}
	}

	s.mu.Lock()
	flight := s.startLocked()
	s.mu.Unlock()
	return s.wait(ctx, flight)
}

// startLocked returns the fetch in flight, starting one if needed. The fetch is bounded by
// fetchTimeout, so the goroutine always ends, whether or not any request waits for it.
func (s *keySet) startLocked() *reload {
	if s.inFlight != nil {
		return s.inFlight
	}
	flight := &reload{done: make(chan struct{})}
	s.inFlight = flight
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
		defer cancel()
		keys, err := s.fetch(ctx)

		s.mu.Lock()
		now := s.now()
		s.lastAttempt = now
		s.lastAttemptFailed = err != nil
		if err == nil {
			s.keys = keys
			s.lastSuccess = now
		}
		s.inFlight = nil
		s.mu.Unlock()

		flight.err = err
		close(flight.done)
	}()
	return flight
}

func (s *keySet) wait(ctx context.Context, flight *reload) error {
	select {
	case <-flight.done:
		return flight.err
	case <-ctx.Done():
		return fmt.Errorf("%w: %w", ErrKeySetUnavailable, ctx.Err())
	}
}

// fetch performs one whole reload. The errors name a stage and nothing else: an HTTP client's error
// text holds the URL, which must not reach a caller.
func (s *keySet) fetch(ctx context.Context) (map[string]publicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, unavailable("request")
	}
	req.Header.Set("Accept", "application/json, application/jwk-set+json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, unavailable("network")
	}
	stage := ""
	var body []byte
	if resp.StatusCode != http.StatusOK {
		stage = "status"
	} else if body, err = readCapped(resp, s.opts.MaxBytes); err != nil {
		stage = "body"
	}
	// A failed close counts against the body, unless an earlier stage already failed.
	if err := resp.Body.Close(); err != nil && stage == "" {
		stage = "body"
	}
	if stage != "" {
		return nil, unavailable(stage)
	}
	keys, stage := parseKeySet(body)
	if stage != "" {
		return nil, unavailable(stage)
	}
	return keys, nil
}

func readCapped(resp *http.Response, maxBytes int64) ([]byte, error) {
	if resp.ContentLength > maxBytes {
		return nil, errors.New("body over the cap")
	}
	limit := maxBytes
	if limit < math.MaxInt64 {
		limit++ // one byte past the cap tells a body at the cap from one over it
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, errors.New("body over the cap")
	}
	return body, nil
}

var (
	// jwkPrivateMembers are the JWK members that exist only on a private key.
	jwkPrivateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth"}

	strictBase64URL = base64.RawURLEncoding.Strict()
)

// parseKeySet accepts a body as a key set, or returns the stage that failed. Metadata decides
// whether a key is usable, and an unusable key is skipped. Key material decides whether a usable
// key is accepted, and one failure fails the whole reload: a publisher leaking private keys, or
// publishing a key this library would reject, is not trusted, and the last good set stays.
func parseKeySet(body []byte) (map[string]publicKey, string) {
	// encoding/json would read invalid UTF-8 as U+FFFD. A leading BOM fails the decode below.
	if !utf8.Valid(body) {
		return nil, "parse"
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, "parse"
	}
	var members []map[string]json.RawMessage
	raw, ok := document["keys"]
	if !ok {
		return nil, "parse"
	}
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return nil, "parse"
	}

	keys := make(map[string]publicKey, len(members))
	for _, member := range members {
		if member == nil {
			return nil, "parse"
		}
		if !jwkUsable(member) {
			continue
		}
		kid, _ := jwkString(member, "kid")
		if _, duplicate := keys[kid]; duplicate {
			return nil, "key"
		}
		key, err := jwkAccept(member)
		if err != nil {
			return nil, "key"
		}
		keys[kid] = key
	}
	if len(keys) == 0 {
		return nil, "key"
	}
	return keys, ""
}

// jwkUsable decides by metadata alone whether a token could ever select this key.
func jwkUsable(member map[string]json.RawMessage) bool {
	kty, _ := jwkString(member, "kty")
	var wantAlg string
	switch kty {
	case "RSA":
		wantAlg = algRS256
	case "EC":
		wantAlg = algES256
	default:
		return false
	}
	if kid, _ := jwkString(member, "kid"); kid == "" {
		return false
	}
	if use, present := member["use"]; present {
		if s, ok := jsonString(use); !ok || s != "sig" {
			return false
		}
	}
	if alg, present := member["alg"]; present {
		if s, ok := jsonString(alg); !ok || s != wantAlg {
			return false
		}
	}
	if ops, present := member["key_ops"]; present {
		var values []string
		if err := json.Unmarshal(ops, &values); err != nil {
			return false
		}
		return slices.Contains(values, "verify")
	}
	return true
}

// jwkAccept decides by key material whether a usable key may enter the set.
func jwkAccept(member map[string]json.RawMessage) (publicKey, error) {
	for _, name := range jwkPrivateMembers {
		if _, present := member[name]; present {
			return publicKey{}, errors.New("private member")
		}
	}
	if kty, _ := jwkString(member, "kty"); kty == "RSA" {
		return acceptRSA(member)
	}
	return acceptP256(member)
}

func acceptRSA(member map[string]json.RawMessage) (publicKey, error) {
	modulus, err := jwkBytes(member, "n")
	if err != nil {
		return publicKey{}, err
	}
	exponent, err := jwkBytes(member, "e")
	if err != nil {
		return publicKey{}, err
	}
	n := new(big.Int).SetBytes(modulus)
	if n.BitLen() < minRSAModulusBits {
		return publicKey{}, errors.New("modulus too small")
	}
	e := new(big.Int).SetBytes(exponent)
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > maxRSAExponent || e.Bit(0) == 0 {
		return publicKey{}, errors.New("bad exponent")
	}
	return publicKey{kind: keyKindRSA, key: &rsa.PublicKey{N: n, E: int(e.Int64())}}, nil
}

func acceptP256(member map[string]json.RawMessage) (publicKey, error) {
	if crv, _ := jwkString(member, "crv"); crv != "P-256" {
		return publicKey{}, errors.New("unsupported curve")
	}
	x, err := jwkBytes(member, "x")
	if err != nil {
		return publicKey{}, err
	}
	y, err := jwkBytes(member, "y")
	if err != nil {
		return publicKey{}, err
	}
	if len(x) != p256CoordinateLen || len(y) != p256CoordinateLen {
		return publicKey{}, errors.New("bad coordinate length")
	}
	// ParseUncompressedPublicKey rejects a point off the curve and the point at infinity.
	uncompressed := make([]byte, 0, 1+2*p256CoordinateLen)
	uncompressed = append(uncompressed, 4)
	uncompressed = append(uncompressed, x...)
	uncompressed = append(uncompressed, y...)
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		return publicKey{}, errors.New("point not on the curve")
	}
	return publicKey{kind: keyKindP256, key: key}, nil
}

func jwkString(member map[string]json.RawMessage, name string) (string, bool) {
	raw, present := member[name]
	if !present {
		return "", false
	}
	return jsonString(raw)
}

func jsonString(raw json.RawMessage) (string, bool) {
	var s string
	// A JSON null decodes into a string without an error, so check the first byte.
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

func jwkBytes(member map[string]json.RawMessage, name string) ([]byte, error) {
	s, ok := jwkString(member, name)
	if !ok {
		return nil, errors.New("member absent or not a string")
	}
	// A member has one encoding. Strict refuses non-zero trailing bits, and the decoder skips line
	// breaks in any mode, so those are refused here.
	decoded, err := strictBase64URL.DecodeString(s)
	if err != nil || strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("member not base64url")
	}
	if len(decoded) == 0 {
		return nil, errors.New("member empty")
	}
	return decoded, nil
}

func unavailable(stage string) error {
	return fmt.Errorf("%w: %s", ErrKeySetUnavailable, stage)
}
