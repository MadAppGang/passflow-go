package auth_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/madappgang/passflow-go/auth"
)

// Generated keys, never committed key bytes or copies of the corpus.
type testKey struct {
	id      string
	private any
	method  jwt.SigningMethod
	jwk     map[string]any
}

func generateTestKey(t testing.TB, kty, id string, bits int) *testKey {
	t.Helper()
	k := &testKey{id: id}
	enc := base64.RawURLEncoding.EncodeToString
	switch kty {
	case "RSA":
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		k.private, k.method = key, jwt.SigningMethodRS256
		k.jwk = map[string]any{"kid": id, "kty": "RSA", "n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes())}
	case "EC":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		k.private, k.method = key, jwt.SigningMethodES256
		k.jwk = map[string]any{"kid": id, "kty": "EC", "crv": "P-256",
			"x": enc(key.X.FillBytes(make([]byte, 32))), "y": enc(key.Y.FillBytes(make([]byte, 32)))}
	default:
		t.Fatalf("unsupported test key type %q", kty)
	}
	return k
}

func testKeys(t testing.TB) map[string]*testKey {
	t.Helper()
	return map[string]*testKey{
		"rsa":       generateTestKey(t, "RSA", "generated-rsa", 2048),
		"ec":        generateTestKey(t, "EC", "generated-ec", 0),
		"other-rsa": generateTestKey(t, "RSA", "other-rsa", 2048),
	}
}

func happyClaims() map[string]any {
	return map[string]any{"iss": "https://auth.example.com", "sub": "user-1", "aud": []string{"app-1"},
		"type": "access", "iat": 1699999940, "exp": 1700100000, "acr": "2",
		"auth_time": 1699999940, "amr": []string{"pwd", "otp"}, "sid": "session-1", "scope": "read write"}
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func signToken(t testing.TB, key *testKey, claims map[string]any, header map[string]any) string {
	t.Helper()
	tok := jwt.NewWithClaims(key.method, jwt.MapClaims(claims))
	tok.Header["kid"] = key.id
	for k, v := range header {
		tok.Header[k] = v
	}
	raw, err := tok.SignedString(key.private)
	if err != nil {
		t.Fatal("cannot sign test token")
	}
	return raw
}

type tokenCase struct {
	ID       string         `json:"id"`
	Key      string         `json:"key"`
	RawToken string         `json:"raw_token"`
	Header   map[string]any `json:"header"`
	Claims   map[string]any `json:"claims"`
	Now      float64        `json:"now"`
	JWKS     string         `json:"jwks"`
	Verifier struct {
		Issuer     string   `json:"issuer"`
		Audiences  []string `json:"audiences"`
		Leeway     float64  `json:"leeway"`
		TokenTypes []string `json:"token_types"`
	} `json:"verifier"`
	Expect struct {
		Outcome string `json:"outcome"`
		Reason  string `json:"reason"`
		Fetches *struct {
			Open   int64 `json:"gate_open"`
			Closed int64 `json:"gate_closed"`
		} `json:"fetches"`
		Tenants map[string]struct {
			Roles []string `json:"roles"`
		} `json:"tenants"`
		TenantsAbsent []string `json:"tenants_absent"`
	} `json:"expect"`
}

func tokenFromCase(t testing.TB, keys map[string]*testKey, row tokenCase) string {
	t.Helper()
	if row.RawToken != "" {
		return row.RawToken
	}
	key := keys[row.Key]
	if row.Key == "hmac" {
		public, err := x509.MarshalPKIXPublicKey(&keys["rsa"].private.(*rsa.PrivateKey).PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		key = &testKey{private: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), method: jwt.SigningMethodHS256}
	}
	if row.Key == "none" {
		key = &testKey{private: jwt.UnsafeAllowNoneSignatureType, method: jwt.SigningMethodNone}
	}
	if key == nil {
		t.Fatal("corpus names an unsupported generated key")
	}
	header := cloneMap(row.Header)
	switch header["kid"] {
	case "generated":
		header["kid"] = key.id
	case "generated-rsa":
		header["kid"] = keys["rsa"].id
	case "generated-ec":
		header["kid"] = keys["ec"].id
	case "absent":
		delete(header, "kid")
	}
	tok := jwt.NewWithClaims(key.method, jwt.MapClaims(row.Claims))
	for k, v := range header {
		tok.Header[k] = v
	}
	raw, err := tok.SignedString(key.private)
	if err != nil {
		t.Fatal("cannot sign corpus token")
	}
	return raw
}

func loadCorpus(t testing.TB, file string, version int, out any) {
	t.Helper()
	body, err := os.ReadFile("testdata/corpus/" + file)
	if err != nil {
		t.Fatalf("read corpus %s: %v", file, err)
	}
	var meta struct {
		Version int `json:"corpus_version"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Version != version {
		t.Fatalf("%s corpus_version=%d, want %d", file, meta.Version, version)
	}
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatal(err)
	}
}

func equal(t testing.TB, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func requireOutcome(t testing.TB, claims *auth.Claims, err error, outcome, reason string) {
	t.Helper()
	switch outcome {
	case "ok":
		if err != nil || claims == nil {
			t.Fatalf("verification did not succeed: %v", err)
		}
	case "jwks_unavailable":
		if !errors.Is(err, auth.ErrKeySetUnavailable) {
			t.Fatalf("got error category %T, want key set unavailable", err)
		}
		if claims != nil {
			t.Fatal("failure returned claims")
		}
	case "invalid_token":
		var rejected *auth.VerifyError
		if !errors.Is(err, auth.ErrInvalidToken) || !errors.As(err, &rejected) {
			t.Fatalf("got category %T, want invalid token", err)
		}
		equal(t, rejected.Reason.String(), reason)
		if claims != nil {
			t.Fatal("failure returned claims")
		}
	default:
		t.Fatalf("unknown corpus outcome %q", outcome)
	}
}

type jwksHarness struct {
	server *httptest.Server
	clock  atomic.Int64
	count  atomic.Int64
	mu     sync.RWMutex
	body   []byte
	status int
	block  <-chan struct{}
}

func newJWKSHarness(t testing.TB, keys ...*testKey) *jwksHarness {
	t.Helper()
	h := &jwksHarness{status: http.StatusOK}
	h.setTime(1700000000)
	h.publish(t, keys...)
	h.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.RLock()
		body, status, block := bytes.Clone(h.body), h.status, h.block
		h.mu.RUnlock()
		h.count.Add(1)
		if block != nil {
			select {
			case <-block:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(h.server.Close)
	return h
}

func (h *jwksHarness) setTime(seconds float64) { h.clock.Store(int64(seconds * 1e9)) }
func (h *jwksHarness) now() time.Time          { return time.Unix(0, h.clock.Load()) }
func (h *jwksHarness) publish(t testing.TB, keys ...*testKey) {
	t.Helper()
	jwks := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		jwks = append(jwks, k.jwk)
	}
	h.setJSON(t, jwks)
}
func (h *jwksHarness) setJSON(t testing.TB, keys []map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	h.respond(http.StatusOK, body)
}
func (h *jwksHarness) respond(status int, body []byte) {
	h.mu.Lock()
	h.status, h.body = status, bytes.Clone(body)
	h.mu.Unlock()
}
func (h *jwksHarness) hold(t testing.TB) func() {
	t.Helper()
	ch := make(chan struct{})
	h.mu.Lock()
	h.block = ch
	h.mu.Unlock()
	var once sync.Once
	release := func() { once.Do(func() { close(ch); h.mu.Lock(); h.block = nil; h.mu.Unlock() }) }
	t.Cleanup(release) // Registered after Close: released first, even on failure.
	return release
}
func (h *jwksHarness) verifier(t testing.TB, change func(*auth.Config)) *auth.Verifier {
	t.Helper()
	cfg := auth.Config{Issuer: "https://auth.example.com", Audiences: []string{"app-1"},
		JWKSURL: h.server.URL + "/.well-known/jwks.json", Now: h.now,
		HTTPClient: &http.Client{Timeout: 2 * time.Second}}
	if change != nil {
		change(&cfg)
	}
	v, err := auth.NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func (h *jwksHarness) waitCount(t testing.TB, want int64) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		n := h.count.Load()
		if n == want {
			return
		}
		if n > want {
			t.Fatalf("fetches=%d, want %d", n, want)
		}
		select {
		case <-deadline.C:
			t.Fatalf("fetches=%d, want %d before deadline", n, want)
		case <-tick.C:
		}
	}
}
func (h *jwksHarness) barrier(t testing.TB, v *auth.Verifier, k *testKey, want string) {
	t.Helper()
	before := h.count.Load()
	raw := signToken(t, k, happyClaims(), map[string]any{"kid": "barrier-unknown"})
	c, err := v.Verify(context.Background(), raw)
	reason := ""
	if want == "invalid_token" {
		reason = "key_unknown"
	}
	requireOutcome(t, c, err, want, reason)
	equal(t, h.count.Load(), before)
}

func requestWithBearer(raw string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if raw != "" {
		r.Header.Set("Authorization", "Bearer "+raw)
	}
	return r
}
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}
func assertRejected(t testing.TB, rr *httptest.ResponseRecorder, status int, header string) {
	t.Helper()
	equal(t, rr.Code, status)
	equal(t, rr.Header().Get(auth.ChallengeHeader), header)
	equal(t, rr.Header().Get("Cache-Control"), "no-store")
}
func assertNoToken(t testing.TB, text, raw string) {
	t.Helper()
	if strings.Contains(text, raw) || strings.Contains(text, "secret-subject-canary") {
		t.Fatal("credential-derived content leaked")
	}
}
func mustPanic(t testing.TB, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Error("constructor did not panic")
		}
	}()
	fn()
}

func configRowToGo(t testing.TB, row map[string]any) auth.Config {
	t.Helper()
	var cfg auth.Config
	body, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Issuer    string   `json:"issuer"`
		Audiences []string `json:"audiences"`
		URL       string   `json:"jwks_url"`
		Insecure  bool     `json:"allow_insecure_jwks_url"`
		Leeway    float64  `json:"leeway"`
		Types     []string `json:"token_types"`
		Age       float64  `json:"max_age"`
		Interval  float64  `json:"min_refresh_interval"`
		Stale     float64  `json:"max_stale"`
		Bytes     int64    `json:"max_bytes"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		t.Fatal(err)
	}
	cfg.Issuer, cfg.Audiences, cfg.JWKSURL = data.Issuer, data.Audiences, data.URL
	cfg.AllowInsecureJWKSURL, cfg.TokenTypes = data.Insecure, data.Types
	cfg.Leeway = time.Duration(data.Leeway * float64(time.Second))
	cfg.JWKS = auth.JWKSOptions{MaxAge: time.Duration(data.Age * float64(time.Second)),
		MinRefreshInterval: time.Duration(data.Interval * float64(time.Second)),
		MaxStale:           time.Duration(data.Stale * float64(time.Second)), MaxBytes: data.Bytes}
	return cfg
}

func tokenRows(t testing.TB) []tokenCase {
	t.Helper()
	var data struct {
		Cases []tokenCase `json:"cases"`
	}
	loadCorpus(t, "token-validation.json", 2, &data)
	return data.Cases
}
func runTokenRows(t *testing.T, include func(tokenCase) bool) {
	t.Helper()
	keys := testKeys(t)
	for _, row := range tokenRows(t) {
		if !include(row) {
			continue
		}
		t.Run(row.ID, func(t *testing.T) {
			h := newJWKSHarness(t, keys["rsa"], keys["ec"])
			h.setTime(row.Now)
			if row.JWKS == "unreachable" {
				h.respond(http.StatusServiceUnavailable, []byte("offline"))
			}
			v := h.verifier(t, func(c *auth.Config) {
				c.Issuer, c.Audiences, c.TokenTypes = row.Verifier.Issuer, row.Verifier.Audiences, row.Verifier.TokenTypes
				c.Leeway = time.Duration(row.Verifier.Leeway * float64(time.Second))
			})
			raw := tokenFromCase(t, keys, row)
			claims, err := v.Verify(context.Background(), raw)
			requireOutcome(t, claims, err, row.Expect.Outcome, row.Expect.Reason)
			if err != nil {
				assertNoToken(t, fmt.Sprintf("%+v", err), raw)
			}
			if strings.HasPrefix(row.ID, "malformed-") || row.Expect.Reason == "alg" || row.Expect.Reason == "crit" || row.Expect.Reason == "kid_missing" {
				equal(t, h.count.Load(), int64(0))
			}
			if !strings.ContainsAny(raw, "\r\n") {
				w := httptest.NewRecorder()
				v.Authenticate(okHandler()).ServeHTTP(w, requestWithBearer(raw))
				switch row.Expect.Outcome {
				case "ok":
					equal(t, w.Code, 200)
				case "invalid_token":
					assertRejected(t, w, 401, `Bearer error="invalid_token"`)
				case "jwks_unavailable":
					assertRejected(t, w, 503, "")
				}
				assertNoToken(t, w.Body.String(), raw)
			}
			if claims != nil {
				equal(t, claims.Subject, row.Claims["sub"])
				equal(t, claims.VerifiedBy(v), true)
				for tenantID, expected := range row.Expect.Tenants {
					if _, exists := claims.Tenants[tenantID]; !exists {
						t.Errorf("expected tenant %s absent", tenantID)
					}
					got := claims.Roles(tenantID)
					equal(t, len(got), len(expected.Roles))
					for i := range expected.Roles {
						if i < len(got) {
							equal(t, got[i], expected.Roles[i])
						}
					}
				}
				for _, id := range row.Expect.TenantsAbsent {
					if _, exists := claims.Tenants[id]; exists {
						t.Errorf("undecodable tenant %s retained", id)
					}
				}
			}
			// Invalid raw headers may contain LF and cannot be passed through HTTP.
			if row.Expect.Fetches != nil && row.JWKS != "unreachable" {
				h2 := newJWKSHarness(t, keys["rsa"], keys["ec"])
				h2.setTime(row.Now)
				v2 := h2.verifier(t, func(c *auth.Config) {
					c.Issuer, c.Audiences = row.Verifier.Issuer, row.Verifier.Audiences
				})
				if err := v2.Refresh(context.Background()); err != nil {
					t.Fatal(err)
				}
				for _, gate := range []struct {
					delta float64
					want  int64
				}{{0, row.Expect.Fetches.Closed}, {30, row.Expect.Fetches.Open}} {
					h2.setTime(row.Now + gate.delta)
					before := h2.count.Load()
					cc, ee := v2.Verify(context.Background(), raw)
					requireOutcome(t, cc, ee, row.Expect.Outcome, row.Expect.Reason)
					equal(t, h2.count.Load()-before, gate.want)
				}
			}
		})
	}
}
