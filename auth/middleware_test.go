package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/madappgang/passflow-go/auth"
)

func TestRequire_WithoutAuthenticateIs500(t *testing.T) {
	// Contract amendment A1: each wiring error identifies its own constructor.
	for _, tc := range []struct {
		mw       func(http.Handler) http.Handler
		wantBody string
	}{
		{auth.Require(auth.AAL2), "passflow auth: Require used without Authenticate"},
		{auth.RequireFresh(time.Minute), "passflow auth: RequireFresh used without Authenticate"},
	} {
		w := httptest.NewRecorder()
		tc.mw(okHandler()).ServeHTTP(w, requestWithBearer(""))
		equal(t, w.Code, http.StatusInternalServerError)
		equal(t, w.Header().Get(auth.ChallengeHeader), "")
		equal(t, w.Header().Get("Cache-Control"), "no-store")
		// http.Error is permitted to append a newline.
		if w.Body.String() != tc.wantBody+"\n" && w.Body.String() != tc.wantBody {
			t.Error("wiring error body differs from contract")
		}
	}
}

func TestVerifierRequire_AuthenticatesOnDemand(t *testing.T) {
	key := generateTestKey(t, "RSA", "k1", 2048)
	h := newJWKSHarness(t, key)
	v := h.verifier(t, nil)
	raw := signToken(t, key, happyClaims(), nil)
	for _, mw := range []func(http.Handler) http.Handler{v.Require(auth.AAL2), v.RequireFresh(5 * time.Minute)} {
		w := httptest.NewRecorder()
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, ok := auth.ClaimsFromContext(r.Context())
			if !ok || !c.VerifiedBy(v) {
				t.Error("handler did not receive verifier's claims")
			}
			w.WriteHeader(200)
		})
		mw(next).ServeHTTP(w, requestWithBearer(raw))
		equal(t, w.Code, 200)
	}
}

// Exact identity and the contract-declared verification budget both bind reuse.
func TestVerifierRequire_ReusesOwnClaims(t *testing.T) {
	key := generateTestKey(t, "RSA", "k1", 2048)
	h := newJWKSHarness(t, key)
	v := h.verifier(t, nil)
	verifications := 0
	auth.SetVerifyHook(v, func() { verifications++ })
	c, err := v.Verify(context.Background(), signToken(t, key, happyClaims(), nil))
	requireOutcome(t, c, err, "ok", "")
	for _, mw := range []func(http.Handler) http.Handler{v.Require(auth.AAL2), v.RequireFresh(time.Minute)} {
		r := requestWithBearer("").WithContext(auth.ContextWithClaims(context.Background(), c))
		w := httptest.NewRecorder()
		mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, _ := auth.ClaimsFromContext(r.Context())
			if got != c {
				t.Error("own exact claims were not reused")
			}
			w.WriteHeader(200)
		})).ServeHTTP(w, r)
		equal(t, w.Code, 200)
		equal(t, verifications, 1)
	}
}

func TestVerifierRequire_ReverifiesCopiedClaims(t *testing.T) {
	key := generateTestKey(t, "RSA", "k1", 2048)
	h := newJWKSHarness(t, key)
	v := h.verifier(t, nil)
	raw := signToken(t, key, happyClaims(), nil)
	for _, mw := range []func(http.Handler) http.Handler{v.Require(auth.AAL2), v.RequireFresh(time.Minute)} {
		verifications := 0
		auth.SetVerifyHook(v, func() { verifications++ })
		c, err := v.Verify(context.Background(), raw)
		requireOutcome(t, c, err, "ok", "")
		copied := *c
		copied.Subject = "edited-subject"
		copied.ACR = auth.AAL3
		r := requestWithBearer(raw).WithContext(auth.ContextWithClaims(context.Background(), &copied))
		w := httptest.NewRecorder()
		mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, ok := auth.ClaimsFromContext(r.Context())
			if !ok || got == &copied || got == c || !got.VerifiedBy(v) {
				t.Error("copy was reused or fresh identity missing")
			}
			equal(t, got.Subject, "user-1")
			equal(t, got.ACR, auth.AAL2)
			w.WriteHeader(200)
		})).ServeHTTP(w, r)
		equal(t, w.Code, 200)
		equal(t, verifications, 2)
	}
}

type compositionRow struct {
	ID          string `json:"id"`
	Arrangement string `json:"arrangement"`
	Upstream    struct {
		Issuer    string   `json:"issuer"`
		Audiences []string `json:"audiences"`
	} `json:"upstream"`
	Route struct {
		Issuer    string   `json:"issuer"`
		Audiences []string `json:"audiences"`
	} `json:"route"`
	Token  map[string]any `json:"token"`
	Expect struct {
		Outcome       string `json:"outcome"`
		Reason        string `json:"reason"`
		ClaimsFrom    string `json:"claims_from"`
		Verifications int    `json:"verifications"`
	} `json:"expect"`
}

// Corpus outcomes, public claim provenance and its declared verification budget.
func TestVerifierRequire_ReverifiesClaimsFromAnotherVerifier(t *testing.T) {
	var data struct {
		Rows []compositionRow `json:"composition"`
	}
	loadCorpus(t, "token-validation.json", 2, &data)
	key := generateTestKey(t, "RSA", "k1", 2048)
	for _, row := range data.Rows {
		t.Run(row.ID, func(t *testing.T) {
			h := newJWKSHarness(t, key)
			upstream := h.verifier(t, func(c *auth.Config) { c.Issuer, c.Audiences = row.Upstream.Issuer, row.Upstream.Audiences })
			route := h.verifier(t, func(c *auth.Config) { c.Issuer, c.Audiences = row.Route.Issuer, row.Route.Audiences })
			if row.Arrangement == "same_instance" || row.Arrangement == "copied_claims" {
				route = upstream
			}
			verifications := 0
			countVerification := func() { verifications++ }
			auth.SetVerifyHook(upstream, countVerification)
			if route != upstream {
				auth.SetVerifyHook(route, countVerification)
			}
			payload := happyClaims()
			for k, v := range row.Token {
				payload[k] = v
			}
			raw := signToken(t, key, payload, nil)
			r := requestWithBearer(raw)
			var original *auth.Claims
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, ok := auth.ClaimsFromContext(r.Context())
				if !ok || !got.VerifiedBy(route) {
					t.Error("route verifier's claims not visible")
				}
				if row.Expect.ClaimsFrom == "upstream" && got != original {
					t.Error("upstream exact object not reused")
				}
				if row.Expect.ClaimsFrom == "route" && got == original {
					t.Error("foreign/copy object reused")
				}
				w.WriteHeader(200)
			})
			protected := route.Require(auth.AAL2)(next)
			observe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				original, _ = auth.ClaimsFromContext(r.Context())
				if row.Arrangement == "copied_claims" {
					copy := *original
					r = r.WithContext(auth.ContextWithClaims(r.Context(), &copy))
				}
				protected.ServeHTTP(w, r)
			})
			w := httptest.NewRecorder()
			if row.Arrangement == "foreign_claims_no_header" {
				c, err := upstream.Verify(context.Background(), raw)
				requireOutcome(t, c, err, "ok", "")
				r = requestWithBearer("").WithContext(auth.ContextWithClaims(context.Background(), c))
				protected.ServeHTTP(w, r)
			} else {
				upstream.Authenticate(observe).ServeHTTP(w, r)
			}
			switch row.Expect.Outcome {
			case "ok":
				equal(t, w.Code, 200)
			case "missing_token":
				assertRejected(t, w, 401, "Bearer")
			case "invalid_token":
				assertRejected(t, w, 401, `Bearer error="invalid_token"`)
			default:
				t.Fatal("unsupported composition outcome")
			}
			equal(t, verifications, row.Expect.Verifications)
		})
	}
}

func TestAuthenticate_ReplacesUpstreamClaims(t *testing.T) {
	key := generateTestKey(t, "RSA", "k1", 2048)
	h := newJWKSHarness(t, key)
	v := h.verifier(t, nil)
	upstream := &auth.Claims{Subject: "foreign", ACR: auth.AAL3}
	r := requestWithBearer(signToken(t, key, happyClaims(), nil))
	r = r.WithContext(auth.ContextWithClaims(r.Context(), upstream))
	w := httptest.NewRecorder()
	v.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := auth.ClaimsFromContext(r.Context())
		if !ok || got == upstream || !got.VerifiedBy(v) {
			t.Error("Authenticate trusted upstream claims")
		}
		equal(t, got.Subject, "user-1")
		w.WriteHeader(200)
	})).ServeHTTP(w, r)
	equal(t, w.Code, 200)
}

func TestRequireFresh_MeasuresFromVerifiedAt(t *testing.T) {
	c := &auth.Claims{AuthTime: time.Unix(1700000300, 0), VerifiedAt: time.Unix(1700000600, 0)}
	w := httptest.NewRecorder()
	r := requestWithBearer("").WithContext(auth.ContextWithClaims(context.Background(), c))
	auth.RequireFresh(300*time.Second)(okHandler()).ServeHTTP(w, r)
	equal(t, w.Code, 200) // The real wall clock is irrelevant.
}

func TestRequireFresh_ComparesWholeSeconds(t *testing.T) {
	key := generateTestKey(t, "RSA", "k1", 2048)
	for _, row := range []struct {
		now    float64
		status int
	}{{1700000600.5, 200}, {1700000601.25, 401}} {
		h := newJWKSHarness(t, key)
		h.setTime(row.now)
		v := h.verifier(t, nil)
		payload := happyClaims()
		payload["auth_time"] = 1700000300
		c, err := v.Verify(context.Background(), signToken(t, key, payload, nil))
		requireOutcome(t, c, err, "ok", "")
		if !c.VerifiedAt.Equal(h.now()) {
			t.Error("VerifiedAt lost the injected instant or its fraction")
		}
		w := httptest.NewRecorder()
		r := requestWithBearer("").WithContext(auth.ContextWithClaims(context.Background(), c))
		auth.RequireFresh(300*time.Second)(okHandler()).ServeHTTP(w, r)
		equal(t, w.Code, row.status)
		if row.status == 401 {
			assertRejected(t, w, 401, `Bearer error="insufficient_user_authentication", max_age=300`)
		}
	}
}

func TestRequireFresh_PanicsBelowOneSecond(t *testing.T) {
	for _, d := range []time.Duration{-time.Second, 0, 900 * time.Millisecond} {
		mustPanic(t, func() { auth.RequireFresh(d) })
	}
}
