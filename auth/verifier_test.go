package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/usepassflow/go/auth"
)

func TestVerify_AudienceAnyOf(t *testing.T) {
	runTokenRows(t, func(row tokenCase) bool { return strings.HasPrefix(row.ID, "audience-") })
}

type constructorTransport func(*http.Request) (*http.Response, error)

func (fn constructorTransport) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

// Required issuer/audience cannot become an optional check when the claim is absent.
func TestVerify_RequiredIssuerAndAudience(t *testing.T) {
	key := generateTestKey(t, "RSA", "k1", 2048)
	for _, claim := range []string{"iss", "aud"} {
		for _, value := range []any{nil, "", []any{}, float64(2)} {
			payload := happyClaims()
			payload[claim] = value
			h := newJWKSHarness(t, key)
			v := h.verifier(t, nil)
			c, err := v.Verify(context.Background(), signToken(t, key, payload, nil))
			if claim == "aud" {
				requireOutcome(t, c, err, "invalid_token", "audience")
			} else if !errors.Is(err, auth.ErrInvalidToken) || c != nil {
				t.Error("absent, empty or wrong-type issuer must invalidate the token")
			}
		}
		payload := happyClaims()
		delete(payload, claim)
		h := newJWKSHarness(t, key)
		v := h.verifier(t, nil)
		c, err := v.Verify(context.Background(), signToken(t, key, payload, nil))
		if claim == "aud" {
			requireOutcome(t, c, err, "invalid_token", "audience")
		} else if !errors.Is(err, auth.ErrInvalidToken) || c != nil {
			t.Error("missing issuer must invalidate the token")
		}
	}
}

func checkConfigs(t *testing.T, selectRow func(string) bool) {
	t.Helper()
	var data struct {
		Cases []struct {
			ID       string         `json:"id"`
			Config   map[string]any `json:"config"`
			Error    *string        `json:"error"`
			NodeOnly bool           `json:"node_only"`
		} `json:"cases"`
	}
	loadCorpus(t, "config.json", 2, &data)
	for _, row := range data.Cases {
		if row.NodeOnly || !selectRow(row.ID) {
			continue
		}
		t.Run(row.ID, func(t *testing.T) {
			cfg := configRowToGo(t, row.Config)
			var fetches atomic.Int64
			cfg.HTTPClient = &http.Client{Transport: constructorTransport(func(r *http.Request) (*http.Response, error) {
				fetches.Add(1)
				return &http.Response{StatusCode: 503, Header: make(http.Header), Body: http.NoBody, Request: r}, nil
			})}
			v, err := auth.NewVerifier(cfg)
			equal(t, fetches.Load(), int64(0))
			if row.Error == nil {
				if err != nil || v == nil {
					t.Fatalf("valid config rejected: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("invalid config accepted")
				}
				if !strings.Contains(err.Error(), *row.Error) {
					t.Fatalf("error does not name rejected option %q", *row.Error)
				}
				if strings.Contains(err.Error(), "keys.example.com") || strings.Contains(err.Error(), "keys.internal") {
					t.Error("JWKS URL leaked")
				}
			}
		})
	}
}

func TestNewVerifier_RejectsInsecureJWKSURL(t *testing.T) {
	checkConfigs(t, func(id string) bool { return strings.HasPrefix(id, "jwks-url-") && !strings.Contains(id, "loopback-") })
}

func TestNewVerifier_AllowsLoopback(t *testing.T) {
	checkConfigs(t, func(id string) bool { return strings.HasPrefix(id, "jwks-url-loopback-") })
}

func TestNewVerifier_LoopbackIsReadAsWritten(t *testing.T) {
	for _, host := range []string{"127.1", "2130706433", "0x7f.1", "127.00.0.1"} {
		t.Run(host, func(t *testing.T) {
			_, err := auth.NewVerifier(auth.Config{Issuer: "https://auth.example.com", Audiences: []string{"app-1"}, JWKSURL: "http://" + host + "/jwks"})
			if err == nil {
				t.Fatal("non-canonical loopback accepted")
			}
		})
	}
}

func TestNewVerifier_ValidatesJWKSOptions(t *testing.T) {
	checkConfigs(t, func(string) bool { return true })
}

func TestBearerToken_WhitespaceOnlyIsMissing(t *testing.T) {
	h := newJWKSHarness(t)
	v := h.verifier(t, nil)
	for _, value := range []string{"Bearer   ", "Bearer \t"} {
		r := requestWithBearer("")
		r.Header.Set("Authorization", value)
		_, err := auth.BearerToken(r)
		if !errors.Is(err, auth.ErrMissingToken) {
			t.Error("whitespace-only bearer was not missing")
		}
		w := httptest.NewRecorder()
		v.Authenticate(okHandler()).ServeHTTP(w, r)
		assertRejected(t, w, 401, "Bearer")
	}
	equal(t, h.count.Load(), int64(0))
}

func TestVerify_IATNotComparedWithTheClock(t *testing.T) {
	runTokenRows(t, func(row tokenCase) bool { return row.ID == "iat-absent" || row.ID == "iat-far-future" })
}

func TestVerify_NonNumericIATIsMalformed(t *testing.T) {
	runTokenRows(t, func(row tokenCase) bool {
		return row.ID == "iat-string" || row.ID == "iat-null" || row.ID == "iat-array"
	})
}
