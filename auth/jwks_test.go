package auth_test

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/usepassflow/go/auth"
)

func verifyHappy(t testing.TB, v *auth.Verifier, key *testKey) {
	t.Helper()
	c, err := v.Verify(context.Background(), signToken(t, key, happyClaims(), nil))
	requireOutcome(t, c, err, "ok", "")
}
func verifyUnknown(t testing.TB, v *auth.Verifier, key *testKey, outcome string) {
	t.Helper()
	c, err := v.Verify(context.Background(), signToken(t, key, happyClaims(), map[string]any{"kid": "unknown"}))
	reason := ""
	if outcome == "invalid_token" {
		reason = "key_unknown"
	}
	requireOutcome(t, c, err, outcome, reason)
}
func promptVerify(t testing.TB, v *auth.Verifier, raw string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	start := time.Now()
	c, err := v.Verify(ctx, raw)
	requireOutcome(t, c, err, "ok", "")
	if time.Since(start) >= time.Second {
		t.Fatal("known key waited for background fetch")
	}
}

// A successful reload replaces the set; it never accumulates retired keys.
func TestJWKS_ReloadReplacesWholeSet(t *testing.T) {
	k1 := generateTestKey(t, "RSA", "k1", 2048)
	k2 := generateTestKey(t, "RSA", "k2", 2048)
	h := newJWKSHarness(t, k1)
	v := h.verifier(t, nil)
	verifyHappy(t, v, k1)
	h.publish(t, k2)
	if err := v.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	verifyHappy(t, v, k2)
	c, err := v.Verify(context.Background(), signToken(t, k1, happyClaims(), nil))
	requireOutcome(t, c, err, "invalid_token", "key_unknown")
	equal(t, h.count.Load(), int64(2))
}

func TestJWKS_MinRefreshIntervalGate(t *testing.T) {
	key := generateTestKey(t, "RSA", "k1", 2048)
	h := newJWKSHarness(t, key)
	v := h.verifier(t, nil)
	verifyHappy(t, v, key)
	for range 8 {
		verifyUnknown(t, v, key, "invalid_token")
	}
	equal(t, h.count.Load(), int64(1))
	h.setTime(1700000030)
	verifyUnknown(t, v, key, "invalid_token")
	equal(t, h.count.Load(), int64(2))
	for range 8 {
		verifyUnknown(t, v, key, "invalid_token")
	}
	equal(t, h.count.Load(), int64(2))
}

func TestJWKS_SingleFlight(t *testing.T) {
	key := generateTestKey(t, "RSA", "k1", 2048)
	h := newJWKSHarness(t, key)
	release := h.hold(t)
	v := h.verifier(t, nil)
	raw := signToken(t, key, happyClaims(), nil)
	results := make(chan error, 24)
	for range 24 {
		go func() { _, err := v.Verify(context.Background(), raw); results <- err }()
	}
	h.waitCount(t, 1)
	release()
	for range 24 {
		if err := <-results; err != nil {
			t.Fatalf("concurrent verify failed: %v", err)
		}
	}
	equal(t, h.count.Load(), int64(1))
}

func TestJWKS_VerifyReturnsWhileRefreshHangs(t *testing.T) {
	key := generateTestKey(t, "RSA", "k1", 2048)
	h := newJWKSHarness(t, key)
	v := h.verifier(t, nil)
	raw := signToken(t, key, happyClaims(), nil)
	verifyHappy(t, v, key)
	h.hold(t)
	h.setTime(1700000601)
	promptVerify(t, v, raw)
	h.waitCount(t, 2)
	results := make(chan error, 12)
	for range 12 {
		go func() { _, err := v.Verify(context.Background(), raw); results <- err }()
	}
	for range 12 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("known key failed: %v", err)
			}
		case <-time.After(400 * time.Millisecond):
			t.Fatal("known key stalled on refresh")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	_, err := v.Verify(ctx, signToken(t, key, happyClaims(), map[string]any{"kid": "unknown"}))
	if !errors.Is(err, auth.ErrKeySetUnavailable) {
		t.Fatalf("unknown kid deadline category=%T", err)
	}
	equal(t, h.count.Load(), int64(2))
}

func TestJWKS_OneRequestNeverCostsTwoFetches(t *testing.T) {
	key := generateTestKey(t, "RSA", "k1", 2048)
	for _, row := range []struct {
		name string
		warm bool
		at   float64
		fail bool
	}{
		{"first-fetch", false, 1700000000, false}, {"old-set-success", true, 1700000601, false},
		{"old-set-failure", true, 1700000601, true}, {"past-max-stale", true, 1700003601, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			h := newJWKSHarness(t, key)
			v := h.verifier(t, func(c *auth.Config) {
				c.JWKS.MinRefreshInterval = time.Nanosecond
				// A nanosecond gate cannot conceal a duplicate attempt, even with an injected clock.
				c.Now = func() time.Time { return time.Unix(0, h.clock.Add(10)) }
			})
			if row.warm {
				verifyHappy(t, v, key)
			}
			before := h.count.Load()
			h.setTime(row.at)
			if row.fail {
				h.respond(503, []byte("down"))
			}
			outcome := "invalid_token"
			if row.fail {
				outcome = "jwks_unavailable"
			}
			verifyUnknown(t, v, key, outcome)
			equal(t, h.count.Load()-before, int64(1))
		})
	}
}

func TestJWKS_BackgroundFailureKeepsLastSuccess(t *testing.T) {
	checkBackgroundDeadline(t, false)
}

func TestJWKS_BackgroundSuccessMovesLastSuccess(t *testing.T) {
	checkBackgroundDeadline(t, true)
}
func checkBackgroundDeadline(t *testing.T, success bool) {
	t.Helper()
	key := generateTestKey(t, "RSA", "k1", 2048)
	h := newJWKSHarness(t, key)
	v := h.verifier(t, func(c *auth.Config) { c.JWKS.MaxAge = 10 * time.Second; c.JWKS.MaxStale = 100 * time.Second })
	verifyHappy(t, v, key)
	h.setTime(1700000080)
	if !success {
		h.respond(503, []byte("down"))
	}
	promptVerify(t, v, signToken(t, key, happyClaims(), nil))
	h.waitCount(t, 2)
	barrierOutcome := "invalid_token"
	if !success {
		barrierOutcome = "jwks_unavailable"
	}
	h.barrier(t, v, key, barrierOutcome)
	h.respond(503, []byte("down"))
	h.setTime(1700000101) // Past original success deadline; within second success deadline.
	c, err := v.Verify(context.Background(), signToken(t, key, happyClaims(), nil))
	if success {
		requireOutcome(t, c, err, "ok", "")
	} else {
		requireOutcome(t, c, err, "jwks_unavailable", "")
	}
}

func TestJWKS_GateClosesBackgroundRefresh(t *testing.T) {
	key := generateTestKey(t, "RSA", "k1", 2048)
	h := newJWKSHarness(t, key)
	v := h.verifier(t, func(c *auth.Config) { c.JWKS.MaxAge = 10 * time.Second; c.JWKS.MinRefreshInterval = time.Minute })
	verifyHappy(t, v, key)
	h.setTime(1700000020)
	verifyHappy(t, v, key)
	equal(t, h.count.Load(), int64(1))
	h.setTime(1700000061)
	verifyHappy(t, v, key)
	h.waitCount(t, 2)
	h.barrier(t, v, key, "invalid_token")
}

func TestRefresh_KeyPublishedAfterTheCallIsInTheSet(t *testing.T) {
	for _, laterFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("later-fails-%t", laterFails), func(t *testing.T) {
			k1 := generateTestKey(t, "RSA", "k1", 2048)
			k2 := generateTestKey(t, "RSA", "k2", 2048)
			h := newJWKSHarness(t, k1)
			v := h.verifier(t, nil)
			verifyHappy(t, v, k1)
			release := h.hold(t)
			h.setTime(1700000601)
			verifyHappy(t, v, k1)
			h.waitCount(t, 2) // Response snapshot contains k1 only.
			h.publish(t, k1, k2)
			if laterFails {
				h.respond(503, []byte("later response down"))
			}
			result := make(chan error, 1)
			called := make(chan struct{})
			go func() { close(called); result <- v.Refresh(context.Background()) }()
			<-called
			// A held fetch cannot satisfy the call, nor can Refresh return before it.
			select {
			case err := <-result:
				t.Fatalf("Refresh returned before pre-call response was released: %v", err)
			default:
			}
			// A second Refresh ending its wait must not wait for the server's timeout.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := v.Refresh(ctx); !errors.Is(err, auth.ErrKeySetUnavailable) {
				t.Errorf("cancelled Refresh category=%T", err)
			}
			release()
			select {
			case err := <-result:
				if laterFails {
					if !errors.Is(err, auth.ErrKeySetUnavailable) {
						t.Errorf("earlier success concealed later failure: %T", err)
					}
				} else if err != nil {
					t.Fatalf("Refresh failed: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Refresh did not settle")
			}
			equal(t, h.count.Load(), int64(3))
			if !laterFails {
				verifyHappy(t, v, k2)
				equal(t, h.count.Load(), int64(3))
			}
		})
	}
}

func TestJWKS_ConcurrentRotationNeverRejectsAnInstalledKey(t *testing.T) {
	k1 := generateTestKey(t, "RSA", "k1", 2048)
	k2 := generateTestKey(t, "RSA", "k2", 2048)
	for round := range 6 {
		t.Run(fmt.Sprint(round), func(t *testing.T) {
			h := newJWKSHarness(t, k1)
			v := h.verifier(t, nil)
			verifyHappy(t, v, k1)
			h.publish(t, k1, k2)
			h.setTime(1700000031)
			raw := signToken(t, k2, happyClaims(), nil)
			results := make(chan error, 24)
			for i := range 24 {
				go func(i int) {
					if i%3 == 0 {
						runtime.Gosched()
					}
					_, err := v.Verify(context.Background(), raw)
					results <- err
				}(i)
			}
			for range 24 {
				if err := <-results; err != nil {
					t.Fatalf("installed key rejected: %v", err)
				}
			}
			equal(t, h.count.Load(), int64(2))
		})
	}
}

func TestJWKS_StaleIfErrorWithinMaxStale(t *testing.T) { checkStaleDeadline(t, []float64{1700001800}) }

func TestJWKS_StaleTrustDeadline(t *testing.T) {
	checkStaleDeadline(t, []float64{1700001800, 1700002700, 1700003540})
}
func checkStaleDeadline(t *testing.T, schedule []float64) {
	t.Helper()
	key := generateTestKey(t, "RSA", "k1", 2048)
	h := newJWKSHarness(t, key)
	v := h.verifier(t, nil)
	verifyHappy(t, v, key)
	h.respond(503, []byte("down"))
	count := int64(1)
	for _, at := range schedule {
		h.setTime(at)
		promptVerify(t, v, signToken(t, key, happyClaims(), nil))
		count++
		h.waitCount(t, count)
		h.barrier(t, v, key, "jwks_unavailable")
	}
	h.setTime(1700003660)
	c, err := v.Verify(context.Background(), signToken(t, key, happyClaims(), nil))
	requireOutcome(t, c, err, "jwks_unavailable", "")
	equal(t, h.count.Load(), count+1)
}

func TestJWKS_UnknownKidRefetchFailureIs503(t *testing.T) {
	key := generateTestKey(t, "RSA", "k1", 2048)
	h := newJWKSHarness(t, key)
	v := h.verifier(t, nil)
	verifyHappy(t, v, key)
	h.respond(503, []byte("down"))
	h.setTime(1700000031)
	verifyUnknown(t, v, key, "jwks_unavailable")
	equal(t, h.count.Load(), int64(2))
}

func TestJWKS_GateRemembersFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			key := generateTestKey(t, "RSA", "k1", 2048)
			h := newJWKSHarness(t, key)
			v := h.verifier(t, nil)
			if fail {
				h.respond(503, []byte("down"))
			}
			want := "invalid_token"
			if fail {
				want = "jwks_unavailable"
			}
			for range 10 {
				verifyUnknown(t, v, key, want)
			}
			equal(t, h.count.Load(), int64(1))
		})
	}
}

func TestJWKS_NoRefetchOnBadSignature(t *testing.T) {
	keys := testKeys(t)
	h := newJWKSHarness(t, keys["rsa"])
	v := h.verifier(t, nil)
	verifyHappy(t, v, keys["rsa"])
	h.setTime(1700000031)
	raw := signToken(t, keys["other-rsa"], happyClaims(), map[string]any{"kid": keys["rsa"].id})
	c, err := v.Verify(context.Background(), raw)
	requireOutcome(t, c, err, "invalid_token", "signature")
	equal(t, h.count.Load(), int64(1))
}

func TestJWKS_KeyTypeMismatchIsUnknown(t *testing.T) {
	runTokenRows(t, func(row tokenCase) bool { return strings.HasPrefix(row.ID, "key-type-confusion-") })
}

func TestJWKS_SuccessRequiresWholeReload(t *testing.T) {
	key := generateTestKey(t, "RSA", "k1", 2048)
	for _, name := range []string{"html", "not-set", "over-cap", "duplicate"} {
		t.Run(name, func(t *testing.T) {
			h := newJWKSHarness(t, key)
			switch name {
			case "html":
				h.respond(200, []byte("<html>error</html>"))
			case "not-set":
				h.respond(200, []byte("{}"))
			case "over-cap":
				h.respond(200, make([]byte, 2049))
			case "duplicate":
				h.setJSON(t, []map[string]any{key.jwk, key.jwk})
			}
			v := h.verifier(t, func(c *auth.Config) { c.JWKS.MaxBytes = 2048 })
			for range 2 {
				c, err := v.Verify(context.Background(), signToken(t, key, happyClaims(), nil))
				requireOutcome(t, c, err, "jwks_unavailable", "")
				equal(t, h.count.Load(), int64(1))
			}
		})
	}
}

func TestJWKS_SuccessRequiresEveryUsableKey(t *testing.T) {
	anchor := generateTestKey(t, "RSA", "anchor", 2048)
	rsaKey := generateTestKey(t, "RSA", "subject-rsa", 2048)
	ecKey := generateTestKey(t, "EC", "subject-ec", 0)
	weak := generateTestKey(t, "RSA", "weak", 1024)
	rsaMissing := cloneMap(rsaKey.jwk)
	delete(rsaMissing, "n")
	delete(rsaMissing, "e")
	rsaBad := cloneMap(rsaKey.jwk)
	rsaBad["n"] = "not!base64url"
	ecOff := cloneMap(ecKey.jwk)
	ecOff["x"], ecOff["y"] = strings.Repeat("A", 43), strings.Repeat("A", 43)
	ecCurve := cloneMap(ecKey.jwk)
	ecCurve["crv"] = "P-384"
	ecCurve["alg"] = "ES256"
	rsaPrivate := cloneMap(rsaKey.jwk)
	rsaPrivate["d"] = base64.RawURLEncoding.EncodeToString(rsaKey.private.(*rsa.PrivateKey).D.Bytes())
	ecPrivate := cloneMap(ecKey.jwk)
	ecPrivate["d"] = base64.RawURLEncoding.EncodeToString([]byte{1})
	for _, row := range []struct {
		name string
		jwk  map[string]any
	}{
		{"rsa-missing", rsaMissing}, {"rsa-encoding", rsaBad}, {"weak-rsa", weak.jwk}, {"off-curve", ecOff},
		{"wrong-curve", ecCurve}, {"rsa-private", rsaPrivate}, {"ec-private", ecPrivate},
	} {
		t.Run(row.name, func(t *testing.T) {
			h := newJWKSHarness(t, anchor)
			h.setJSON(t, []map[string]any{anchor.jwk, row.jwk})
			v := h.verifier(t, nil)
			assertAcceptance(t, h, v, anchor, nil, acceptanceExpectation{Outcome: "reload_fails", Stage: "key"})
		})
	}
}

func TestJWKS_NoUsableKeyFailsReload(t *testing.T) {
	anchor := generateTestKey(t, "RSA", "anchor", 2048)
	for _, keys := range [][]map[string]any{{}, {{"kty": "oct", "kid": "oct", "k": "AA"}}} {
		h := newJWKSHarness(t, anchor)
		h.setJSON(t, keys)
		v := h.verifier(t, nil)
		assertAcceptance(t, h, v, anchor, nil, acceptanceExpectation{Outcome: "reload_fails", Stage: "key"})
	}
}

func TestJWKS_UnusableKeysAreSkipped(t *testing.T) {
	key := generateTestKey(t, "RSA", "k1", 2048)
	for _, row := range []map[string]any{
		{"kty": "oct", "kid": "oct", "k": "AA"}, {"kty": "RSA", "kid": "enc", "use": "enc"},
		{"kty": "RSA", "kid": "pss", "alg": "PS256"}, {"kty": "RSA"},
	} {
		h := newJWKSHarness(t, key)
		h.setJSON(t, []map[string]any{key.jwk, row})
		v := h.verifier(t, nil)
		verifyHappy(t, v, key)
		equal(t, h.count.Load(), int64(1))
	}
}

func TestJWKS_StaleSetSurvivesMalformedKey(t *testing.T) {
	key := generateTestKey(t, "RSA", "k1", 2048)
	h := newJWKSHarness(t, key)
	v := h.verifier(t, nil)
	verifyHappy(t, v, key)
	bad := cloneMap(key.jwk)
	bad["d"] = base64.RawURLEncoding.EncodeToString([]byte{1})
	h.setJSON(t, []map[string]any{bad})
	h.setTime(1700000601)
	promptVerify(t, v, signToken(t, key, happyClaims(), nil))
	h.waitCount(t, 2)
	h.barrier(t, v, key, "jwks_unavailable")
	verifyHappy(t, v, key)
	equal(t, h.count.Load(), int64(2))
	h.setTime(1700003601)
	c, err := v.Verify(context.Background(), signToken(t, key, happyClaims(), nil))
	requireOutcome(t, c, err, "jwks_unavailable", "")
	equal(t, h.count.Load(), int64(3))
}

// The checked JWKS URL cannot redirect to an unchecked trust source.
func TestJWKS_DoesNotFollowRedirects(t *testing.T) {
	key := generateTestKey(t, "RSA", "k1", 2048)
	target := newJWKSHarness(t, key)
	h := newJWKSHarness(t, key)
	v := h.verifier(t, func(c *auth.Config) {
		c.HTTPClient = &http.Client{Transport: redirectTransport{location: target.server.URL}}
	})
	c, err := v.Verify(context.Background(), signToken(t, key, happyClaims(), nil))
	requireOutcome(t, c, err, "jwks_unavailable", "")
	equal(t, target.count.Load(), int64(0))
}

type redirectTransport struct{ location string }

func (r redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasPrefix(req.URL.String(), r.location) {
		return http.DefaultTransport.RoundTrip(req)
	}
	return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{r.location}}, Body: http.NoBody, Request: req}, nil
}
