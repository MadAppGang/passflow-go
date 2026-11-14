package auth_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/usepassflow/go/auth"
)

func TestConformance_TokenValidation(t *testing.T) {
	runTokenRows(t, func(tokenCase) bool { return true })
}

func TestConformance_Challenges(t *testing.T) { checkChallengeCorpus(t) }

func TestConformance_Config(t *testing.T) { checkConfigs(t, func(string) bool { return true }) }

func TestConformance_NonStringACR(t *testing.T) {
	var data acrCorpus
	loadCorpus(t, "acr-levels.json", 1, &data)
	key := generateTestKey(t, "RSA", "k1", 2048)
	for i, row := range data.Cases {
		if _, isString := row.ACR.(string); isString {
			continue
		}
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			h := newJWKSHarness(t, key)
			v := h.verifier(t, nil)
			payload := happyClaims()
			payload["acr"] = row.ACR
			raw := signToken(t, key, payload, nil)
			c, err := v.Verify(context.Background(), raw)
			requireOutcome(t, c, err, "ok", "")
			equal(t, c.ACR, auth.ACRNone)
			equal(t, c.ACR.Level(), int64(0))
			w := httptest.NewRecorder()
			v.Require(auth.AAL1)(okHandler()).ServeHTTP(w, requestWithBearer(raw))
			assertRejected(t, w, 401, `Bearer error="insufficient_user_authentication", acr_values="1"`)
		})
	}
}

type freshnessCorpus struct {
	Cases []struct {
		ID       string  `json:"id"`
		Now      float64 `json:"now"`
		AuthTime any     `json:"auth_time"`
		MaxAge   float64 `json:"max_age"`
		Allow    bool    `json:"allow"`
		Header   string  `json:"header_if_rejected"`
	} `json:"cases"`
	Inputs []struct {
		Input     any   `json:"input"`
		Effective int64 `json:"effective"`
		Error     bool  `json:"error"`
		NodeOnly  bool  `json:"node_only"`
	} `json:"max_age_input"`
}

func TestConformance_Freshness(t *testing.T) {
	var data freshnessCorpus
	loadCorpus(t, "freshness.json", 2, &data)
	key := generateTestKey(t, "RSA", "k1", 2048)
	for _, row := range data.Cases {
		t.Run(row.ID, func(t *testing.T) {
			h := newJWKSHarness(t, key)
			h.setTime(row.Now)
			v := h.verifier(t, nil)
			payload := happyClaims()
			payload["exp"] = row.Now + 3600
			delete(payload, "auth_time")
			if row.AuthTime != nil {
				payload["auth_time"] = row.AuthTime
			}
			raw := signToken(t, key, payload, nil)
			w := httptest.NewRecorder()
			v.RequireFresh(time.Duration(row.MaxAge)*time.Second)(okHandler()).ServeHTTP(w, requestWithBearer(raw))
			if row.Allow {
				equal(t, w.Code, 200)
			} else {
				assertRejected(t, w, 401, row.Header)
			}
			c, err := v.Verify(context.Background(), raw)
			requireOutcome(t, c, err, "ok", "")
			if !c.VerifiedAt.Equal(h.now()) {
				t.Error("VerifiedAt lost the injected instant or its fraction")
			}
		})
	}
}

func TestConformance_FreshnessConstructors(t *testing.T) {
	var data freshnessCorpus
	loadCorpus(t, "freshness.json", 2, &data)
	key := generateTestKey(t, "RSA", "k1", 2048)
	for i, row := range data.Inputs {
		if row.NodeOnly {
			continue
		}
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			seconds, ok := row.Input.(float64)
			if !ok {
				t.Fatal("non-numeric Go constructor row")
			}
			d := time.Duration(seconds * float64(time.Second))
			h := newJWKSHarness(t, key)
			v := h.verifier(t, nil)
			if row.Error {
				mustPanic(t, func() { auth.RequireFresh(d) })
				mustPanic(t, func() { v.RequireFresh(d) })
				return
			}
			for _, age := range []int64{row.Effective, row.Effective + 1} {
				c := &auth.Claims{AuthTime: time.Unix(1700000000-age, 0), VerifiedAt: time.Unix(1700000000, 0)}
				r := requestWithBearer("").WithContext(auth.ContextWithClaims(context.Background(), c))
				w := httptest.NewRecorder()
				auth.RequireFresh(d)(okHandler()).ServeHTTP(w, r)
				if age == row.Effective {
					equal(t, w.Code, 200)
				} else {
					assertRejected(t, w, 401, fmt.Sprintf(`Bearer error="insufficient_user_authentication", max_age=%d`, row.Effective))
				}
			}
		})
	}
}

func TestConformance_AuthorizationHeader(t *testing.T) {
	var data struct {
		Rows []struct {
			ID     string  `json:"id"`
			Value  *string `json:"value"`
			Expect struct {
				Outcome string `json:"outcome"`
			} `json:"expect"`
		} `json:"authorization_header"`
	}
	loadCorpus(t, "token-validation.json", 2, &data)
	key := generateTestKey(t, "RSA", "k1", 2048)
	for _, row := range data.Rows {
		t.Run(row.ID, func(t *testing.T) {
			h := newJWKSHarness(t, key)
			v := h.verifier(t, nil)
			raw := signToken(t, key, happyClaims(), nil)
			r := requestWithBearer("")
			if row.Value != nil {
				r.Header.Set("Authorization", strings.ReplaceAll(*row.Value, "<t>", raw))
			}
			w := httptest.NewRecorder()
			v.Authenticate(okHandler()).ServeHTTP(w, r)
			if row.Expect.Outcome == "ok" {
				equal(t, w.Code, 200)
			} else {
				assertRejected(t, w, 401, "Bearer")
				equal(t, h.count.Load(), int64(0))
			}
			assertNoToken(t, w.Body.String(), raw)
		})
	}
}

type keyMutation struct {
	Op     string `json:"op"`
	Member string `json:"member"`
	Value  any    `json:"value"`
}
type acceptanceExpectation struct {
	Outcome string `json:"outcome"`
	Stage   string `json:"stage"`
}

func mutateJWK(t testing.TB, original map[string]any, mutation keyMutation) map[string]any {
	t.Helper()
	out := cloneMap(original)
	if mutation.Op == "set" {
		out[mutation.Member] = mutation.Value
		return out
	}
	value, ok := out[mutation.Member].(string)
	if !ok || value == "" {
		t.Fatal("mutation member is not encoded key material")
	}
	switch mutation.Op {
	case "append":
		suffix, ok := mutation.Value.(string)
		if !ok {
			t.Fatal("append mutation has non-string value")
		}
		out[mutation.Member] = value + suffix
	case "set_unused_bit":
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		index := strings.IndexByte(alphabet, value[len(value)-1])
		if index < 0 || index == 63 {
			t.Fatal("invalid canonical test member")
		}
		out[mutation.Member] = value[:len(value)-1] + alphabet[index+1:index+2]
	case "drop_first_byte", "prepend_zero_byte":
		raw, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(raw) == 0 {
			t.Fatal("cannot decode generated test member")
		}
		if mutation.Op == "drop_first_byte" {
			raw = raw[1:]
		} else {
			raw = append([]byte{0}, raw...)
		}
		out[mutation.Member] = base64.RawURLEncoding.EncodeToString(raw)
	default:
		t.Fatal("unknown key mutation operation")
	}
	return out
}

// Valid controls are essential; rejecting every set must fail.
func TestConformance_KeyAcceptance(t *testing.T) {
	var data struct {
		Cases []struct {
			ID     string                `json:"id"`
			KTY    string                `json:"kty"`
			Mutate keyMutation           `json:"mutate"`
			Expect acceptanceExpectation `json:"expect"`
		} `json:"cases"`
		Body []struct {
			ID    string `json:"id"`
			Bytes struct {
				Prefix string `json:"prefix_hex"`
				Note   string `json:"note_hex"`
			} `json:"bytes"`
			Expect acceptanceExpectation `json:"expect"`
		} `json:"body"`
	}
	loadCorpus(t, "key-acceptance.json", 1, &data)
	for _, kty := range []string{"RSA", "EC"} {
		t.Run("unmutated-"+kty, func(t *testing.T) {
			anchor := generateTestKey(t, "RSA", "anchor", 2048)
			subject := generateTestKey(t, kty, "subject", 2048)
			h := newJWKSHarness(t, anchor, subject)
			v := h.verifier(t, nil)
			for _, key := range []*testKey{anchor, subject} {
				c, err := v.Verify(context.Background(), signToken(t, key, happyClaims(), nil))
				requireOutcome(t, c, err, "ok", "")
			}
			equal(t, h.count.Load(), int64(1))
		})
	}
	for _, row := range data.Cases {
		t.Run(row.ID, func(t *testing.T) {
			anchor := generateTestKey(t, "RSA", "anchor", 2048)
			subject := generateTestKey(t, row.KTY, "subject", 2048)
			h := newJWKSHarness(t, anchor)
			h.setJSON(t, []map[string]any{anchor.jwk, mutateJWK(t, subject.jwk, row.Mutate)})
			v := h.verifier(t, nil)
			assertAcceptance(t, h, v, anchor, subject, row.Expect)
		})
	}
	for _, row := range data.Body {
		t.Run(row.ID, func(t *testing.T) {
			anchor := generateTestKey(t, "RSA", "anchor", 2048)
			subject := generateTestKey(t, "RSA", "subject", 2048)
			anchor.jwk["note"] = "@@"
			h := newJWKSHarness(t, anchor, subject)
			h.mu.RLock()
			body := bytes.Clone(h.body)
			h.mu.RUnlock()
			if row.Bytes.Prefix != "" {
				prefix, err := hex.DecodeString(row.Bytes.Prefix)
				if err != nil {
					t.Fatal(err)
				}
				body = append(prefix, body...)
			} else {
				note, err := hex.DecodeString(row.Bytes.Note)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Count(body, []byte("@@")) != 1 {
					t.Fatal("byte splice marker not unique")
				}
				body = bytes.Replace(body, []byte("@@"), note, 1)
			}
			h.respond(200, body)
			v := h.verifier(t, nil)
			assertAcceptance(t, h, v, anchor, subject, row.Expect)
		})
	}
}
func assertAcceptance(t testing.TB, h *jwksHarness, v *auth.Verifier, anchor, subject *testKey, want acceptanceExpectation) {
	t.Helper()
	raw := signToken(t, anchor, happyClaims(), nil)
	c, err := v.Verify(context.Background(), raw)
	if want.Outcome == "reload_fails" {
		requireOutcome(t, c, err, "jwks_unavailable", "")
		if !strings.HasSuffix(err.Error(), ": "+want.Stage) {
			t.Errorf("failure did not report corpus stage %s", want.Stage)
		}
		equal(t, h.count.Load(), int64(1))
		c, err = v.Verify(context.Background(), raw)
		requireOutcome(t, c, err, "jwks_unavailable", "")
	} else {
		requireOutcome(t, c, err, "ok", "")
		if want.Outcome == "key_skipped" {
			c, err = v.Verify(context.Background(), signToken(t, subject, happyClaims(), nil))
			requireOutcome(t, c, err, "invalid_token", "key_unknown")
		}
	}
	equal(t, h.count.Load(), int64(1))
}
