package authgin_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/madappgang/passflow-go/auth"
	"github.com/madappgang/passflow-go/auth/authgin"
)

func ginTestVerifier(t *testing.T) (*auth.Verifier, func(string, int64) string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": "k1", "n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	t.Cleanup(server.Close)
	v, err := auth.NewVerifier(auth.Config{Issuer: "https://auth.example.com", Audiences: []string{"app-1"},
		JWKSURL: server.URL, Now: func() time.Time { return time.Unix(1700000000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	sign := func(acr string, at int64) string {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": "https://auth.example.com", "sub": "gin-user", "aud": []string{"app-1"},
			"exp": 1700003600, "type": "access", "acr": acr, "auth_time": at})
		token.Header["kid"] = "k1"
		raw, err := token.SignedString(key)
		if err != nil {
			t.Fatal("cannot sign test token")
		}
		return raw
	}
	return v, sign
}

// REQ-17: real Gin request context, not a bridge-helper test.
func TestAuthgin_ContextPropagation(t *testing.T) {
	v, sign := ginTestVerifier(t)
	engine := gin.New()
	group := engine.Group("/", authgin.Authenticate(v))
	group.GET("/invoices", authgin.Require(auth.AAL2), func(c *gin.Context) {
		claims, ok := authgin.Claims(c)
		if !ok || claims.Subject != "gin-user" || !claims.VerifiedBy(v) {
			t.Error("Gin lost verified claims")
		}
		requestClaims, requestOK := auth.ClaimsFromContext(c.Request.Context())
		if !requestOK || requestClaims != claims {
			t.Error("Gin request and accessor do not share claims")
		}
		c.String(200, "protected")
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/invoices", nil)
	r.Header.Set("Authorization", "Bearer "+sign("2", 1700000000))
	engine.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "protected" {
		t.Error("protected response missing or written more than once")
	}
}

// REQ-12, REQ-17
func TestAuthgin_SingleWriteAndAbort(t *testing.T) {
	v, sign := ginTestVerifier(t)
	engine := gin.New()
	group := engine.Group("/", authgin.Authenticate(v))
	group.GET("/invoices", authgin.Require(auth.AAL2), func(c *gin.Context) { c.String(200, "PROTECTED-HANDLER") })
	group.GET("/transfers", authgin.RequireFresh(300*time.Second), func(c *gin.Context) { c.String(200, "PROTECTED-HANDLER") })
	for _, row := range []struct{ path, bearer, header string }{
		{"/invoices", "", "Bearer"},
		{"/invoices", "not-a-token", `Bearer error="invalid_token"`},
		{"/invoices", sign("1", 1700000000), `Bearer error="insufficient_user_authentication", acr_values="2"`},
		{"/transfers", sign("2", 1699999699), `Bearer error="insufficient_user_authentication", max_age=300`},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", row.path, nil)
		if row.bearer != "" {
			r.Header.Set("Authorization", "Bearer "+row.bearer)
		}
		engine.ServeHTTP(w, r)
		if w.Code != 401 || w.Header().Get("WWW-Authenticate") != row.header ||
			w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "PROTECTED-HANDLER") {
			t.Errorf("%s did not terminate with one exact rejection", row.path)
		}
	}
}

// REQ-11, REQ-17, REQ-19
func TestAuthgin_FreshnessConstructors(t *testing.T) {
	body, err := os.ReadFile("../testdata/corpus/freshness.json")
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Version int `json:"corpus_version"`
		Inputs  []struct {
			Input     any   `json:"input"`
			Error     bool  `json:"error"`
			NodeOnly  bool  `json:"node_only"`
			Effective int64 `json:"effective"`
		} `json:"max_age_input"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		t.Fatal(err)
	}
	if data.Version != 2 {
		t.Fatal("freshness corpus version changed")
	}
	v, sign := ginTestVerifier(t)
	for _, row := range data.Inputs {
		if row.NodeOnly {
			continue
		}
		seconds, ok := row.Input.(float64)
		if !ok {
			t.Fatal("Go duration input is not numeric")
		}
		func() {
			defer func() {
				panicked := recover() != nil
				if panicked != row.Error {
					t.Errorf("panic=%t, want %t", panicked, row.Error)
				}
			}()
			duration := time.Duration(seconds * float64(time.Second))
			authgin.RequireFresh(duration)
			for _, age := range []int64{row.Effective, row.Effective + 1} {
				engine := gin.New()
				engine.GET("/", authgin.Authenticate(v), authgin.RequireFresh(duration), func(c *gin.Context) { c.String(200, "protected") })
				request := httptest.NewRequest("GET", "/", nil)
				request.Header.Set("Authorization", "Bearer "+sign("2", 1700000000-age))
				w := httptest.NewRecorder()
				engine.ServeHTTP(w, request)
				want := 200
				if age > row.Effective {
					want = 401
				}
				if w.Code != want {
					t.Errorf("effective freshness verdict=%d, want %d", w.Code, want)
				}
				if want == 401 && w.Header().Get("WWW-Authenticate") != fmt.Sprintf(`Bearer error="insufficient_user_authentication", max_age=%d`, row.Effective) {
					t.Error("emitted limit differs from enforced whole seconds")
				}
			}
		}()
	}
}
