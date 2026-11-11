package auth_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/madappgang/passflow-go/auth"
)

type challengeCorpus struct {
	Cases []struct {
		ID     string  `json:"id"`
		ACR    *string `json:"acr_values"`
		Age    *int64  `json:"max_age"`
		Header string  `json:"header"`
		Status int     `json:"status"`
		Cache  string  `json:"cache_control"`
	} `json:"cases"`
}

func TestChallenge_TruncatesToWholeSeconds(t *testing.T) {
	c := auth.Challenge{ACRValues: "2", MaxAge: 2500 * time.Millisecond}
	equal(t, c.String(), `Bearer error="insufficient_user_authentication", acr_values="2", max_age=2`)
}

func TestChallenge_OmitsNonPositiveMaxAge(t *testing.T) {
	for _, age := range []time.Duration{0, -5 * time.Second, 900 * time.Millisecond, -900 * time.Millisecond} {
		equal(t, (auth.Challenge{MaxAge: age}).String(), `Bearer error="insufficient_user_authentication"`)
	}
}

func checkChallengeCorpus(t *testing.T) {
	t.Helper()
	var data challengeCorpus
	loadCorpus(t, "challenges.json", 1, &data)
	for _, row := range data.Cases {
		t.Run(row.ID, func(t *testing.T) {
			c := auth.Challenge{}
			if row.ACR != nil {
				c.ACRValues = *row.ACR
			}
			if row.Age != nil {
				c.MaxAge = time.Duration(*row.Age) * time.Second
			}
			equal(t, c.String(), row.Header)
			w := httptest.NewRecorder()
			c.Write(w)
			equal(t, w.Code, row.Status)
			equal(t, w.Header().Get(auth.ChallengeHeader), row.Header)
			equal(t, w.Header().Get("Cache-Control"), row.Cache)
			equal(t, w.Body.Len(), 0)
		})
	}
}
