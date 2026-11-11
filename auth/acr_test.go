package auth_test

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/madappgang/passflow-go/auth"
)

type acrCorpus struct {
	Cases []struct {
		ACR   any    `json:"acr"`
		Level string `json:"server_level"`
	} `json:"cases"`
	Comparisons []struct {
		Token    *string `json:"token_acr"`
		Required string  `json:"required"`
		Allow    bool    `json:"allow"`
	} `json:"comparisons"`
}

func TestACR_LevelParseIntSemantics(t *testing.T) {
	var data acrCorpus
	loadCorpus(t, "acr-levels.json", 1, &data)
	for _, row := range data.Cases {
		value, isString := row.ACR.(string)
		if !isString {
			continue
		} // Raw non-strings bind Verify extraction, not this string API.
		t.Run(fmt.Sprintf("%q", value), func(t *testing.T) {
			want, err := strconv.ParseInt(row.Level, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			equal(t, auth.ACR(value).Level(), want)
			equal(t, auth.ACR(value).String(), value)
		})
	}
}

func TestACR_SatisfiesExactInt64(t *testing.T) {
	var data acrCorpus
	loadCorpus(t, "acr-levels.json", 1, &data)
	for i, row := range data.Comparisons {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			value := auth.ACRNone
			if row.Token != nil {
				value = auth.ACR(*row.Token)
			}
			equal(t, value.Satisfies(auth.ACR(row.Required)), row.Allow)
		})
	}
}

func TestACR_SatisfiesRejectsLevelZeroRequired(t *testing.T) {
	for _, row := range []struct{ token, required string }{{"3", "gold"}, {"3", ""}, {"3", "0"}, {"0", "0"}} {
		t.Run(row.token+"/"+row.required, func(t *testing.T) {
			equal(t, auth.ACR(row.token).Satisfies(auth.ACR(row.required)), false)
			mustPanic(t, func() { auth.Require(auth.ACR(row.required)) })
		})
	}
}
