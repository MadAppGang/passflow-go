package auth_test

import (
	"reflect"
	"testing"

	"github.com/usepassflow/go/auth"
)

func TestCORSExposedHeaders(t *testing.T) {
	for _, row := range []struct {
		name     string
		in, want []string
	}{
		{"empty", nil, []string{"WWW-Authenticate"}},
		{"request id", []string{"X-Request-Id"}, []string{"X-Request-Id", "WWW-Authenticate"}},
		{"already", []string{"WWW-Authenticate"}, []string{"WWW-Authenticate"}},
		{"lower case", []string{"www-authenticate"}, []string{"www-authenticate"}},
		{"wildcard", []string{"*"}, []string{"*", "WWW-Authenticate"}},
		{"duplicates", []string{"X-A", "X-A"}, []string{"X-A", "X-A", "WWW-Authenticate"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			before := append([]string(nil), row.in...)
			got := auth.CORSExposedHeaders(row.in...)
			equal(t, got, row.want)
			if !reflect.DeepEqual(before, row.in) {
				t.Error("helper modified input")
			}
		})
	}
	equal(t, auth.ChallengeHeader, "WWW-Authenticate")
}
