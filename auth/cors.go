package auth

import (
	"slices"
	"strings"
)

// ChallengeHeader is the response header that carries a challenge. It is not CORS-safelisted, so a
// browser hides it from cross-origin callers unless the response exposes it by name.
const ChallengeHeader = "WWW-Authenticate"

// CORSExposedHeaders returns the given exposed headers with [ChallengeHeader] named explicitly,
// for a CORS middleware's exposed-headers option. Entries are kept as given, including "*", which
// is not a wildcard on a request with credentials. The input is not modified.
func CORSExposedHeaders(existing ...string) []string {
	exposed := slices.Clone(existing)
	for _, header := range existing {
		if strings.EqualFold(strings.TrimSpace(header), ChallengeHeader) {
			return exposed
		}
	}
	return append(exposed, ChallengeHeader)
}
