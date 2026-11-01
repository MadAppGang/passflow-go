package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

const (
	algRS256 = "RS256"
	algES256 = "ES256"
)

// tokenHeader is what the inspection established about a token's protected header.
type tokenHeader struct {
	alg  string
	kid  string
	kind keyKind
}

// inspectHeader applies the header rules on the raw token, before any key lookup. The order is
// shared with @passflow/node: malformed, then alg, then crit, then kid. The JWT library would decide
// the algorithm only after parsing, and the two languages would then disagree on the reason.
//
// The header decodes into a map because encoding/json matches struct fields case-insensitively,
// so a struct would read "ALG" as "alg" where the JOSE header names are case-sensitive.
func inspectHeader(token string) (tokenHeader, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return tokenHeader{}, rejection(ReasonMalformed)
	}
	// The decoder refuses everything outside the base64url alphabet except line breaks, which it
	// skips, so those are refused here. encoding/json would read invalid UTF-8 as U+FFFD.
	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || strings.ContainsAny(parts[0], "\r\n") || !utf8.Valid(decoded) {
		return tokenHeader{}, rejection(ReasonMalformed)
	}
	var header map[string]any
	// A leading BOM fails this decode. A JSON null decodes into a nil map without an error.
	if err := json.Unmarshal(decoded, &header); err != nil || header == nil {
		return tokenHeader{}, rejection(ReasonMalformed)
	}

	alg, _ := header["alg"].(string)
	var kind keyKind
	switch alg {
	case algRS256:
		kind = keyKindRSA
	case algES256:
		kind = keyKindP256
	default:
		return tokenHeader{}, rejection(ReasonAlg)
	}

	if _, present := header["crit"]; present {
		return tokenHeader{}, rejection(ReasonCrit)
	}

	kid, _ := header["kid"].(string)
	if kid == "" {
		return tokenHeader{}, rejection(ReasonKIDMissing)
	}
	return tokenHeader{alg: alg, kid: kid, kind: kind}, nil
}
