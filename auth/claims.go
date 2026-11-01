package auth

import (
	"context"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The claim names Passflow writes at the root of an access token, beyond the registered ones.
const (
	claimACR      = "acr"
	claimAMR      = "amr"
	claimAuthTime = "auth_time"
	claimScopes   = "scopes"
	claimSession  = "sid"
	claimTenants  = "passflow_tm"
	claimType     = "type"
)

// maxExactSeconds is the largest numeric date read from a token, 2^53: above it a JSON number is
// no longer an exact count of seconds, and converting it to int64 could overflow.
const maxExactSeconds = float64(1 << 53)

// TenantMembership is one entry of the passflow_tm claim, in its wire shape.
type TenantMembership struct {
	TenantID   string `json:"tenant_id"`
	TenantName string `json:"tenant_name"`
	// TenantRoles is decoded for raw access and is not consulted by [Claims.Roles]. The server
	// writes it as a copy derived from the root group's roles, which Roles reads directly.
	TenantRoles []string            `json:"tenant_roles"`
	RootGroupID string              `json:"root_group_id"`
	Groups      map[string][]string `json:"groups"`      // group ID to role names
	GroupNames  map[string]string   `json:"group_names"` // group ID to display name
}

// Claims is what a verified token says about its subject.
type Claims struct {
	Subject, Issuer, Type, SessionID string
	Audience, AMR, Scopes            []string
	ExpiresAt, IssuedAt              time.Time
	// AuthTime is the zero time when auth_time is absent or not a number.
	AuthTime time.Time
	// ACR is ACRNone when acr is absent or not a string.
	ACR ACR
	// Tenants holds passflow_tm by tenant ID. It is empty when the claim is absent, and a tenant
	// whose membership does not decode, such as one with a non-string in a role array, is dropped
	// without invalidating the token.
	Tenants map[string]TenantMembership
	// VerifiedAt is the verifier's clock at verification, at full precision. Freshness is measured
	// from it in whole seconds.
	VerifiedAt time.Time
	// Raw is every claim as decoded from JSON.
	Raw map[string]any

	// verifiedBy and self are the provenance: the verifier whose Verify returned this exact
	// object. A struct copy carries both fields, but its self still points at the original, so a
	// copy fails VerifiedBy and is verified again. Both are nil on hand-built claims.
	verifiedBy *Verifier
	self       *Claims
}

// Roles returns the subject's roles in a tenant, which are the roles of the tenant's root group.
// A missing tenant or root group has no roles. Nor does an empty root group ID, unlike the server: no
// role is granted from a group keyed by the empty string. The caller owns the result: writing to it
// does not change the claims.
func (c *Claims) Roles(tenantID string) []string {
	if c == nil {
		return nil
	}
	membership, ok := c.Tenants[tenantID]
	if !ok || membership.RootGroupID == "" {
		return nil
	}
	return slices.Clone(membership.Groups[membership.RootGroupID])
}

// HasRole reports whether the subject holds a role in a tenant, as resolved by [Claims.Roles].
func (c *Claims) HasRole(tenantID, role string) bool {
	return slices.Contains(c.Roles(tenantID), role)
}

// VerifiedBy reports whether these are the exact claims v's Verify returned. It is false for a
// struct copy, for hand-built claims and for claims from any other verifier, even one configured
// identically.
func (c *Claims) VerifiedBy(v *Verifier) bool {
	return c != nil && v != nil && c.self == c && c.verifiedBy == v
}

type claimsContextKey struct{}

// ContextWithClaims returns a context carrying the claims. It does not change their provenance.
func ContextWithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsContextKey{}, c)
}

// ClaimsFromContext returns the claims in a context.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsContextKey{}).(*Claims)
	return c, ok && c != nil
}

// newClaims extracts claims fail closed: a claim of the wrong JSON type reads as absent.
func newClaims(raw jwt.MapClaims) *Claims {
	c := &Claims{
		Subject:   stringClaim(raw, "sub"),
		Issuer:    stringClaim(raw, "iss"),
		Type:      stringClaim(raw, claimType),
		SessionID: stringClaim(raw, claimSession),
		AMR:       stringsClaim(raw[claimAMR]),
		Scopes:    stringsClaim(raw[claimScopes]),
		ExpiresAt: numericDate(raw["exp"]),
		IssuedAt:  numericDate(raw["iat"]),
		AuthTime:  numericDate(raw[claimAuthTime]),
		ACR:       ACRNone,
		Tenants:   tenantsClaim(raw[claimTenants]),
		Raw:       raw,
	}
	if audience, err := raw.GetAudience(); err == nil {
		c.Audience = audience
	}
	if acr, ok := raw[claimACR].(string); ok {
		c.ACR = ACR(acr)
	}
	return c
}

func stringClaim(raw jwt.MapClaims, name string) string {
	s, _ := raw[name].(string)
	return s
}

// stringsClaim reads a JSON array of strings, keeping only the strings.
func stringsClaim(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// numericDate reads a JSON number of seconds since the epoch, truncated toward zero. Anything else
// is the zero time.
func numericDate(v any) time.Time {
	seconds, ok := v.(float64)
	if !ok || seconds > maxExactSeconds || seconds < -maxExactSeconds {
		return time.Time{}
	}
	return time.Unix(int64(seconds), 0)
}

func tenantsClaim(v any) map[string]TenantMembership {
	tenants := map[string]TenantMembership{}
	entries, ok := v.(map[string]any)
	if !ok {
		return tenants
	}
	for id, entry := range entries {
		if membership, ok := decodeMembership(entry); ok {
			tenants[id] = membership
		}
	}
	return tenants
}

// decodeMembership reads a membership by exact key: encoding/json would match a struct's fields
// case-insensitively, and read a null array member as an empty string. An absent or null member is
// unset. Any other wrong type, including a non-string in a role array, makes the membership
// undecodable. @passflow/node applies the same rules.
func decodeMembership(entry any) (TenantMembership, bool) {
	fields, ok := entry.(map[string]any)
	if !ok {
		return TenantMembership{}, false
	}
	var m TenantMembership
	if m.TenantID, ok = optionalString(fields["tenant_id"]); !ok {
		return TenantMembership{}, false
	}
	if m.TenantName, ok = optionalString(fields["tenant_name"]); !ok {
		return TenantMembership{}, false
	}
	if m.TenantRoles, ok = optionalStrings(fields["tenant_roles"]); !ok {
		return TenantMembership{}, false
	}
	if m.RootGroupID, ok = optionalString(fields["root_group_id"]); !ok {
		return TenantMembership{}, false
	}
	if m.Groups, ok = optionalEntries(fields["groups"], optionalStrings); !ok {
		return TenantMembership{}, false
	}
	if m.GroupNames, ok = optionalEntries(fields["group_names"], optionalString); !ok {
		return TenantMembership{}, false
	}
	return m, true
}

func optionalString(v any) (string, bool) {
	if v == nil {
		return "", true
	}
	s, ok := v.(string)
	return s, ok
}

func optionalStrings(v any) ([]string, bool) {
	if v == nil {
		return nil, true
	}
	items, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// optionalEntries reads a JSON object, leaving out an entry that is null.
func optionalEntries[V any](v any, read func(any) (V, bool)) (map[string]V, bool) {
	if v == nil {
		return nil, true
	}
	entries, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	out := make(map[string]V, len(entries))
	for name, entry := range entries {
		if entry == nil {
			continue
		}
		value, ok := read(entry)
		if !ok {
			return nil, false
		}
		out[name] = value
	}
	return out, true
}
