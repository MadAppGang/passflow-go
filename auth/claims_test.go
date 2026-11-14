package auth_test

import (
	"context"
	"strings"
	"testing"

	"github.com/usepassflow/go/auth"
)

func claimsWithRoles() *auth.Claims {
	return &auth.Claims{Tenants: map[string]auth.TenantMembership{
		"t1": {TenantID: "t1", TenantRoles: []string{"owner"}, RootGroupID: "root",
			Groups: map[string][]string{"root": {"admin"}, "other": {"viewer"}}},
	}}
}

func TestClaims_RolesFromRootGroup(t *testing.T) {
	c := claimsWithRoles()
	equal(t, c.Roles("t1"), []string{"admin"})
	equal(t, c.HasRole("t1", "admin"), true)
	equal(t, c.HasRole("t1", "viewer"), false)
}

func TestClaims_RolesIgnoreTenantRoles(t *testing.T) {
	c := claimsWithRoles()
	equal(t, c.HasRole("t1", "owner"), false)
	c.Tenants["t2"] = auth.TenantMembership{TenantRoles: []string{"owner"}}
	equal(t, c.Roles("t2"), []string(nil))
}

func TestClaims_RolesMissingRootGroupIsNil(t *testing.T) {
	c := claimsWithRoles()
	c.Tenants["missing-root"] = auth.TenantMembership{RootGroupID: "absent", Groups: map[string][]string{"other": {"admin"}}}
	c.Tenants["empty-root"] = auth.TenantMembership{Groups: map[string][]string{"": {"admin"}}}
	c.Tenants["nil-map"] = auth.TenantMembership{RootGroupID: "root"}
	for _, id := range []string{"missing", "missing-root", "empty-root", "nil-map"} {
		equal(t, c.Roles(id), []string(nil))
		equal(t, c.HasRole(id, "admin"), false)
	}
}

func TestClaims_RolesReturnsACopy(t *testing.T) {
	c := claimsWithRoles()
	first := c.Roles("t1")
	if len(first) != 1 {
		t.Fatal("expected one role")
	}
	first[0] = "owner"
	equal(t, c.Roles("t1"), []string{"admin"})
	equal(t, c.HasRole("t1", "admin"), true)
	equal(t, c.HasRole("t1", "owner"), false)
	equal(t, c.Roles("missing"), []string(nil))
}

func TestClaims_UndecodableMembershipDropsTenantOnly(t *testing.T) {
	runTokenRows(t, func(row tokenCase) bool { return len(row.Expect.TenantsAbsent) > 0 })
	keys := testKeys(t)
	for _, bad := range []any{"not-an-object", float64(1), []any{"admin"}} {
		h := newJWKSHarness(t, keys["rsa"])
		v := h.verifier(t, nil)
		payload := happyClaims()
		payload["passflow_tm"] = map[string]any{"bad": bad, "good": map[string]any{"root_group_id": "g", "groups": map[string]any{"g": []string{"viewer"}}}}
		c, err := v.Verify(context.Background(), signToken(t, keys["rsa"], payload, nil))
		requireOutcome(t, c, err, "ok", "")
		if _, exists := c.Tenants["bad"]; exists {
			t.Error("bad membership retained")
		}
		equal(t, c.Roles("good"), []string{"viewer"})
	}
}

func TestClaims_MembershipKeysAreExact(t *testing.T) {
	runTokenRows(t, func(row tokenCase) bool { return row.ID == "passflow-tm-keys-match-exactly" })
}

func TestClaims_NonStringRoleDropsTenantOnly(t *testing.T) {
	key := generateTestKey(t, "RSA", "k1", 2048)
	for _, where := range []string{"root", "other", "tenant_roles"} {
		for _, invalid := range []any{float64(1), nil} {
			h := newJWKSHarness(t, key)
			v := h.verifier(t, nil)
			groups := map[string]any{"g": []any{"admin"}}
			bad := map[string]any{"root_group_id": "g", "groups": groups}
			if where == "root" {
				groups["g"] = []any{"admin", invalid}
			}
			if where == "other" {
				groups["x"] = []any{invalid}
			}
			if where == "tenant_roles" {
				bad["tenant_roles"] = []any{invalid}
			}
			payload := happyClaims()
			payload["passflow_tm"] = map[string]any{"bad": bad, "good": map[string]any{
				"root_group_id": "g", "groups": map[string]any{"g": []any{"viewer"}},
			}}
			claims, err := v.Verify(context.Background(), signToken(t, key, payload, nil))
			requireOutcome(t, claims, err, "ok", "")
			if _, exists := claims.Tenants["bad"]; exists {
				t.Errorf("invalid %s role retained a tenant", where)
			}
			equal(t, claims.Roles("good"), []string{"viewer"})
		}
	}
	runTokenRows(t, func(row tokenCase) bool {
		return strings.HasPrefix(row.ID, "passflow-tm-") && (strings.Contains(row.ID, "null-in-") || strings.Contains(row.ID, "number-in-"))
	})
}

func TestClaims_VerifiedByIsObjectIdentity(t *testing.T) {
	key := generateTestKey(t, "RSA", "k1", 2048)
	h := newJWKSHarness(t, key)
	v, w := h.verifier(t, nil), h.verifier(t, nil)
	c, err := v.Verify(context.Background(), signToken(t, key, happyClaims(), nil))
	requireOutcome(t, c, err, "ok", "")
	copied := *c
	equal(t, c.SessionID, "session-1")
	equal(t, c.Issuer, "https://auth.example.com")
	equal(t, c.Type, "access")
	equal(t, c.Audience, []string{"app-1"})
	equal(t, c.AMR, []string{"pwd", "otp"})
	equal(t, c.AuthTime.Unix(), int64(1699999940))
	equal(t, c.IssuedAt.Unix(), int64(1699999940))
	equal(t, c.ExpiresAt.Unix(), int64(1700100000))
	equal(t, c.Raw["sid"], "session-1")
	equal(t, c.VerifiedBy(v), true)
	equal(t, c.VerifiedBy(w), false)
	equal(t, copied.VerifiedBy(v), false)
	equal(t, copied.VerifiedBy(w), false)
	equal(t, (&auth.Claims{}).VerifiedBy(v), false)
	equal(t, c.VerifiedBy(nil), false)
	var nilClaims *auth.Claims
	equal(t, nilClaims.VerifiedBy(v), false)
	ctx := auth.ContextWithClaims(context.Background(), c)
	got, ok := auth.ClaimsFromContext(ctx)
	equal(t, ok, true)
	if got != c {
		t.Error("context did not preserve public claims identity")
	}
	equal(t, got.VerifiedBy(v), true)
}
