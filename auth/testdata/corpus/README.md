# Resource-server contract corpus

One language-neutral testdata set binds every party to the same wire format and the same
decisions: the Go module, `@passflow/node`, the Passflow server's challenge helper, and the
js-sdk challenge parser. This directory is the single copy. The Go tests read it directly, the
Node package and the server reach it through symlinks, and the js-sdk vendors a pinned copy with
a drift check.

The server is the source of truth for the wire format. If a row disagrees with what the server
emits, the row is wrong.

| File | Version | Pins | Arrays |
|---|---|---|---|
| `challenges.json` | 1 | exact `WWW-Authenticate` bytes | `cases`, `authentication_failures` |
| `acr-levels.json` | 1 | the ACR ordinal table, per consumer | `cases`, `comparisons` |
| `freshness.json` | 2 | the `auth_time` decision and what freshness constructors accept | `cases`, `max_age_input` |
| `token-validation.json` | 2 | verifier outcomes, bearer extraction, verifier-bound claim reuse | `cases`, `authorization_header`, `composition` |
| `config.json` | 2 | verifier constructor rejections and acceptances | `cases` |
| `key-acceptance.json` | 1 | what a reload does with a public key that is wrong, or a body that is not valid text | `cases`, `body` |

## Versioning

Every file carries `corpus_version`, and every consumer asserts the version it was written
against. The number belongs to the file, so a bump in one file does not touch a consumer of
another. Bump it when a row's expected result changes, when a field is renamed or removed, or
when a field's meaning changes. Adding a row that the stated rules already decide does not bump
it. A row that needs a new rule does, because a consumer written against the old version would
fail it.

## Conventions

- **No key material.** Nothing here is a key. `key` names which generated key signs, and each
  harness generates its RSA-2048 and P-256 pairs at test start.
- **`node_only: true`.** Go skips the row, because a `time.Duration` or a zero-valued struct
  field cannot express the input.
- **JavaScript expressions.** In a `node_only` row, a *string* where a number belongs is a
  JavaScript expression, never a literal string input. The harness maps it through this table,
  and no other string appears:

  | Corpus string | JavaScript value |
  |---|---|
  | `NaN`, `Infinity`, `-Infinity` | the number |
  | `undefined`, `null` | the value |
  | `"300"`, `"5000"` (with the inner quotes) | the string `'300'`, `'5000'` |
  | `{}` | an empty object |

- **Reading `js_sdk.level`.** It is a JSON number holding what `Number.parseInt` returns, so
  above 2^53 it is a rounded double. Only JavaScript consumers read it. A Go harness must not
  decode that column into an integer type.
- **Empty roles.** `"roles": []` means no roles: Go's `Roles` returns `nil` and Node's `rolesOf`
  returns an empty result. Compare by length.

## Outcome to HTTP

| Outcome | Status | `WWW-Authenticate` | `Cache-Control` |
|---|---|---|---|
| `ok` | next handler | | |
| `missing_token` | 401 | `Bearer` | `no-store` |
| `invalid_token` | 401 | `Bearer error="invalid_token"` | `no-store` |
| `jwks_unavailable` | 503 | none | `no-store` |
| insufficient authentication | 401 | a row of `challenges.json` | `no-store` |

Authentication failures never carry the step-up error. The browser SDK acts only on the step-up
challenge: a plain 401 and a 503 reach the caller's code unchanged. The three stay distinct
because no dialog can fix an expired token, and an outage is not a bad token.

## `challenges.json`

Parameter order is fixed: `error`, `acr_values`, `max_age`, separated by a comma and a space.

`cases` rows have `id`, `acr_values` (string or `null`), `max_age` (integer or `null`), `header`
(the exact bytes), `status`, `cache_control` and `js_sdk`.

The rows bind the **formatters**: Go `auth.Challenge.String()`, Node `formatChallenge`, and the
server's `SetInsufficientAuthChallenge`. A formatter omits a non-positive `max_age`, so the `0`
and `-5` rows have the same bytes as `null`. The freshness **constructors** reject those values
and are bound by `freshness.json#max_age_input` instead. So the formatter omits and the
constructor throws, and no entry point is asked to do both.

The `js_sdk` column binds the parser. Use vitest `toEqual`, never `toStrictEqual`, because the
parser sets absent fields as own `undefined` properties.

- `parseChallengeHeader(header, status)` equals
  `{ acrValues: js_sdk.acr_values ?? undefined, maxAge: js_sdk.max_age ?? undefined, status }`.
- `readUpgradeChallenge({ status, getHeader }, undefined)`, where `getHeader` returns `header`
  for `www-authenticate`, with default options and no `body` key:
  - `.challenge` equals that shape plus `requiredLevel: js_sdk.required_level ?? undefined` and
    `channels: ['header']`.
  - `.diagnostics` equals `[]`.
- `js_sdk: null` (the `authentication_failures` rows) means `parseChallengeHeader` returns
  `undefined` and `readUpgradeChallenge` returns `{ diagnostics: [] }`.

## `acr-levels.json`

`server_level` is a decimal string in every row, so JSON never has to carry a value a JavaScript
`Number` cannot hold. Go consumers `ParseInt` the column and Node consumers `BigInt()` it.

The rule, defined by parsed magnitude and not by digit count:

1. The whole string must match `^[+-]?[0-9]+$`: optional sign, one or more ASCII digits, leading
   zeros allowed, no whitespace, no underscores.
2. The value must fit a signed 64-bit integer.
3. A lexical failure, a value outside int64, or a negative value is level 0.

| Consumer | Implementation | Comparison type |
|---|---|---|
| Go `auth.ACR.Level()` | `strconv.ParseInt(s, 10, 64)`; an error or `n < 0` gives 0 | `int64` |
| Node `parseACRLevel()` | regex test, `BigInt(s)`, then `n < 0n` or `n > 9223372036854775807n` gives `0n` | `bigint` |
| Server `model.ACR.Level()` (64-bit platforms) | `strconv.Atoi` | `int` |

Nothing on the decision path is converted to a JavaScript `Number`.

Rows bind by the JSON type of `acr`:

- **String `acr`** binds the ordinal primitives: `auth.ACR(s).Level()`, `model.ACR(s).Level()`,
  `parseACRLevel(s)`.
- **Non-string `acr`** (`2`, `null`, `["2"]`) binds claim extraction, the only place a non-string
  can enter a string-typed API. No harness normalizes these into a string.
  - Go signs a token whose `acr` claim is the row's JSON value and asserts `Verify` returns
    `Claims.ACR == auth.ACRNone`.
  - The server builds a token whose payload `acr` is the row's value and asserts
    `RequireAuthLevel(model.AAL1)` answers 401 with `acr_values="1"`.
  - Node passes the raw value to `parseACRLevel` (giving `0n`), and signs the same token and
    asserts `claims.acr === '0'`.
  - `js_sdk` is `null` and the js-sdk test skips these rows by type.

`js_sdk` is `{level, unorderable, zero}` and binds `readAcrValues`, with `level: null` standing
for `undefined`. Its reading legitimately differs from the server's. `acr_values` is a list whose
bar is its minimum, so `"2 3"` is 2 there and 0 on the server. Only whole-digit tokens
participate, so `"+2"` is unorderable there and 2 on the server. Above 2^53 its `parseInt` is
lossy, and that loss is pinned rather than hidden.

`comparisons` rows, `{token_acr, required, allow}`, pin the exported decision primitive
`ACR.Satisfies` / `acrSatisfies`: `min.Level() != 0 && token.Level() >= min.Level()`, compared
exactly. A required side that parses to level 0 is never satisfied. `token_acr: null` is an absent
claim: the Go harness passes `auth.ACRNone`, the Node harness passes `undefined`. The server does
not bind this array, because its level-0 rule belongs to the libraries' exported primitive.

## `freshness.json`

`cases` rows have `id`, `now`, `auth_time`, `max_age`, `allow` and `header_if_rejected`. Reject
when `now - auth_time > max_age`, so an age equal to `max_age` is allowed. There is no leeway on
`auth_time`. An absent or non-numeric `auth_time` is rejected, and a fractional one is truncated
toward zero. An `auth_time` beyond 2^53 in magnitude is no longer an exact count of seconds, so it
reads as absent and is rejected; exactly 2^53 is still a date. A row with no `auth_time` key has the
claim absent.

The comparison is in whole seconds. `now` can be fractional, and the verification time is rounded
down to a whole second before the comparison, so an age of 300.5 against a limit of 300 is allowed
and 301 is not. The exposed `VerifiedAt` keeps its full precision in Go.

A harness signs a happy `rsa` token, as in the `happy-rs256` row of `token-validation.json`, with
`auth_time` replaced by the row's value (or removed) and an `exp` after `now`. It sets the
verifier's clock to `now` at millisecond precision or better (Go
`time.UnixMilli(int64(now * 1000))`, Node `new Date(now * 1000)`), and checks the response of a
route with a freshness limit of `max_age`.

These rows bind the two libraries. The server has its own check, `RequireFreshAuth` in
`src/web/middleware/auth_level.go`, which compares `time.Since(at) > maxAge` at full precision.
Its drift test reads `acr-levels.json` and `challenges.json` and does not read this file, so no
row needs a libraries-only field.

`max_age_input` rows pin the **constructors**: `RequireFresh`, `requireFresh` in all three
adapters, and `evaluate` with `kind: 'fresh'`. The rule is the same in both languages: truncate
toward zero to whole seconds, then require at least 1. `effective` is what is enforced and what
the challenge carries, so the two can never differ. `error: true` means the constructor panics
(Go) or throws `TypeError` (Node).

Node also requires a safe integer, so a challenge can never carry an exponential: `String(1e21)`
is `1e+21`, which the js-sdk's `Number.parseInt` reads as `1`. Go needs no upper bound, because
`time.Duration` tops out below 2^53.

## `token-validation.json`

### `cases`

Each row has `id`, `key`, `header`, `claims`, `now`, `verifier` and `expect`.

| `key` | Signs with |
|---|---|
| `rsa` | the generated RSA key, published in the JWKS |
| `ec` | the generated P-256 key, published in the JWKS |
| `other-rsa` | a second generated RSA key, not published |
| `hmac` | HS256, keyed with the encoded generated RSA public key |
| `none` | nothing: `alg: none` and an empty signature |

| `header.kid` | Means |
|---|---|
| `generated` | the `kid` of the row's own `key` |
| `generated-rsa`, `generated-ec` | the `kid` of that generated JWK, whichever key signs |
| `unknown` | a `kid` that is not in the set |
| `absent` | no `kid` header |

Further fields:

- `raw_token`, when present, replaces `key`, `header` and `claims`: send it as is. Pass it to
  `Verify` / `verify` directly, because an HTTP stack refuses a header value holding a line feed.
- `jwks: "unreachable"` means every JWKS fetch fails. It is reachable otherwise.
- `verifier` carries `issuer`, `audiences`, `leeway` (seconds) and `token_types`.
- `expect` carries `outcome`, and `reason` for `invalid_token`.
- `expect.fetches` is `{gate_open, gate_closed}`, counted after one successful warm-up fetch.
  `gate_closed` verifies at `now`, and `gate_open` verifies at `now` + 30 s, the default minimum
  refresh interval.
- `expect.tenants` maps a tenant ID to its expected `roles`.
- `expect.tenants_absent` lists tenant IDs that must not be in the claims.

Reasons: `expired`, `not_yet_valid`, `exp_missing`, `issuer`, `audience`, `type`, `signature`,
`alg`, `kid_missing`, `key_unknown`, `crit`, `malformed`.

The header is inspected in this order, before any key lookup, identically in both languages:

1. Split on `.`: exactly three parts, part 1 matches `^[A-Za-z0-9_-]+$` and decodes as unpadded
   base64url, the decoded bytes are valid UTF-8 with no leading BOM, and they JSON-decode to an
   object. Otherwise `malformed`, so a `=` or a line feed in part 1, a BOM or invalid UTF-8 never
   reaches key lookup.
2. `alg` is `RS256` or `ES256`. Otherwise `alg`.
3. `crit` is absent. Otherwise `crit`.
4. `kid` is a non-empty string. Otherwise `kid_missing`.
5. Key lookup by `(kid, key type required by alg)`, then the signature, then the claims.

A `kid` present with the wrong key type is not in the set, so it takes the refetch gate and ends
in `key_unknown`.

The `raw_token` rows carry their bytes already, because a token segment is base64url, so a harness
builds nothing for them. Part 1 of `malformed-header-bom` decodes to the bytes `EF BB BF` followed by
`{"alg":"RS256","kid":"k1"}`, and part 1 of `malformed-header-invalid-utf-8` decodes to
`{"alg":"RS256","kid":"k1<FF>"}`. A library that reads either one goes on to look up an unknown `kid`,
so the row's `expect.fetches` of 0 catches it even where the reason is not compared.

Roles come from `groups[root_group_id]` only. `tenant_roles` is decoded but not consulted, and a
membership with no matching root group has no roles. An empty `root_group_id` has no roles either, even
with a group keyed by the empty string. The server's `CalcTenantRoles` reads that shape differently,
and it never writes an empty root group, so this rule binds the two libraries only.

A membership is read by exact key, so `ROOT_GROUP_ID` is not `root_group_id`. A member that is absent
or `null` is unset, and a `null` entry in `groups` or `group_names` is left out. Any other wrong type
makes the membership undecodable, including a non-string in `tenant_roles` or in any array in `groups`,
root group or not, and `null` counts as a non-string there. An undecodable membership drops that tenant
only: the token stays valid, and `expect.tenants_absent` lists the tenant IDs that must not be in the
claims at all (Go `Claims.Tenants`, Node `claims.tenants`), which a role check alone cannot tell from
a tenant with no roles.

`iat` is never compared with the clock, so an absent one and a far-future one are accepted. A
present `iat` that is not a JSON number (a string, `null`, an array) is `malformed`.

`aud` is a string or an array of strings. An array with a non-string member is `audience`, even
when another member matches a configured audience.

### `authorization_header`

Rows pin bearer extraction. `value` is the header value, `null` means no header, and `<t>` stands
for a token the verifier accepts. A whitespace-only `Bearer` is `missing_token`.

### `composition`

Rows pin verifier-bound claim reuse: a verifier's middleware reuses context claims only when it
produced that exact claims object. Otherwise it verifies the presented token itself. The harness
is an upstream `Authenticate` followed by the route verifier's `Require(AAL2)` / `requireACR('2')`.
The token is an otherwise happy `rsa` token at `acr` 2, with the row's `token` values replacing
`iss` and `aud`. Both verifiers use leeway 30 and token types `["access"]`.

| `arrangement` | Harness |
|---|---|
| `two_instances` | `upstream` and `route` are separate verifier instances, even when configured identically |
| `same_instance` | one verifier used both upstream and on the route |
| `foreign_claims_no_header` | claims from the upstream verifier's `Verify` in context, and no `Authorization` header on the request |
| `copied_claims` | one verifier; a copy of its claims in context (Go `copied := *claims`, Node `{ ...claims }`) |

`expect.verifications` counts `Verify` calls summed over every verifier in the row, including the
one that produced the upstream claims.

- Go counts through the unexported `verifyHook` seam.
- Node counts with a spy on the `verify` method of the object `createVerifier` returned.
- A wrapping object is a different identity, so it is re-verified.

`expect.claims_from` is what the handler sees: `route` is the claims from the route verifier's own
`Verify` on this request, and `upstream` is the upstream claims object, reused.

## `config.json`

Each row has `id`, `config`, `error` (the rejected option, or `null` when the config must be
accepted) and optionally `node_only`. `zero_semantics` and `units` in the file state the
per-language zero rule and the units once.

Option keys map to Go's `Config` and `JWKSOptions` fields and to Node's camelCase options. `audiences`
is Node's `audience`.

A key absent from `config` is unset, and an empty array stays an empty array, so a harness must
not collapse `[]` into unset.

Loopback hosts for the plain-HTTP exception, identical in both languages: take the hostname **as
written in the URL**, with the port removed and IPv6 brackets stripped, lower-case it, then it must
equal `localhost`, end with `.localhost`, be a dotted-decimal IPv4 address inside `127.0.0.0/8`, or
parse as the IPv6 address `::1`. A hostname that merely contains "localhost" is not loopback. The
hostname is read before any normalization: a WHATWG URL parser turns `127.1`, `2130706433`, `0x7f.1`
and `127.00.0.1` into `127.0.0.1`, and those spellings are not loopback here. Four decimal octets
with no leading zero is the only IPv4 form.

## `key-acceptance.json`

Each `cases` row has `id`, `kty`, `mutate` and `expect`. A row describes one public key that is
wrong in one way. There is no key in the file: the harness generates the key and then damages it.

**Build the key set, once per row.**

1. Generate a new RSA-2048 key, the *anchor*, with `kid` `anchor`. Its JWK has `kty`, `kid`, `n`
   and `e`.
2. Generate a new key of the row's `kty`, the *subject*, with `kid` `subject`. RSA is RSA-2048, and
   its JWK has `kty`, `kid`, `n` and `e`. EC is P-256, and its JWK has `kty`, `kid`, `crv`, `x` and
   `y`. Neither JWK has `use`, `alg` or `key_ops`, and neither has a private member.
3. Apply `mutate` to the subject's JWK only.
4. Serve `{"keys": [anchor, subject]}`, in that order, with status 200, and count the fetches.

**Apply `mutate`.** `member` names the JWK member, and `op` says what to do to it:

| `op` | Result |
|---|---|
| `set` | The member becomes `value`, whatever its JSON type. `key_ops` is absent before this and present after it. |
| `append` | The member becomes its encoded string followed by `value`. An RSA-2048 `n` is 342 characters, so `AAA` makes it 345, a length with `length % 4 == 1`. |
| `set_unused_bit` | Replace the last character with the next one in the base64url alphabet (`A` becomes `B`, `Q` becomes `R`, `g` becomes `h`, `w` becomes `x`). The lowest bit of that character is outside the encoded bytes in an RSA-2048 `n` and a P-256 `x` or `y`, so a lenient decoder returns the same bytes. |
| `drop_first_byte` | Decode the member, remove its first byte, encode it again. |
| `prepend_zero_byte` | Decode the member, put a zero byte first, encode it again. The number it holds does not change. |

The `set` values for `e` are public exponents, big-endian: `AQ` is 1, `Ag` is 2, `AA` is 0, `gAAAAQ`
is 2^31 + 1, `AQAAAAAAAAAB` is 2^64 + 1, and `Ax` is a non-canonical spelling of 3 (canonical `Aw`).
The last three are odd, so those rows fail only on range or encoding.

**Run it.** Use a fresh verifier for each row, with the verifier settings and `now` of the
`happy-rs256` row in `token-validation.json`, default JWKS options, and a clock that does not move.
The *anchor token* is that row's claims signed RS256 by the anchor, with `kid` `anchor`. The
*subject token* is the same claims signed by the subject, RS256 or ES256 by `kty`, with `kid`
`subject`.

| `expect.outcome` | Meaning | Assert, in order |
|---|---|---|
| `reload_fails` | One key fails its material check, so the whole reload fails at `expect.stage`, and the good key beside it does not save it | 1. The anchor token gives `jwks_unavailable`, and the failure is at stage `key`: in Go the error text ends in `: key`, and in Node `error.cause.stage` is `'key'`. The fetch count is 1. 2. The anchor token again gives `jwks_unavailable`. The fetch count is still 1. |
| `key_skipped` | Metadata says no token could select this key, so it is left out and the reload succeeds | 1. The anchor token gives `ok`. The fetch count is 1. 2. The subject token gives `invalid_token` / `key_unknown`. The fetch count is still 1. |

**Control.** Before the rows, run one set per `kty` with `mutate` not applied: the anchor token and
the subject token both give `ok`, with a fetch count of 1. Without this a harness that fails every
reload would pass every `reload_fails` row.

A `key_ops` member that is JSON `null` is not pinned. Go decodes `key_ops` into `[]string`, which
reads `null` as an empty string, and Node matches that, so `["verify", null]` is usable in both.

### `body`

A `body` row pins the bytes of the response, before any key is read: a key set body is valid UTF-8
with no leading BOM, or the reload fails at stage `parse`. JSON cannot hold these bytes, so `bytes`
names them in hex and the harness builds the body:

1. Generate the anchor and an unmutated subject, as above, with subject `kty` `RSA`.
2. Add the member `"note": "@@"` to the anchor's JWK, and serialize `{"keys": [anchor, subject]}` to
   UTF-8 bytes.
3. `note_hex`: replace the two bytes of `@@` with the decoded hex, and do nothing else. The note is a
   member no rule reads, so only the bytes can decide the row.
4. `prefix_hex`: put the decoded hex in front of the body, and leave `@@` as it is.
5. Serve the bytes as they are, with status 200. Do not pass them through a string type on the way,
   because that can repair them.

| `expect.outcome` | Assert, in order |
|---|---|
| `reload_fails` | As for `cases`, with the failure at stage `parse`. |
| `reload_succeeds` | The anchor token gives `ok`, with a fetch count of 1. This row shows the byte splice itself works. |

## Rotation window

The verifier refetches the key set for an unknown `kid` at most once per minimum refresh interval.
A token signed by a key published less than that interval after the previous fetch attempt is
rejected as `key_unknown` (401) until the gate opens: at most 30 s per instance with the defaults.
Passflow uses one signing key today. Deployments that rotate should call `Refresh` from their
rotation hook, once the new key is published. `Refresh` ignores the gate and returns the result of
a fetch that starts after the call, waiting out and ignoring any fetch already in flight, so
success means the new key is in the set. No row pins this: it needs a fetch held open across the
call, so each language has its own named test.
