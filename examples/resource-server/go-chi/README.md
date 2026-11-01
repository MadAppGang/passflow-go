# Go + Chi resource server

An API protected by [`github.com/madappgang/passflow-go/auth`](../../../auth), the published
module. It answers the React client and `scripts/api-check.sh` next door. See
[`../README.md`](../README.md) for the whole walkthrough.

## Run

From this directory, with your issuer and the app ID that `devtool seed` printed:

```sh
PASSFLOW_ISSUER=http://localhost:8765 PASSFLOW_AUDIENCE=<app-id> go run .
```

## Routes

| Route | Protection | Form |
|---|---|---|
| `GET /public` | none | |
| `GET /me` | authenticated; returns `sub`, `acr`, `amr`, `auth_time` and `roles` by tenant | `r.Use(verifier.Authenticate)` |
| `GET /invoices` | `acr` at least AAL2 | `r.With(auth.Require(auth.AAL2))` under that `Use` |
| `POST /transfers` | `auth_time` within `FRESH_MAX_AGE` seconds | `r.With(verifier.RequireFresh(maxAge))`, on its own |

## Environment

These are settings of this example. The library reads no environment variables.

| Variable | Default | Meaning |
|---|---|---|
| `PASSFLOW_ISSUER` | required | The issuer tokens must name |
| `PASSFLOW_AUDIENCE` | required | The application ID tokens must be issued for |
| `PASSFLOW_JWKS_URL` | `{issuer}/.well-known/jwks.json` | Where to fetch the signing keys |
| `ALLOWED_ORIGIN` | `http://localhost:5173` | The browser origin CORS allows |
| `EXPOSE_CHALLENGE_HEADER` | `true` | `false` hides `WWW-Authenticate` from the browser, the misconfiguration the SDK must survive |
| `FRESH_MAX_AGE` | `300` | The freshness limit on `POST /transfers`, in seconds |
| `PORT` | `8081` | The port to listen on |
