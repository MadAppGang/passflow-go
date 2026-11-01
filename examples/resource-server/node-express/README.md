# Node + Express resource server

An API protected by [`@passflow/node`](https://www.npmjs.com/package/@passflow/node). It answers the
React client and `scripts/api-check.sh` next door. See [`../README.md`](../README.md) for the whole
walkthrough.

## Run

From this directory, with your issuer and the app ID that `devtool seed` printed:

```sh
pnpm install
PASSFLOW_ISSUER=http://localhost:8765 PASSFLOW_AUDIENCE=<app-id> pnpm start
```

## Routes

| Route | Protection |
|---|---|
| `GET /public` | none |
| `GET /me` | authenticated; returns `sub`, `acr`, `amr`, `auth_time` and `roles` by tenant |
| `GET /invoices` | `acr` at least AAL2 |
| `POST /transfers` | `auth_time` within `FRESH_MAX_AGE` seconds |

## Environment

These are settings of this example. The library has no environment variables.

| Variable | Default | Meaning |
|---|---|---|
| `PASSFLOW_ISSUER` | required | the issuer tokens must carry |
| `PASSFLOW_AUDIENCE` | required | the Passflow application ID that may call this API |
| `PASSFLOW_JWKS_URL` | `{issuer}/.well-known/jwks.json` | where the key set is fetched |
| `ALLOWED_ORIGIN` | `http://localhost:5173` | the browser origin CORS allows |
| `EXPOSE_CHALLENGE_HEADER` | `true` | `false` is the negative case: the browser cannot read the challenge |
| `FRESH_MAX_AGE` | `300` | the `/transfers` limit, in seconds |
| `PORT` | `8082` | listen port |
