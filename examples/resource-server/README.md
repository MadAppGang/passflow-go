# Resource server examples

Protect your own API with Passflow tokens, in Go and in Node, and watch the React SDK answer a
step-up challenge from it. The examples install the published packages and run Passflow from its
Docker image, so they work from a plain clone of this repository.

| Directory | What it is | Port |
|---|---|---|
| [`go-chi/`](go-chi) | Chi API on [`github.com/madappgang/passflow-go/auth`](../../auth) | 8081 |
| [`node-express/`](node-express) | Express API on [`@passflow/node`](https://www.npmjs.com/package/@passflow/node) | 8082 |
| [`react-client/`](react-client) | Vite page on `@passflow/react`, on another origin | 5173 |
| [`devtool/`](devtool) | Creates the testdata and issues real tokens through Passflow's public API | |
| [`docker-compose.yml`](docker-compose.yml) | Passflow from `passflow/passflow` | 8765 |
| [`passflow.yaml`](passflow.yaml) | Its config: issuer `http://localhost:8765`, 30-minute access tokens | |
| [`scripts/api-check.sh`](scripts/api-check.sh) | Black-box check of an API with those real tokens | |

Both APIs expose the same routes:

| Route | Protection |
|---|---|
| `GET /public` | none |
| `GET /me` | authenticated; returns `sub`, `acr`, `amr`, `auth_time` and roles |
| `GET /invoices` | `acr` at least AAL2 |
| `POST /transfers` | `auth_time` within `FRESH_MAX_AGE` seconds |

## Run it

You need Docker, Go 1.24 or newer, Node 22.12 or newer and pnpm. Run each server in its own
terminal, from `examples/resource-server`. For a Passflow server of your own, pass `--server` and
`--key` to `devtool seed` and `devtool tokens`, and use its issuer below.

```sh
# 1. Passflow. It keeps everything in memory, so step 2 starts again after a restart.
docker compose up

# 2. Testdata: two apps and a user with TOTP. Note app A's ID, the password and the TOTP secret.
(cd devtool && go run . seed)

# 3. The APIs.
(cd go-chi && PASSFLOW_ISSUER=http://localhost:8765 PASSFLOW_AUDIENCE=<app A> go run .)

(cd node-express && pnpm install && PASSFLOW_ISSUER=http://localhost:8765 PASSFLOW_AUDIENCE=<app A> pnpm start)

# 4. The browser client. Set VITE_PASSFLOW_APP_ID to app A, and VITE_API_URL to the API under test.
cd react-client
cp .env.example .env.local
pnpm install && pnpm dev
```

Open <http://localhost:5173>, sign in with the seeded password, and press `GET /invoices`. The API
answers 401 with a step-up challenge, the SDK opens its dialog, and a code from
`go run . totp <secret>` in `devtool` replays the request to a 200.

Restart an API with `EXPOSE_CHALLENGE_HEADER=false` to see the silent failure this package exists
to prevent: the browser cannot read the challenge, so the SDK logs the `no-channel` diagnostic and
keeps you signed in.

## Check an API from the command line

```sh
(cd devtool && go run . tokens)        # aal1.jwt, aal2.jwt, wrong-aud.jwt, tokens.json
scripts/api-check.sh                   # both APIs; --lang go|node for one
scripts/api-check.sh --only A3-expired
scripts/api-check.sh --result
```

Run `api-check.sh` within 5 minutes of `devtool tokens`, because `POST /transfers` expects a fresh
token. It needs `curl` and `jq`, and the API under test running with its default settings.

| Check | Request | Expected |
|---|---|---|
| A1 | `GET /public`, no token | 200 |
| A2 | `GET /invoices`, no token | 401 `Bearer` |
| A3-tampered | `GET /invoices`, signature byte flipped | 401 `Bearer error="invalid_token"` |
| A3-expired | `GET /invoices`, `aal1.jwt` after `exp` + 35 s | 401 `Bearer error="invalid_token"` |
| A4 | `GET /invoices`, AAL1 token | 401 `Bearer error="insufficient_user_authentication", acr_values="2"` |
| A5 | `GET /invoices`, AAL2 token | 200 |
| A6 | `POST /transfers`, `FRESH_MAX_AGE=10`, 12 s after `auth_time` | 401 `Bearer error="insufficient_user_authentication", max_age=10` |
| A7 | `POST /transfers`, fresh token | 200 |
| A8 | preflight and `GET /invoices` from the client's origin | origin echoed, `Access-Control-Expose-Headers` names `WWW-Authenticate` |
| A9 | the same with `EXPOSE_CHALLENGE_HEADER=false` | origin echoed, `WWW-Authenticate` not exposed |
| A10-aud | `GET /invoices`, token from app B | 401 `Bearer error="invalid_token"` |
| A10-iss | `GET /invoices` against an API configured with another issuer | 401 `Bearer error="invalid_token"` |

Every rejection must also carry `Cache-Control: no-store` and an empty body.

The script starts its own short-lived API instances for A10-iss (port 8091), A6 (8092) and A9
(8093), and stops them afterwards. Set `API_CMD_GO` or `API_CMD_NODE` to change how they start.

Nothing shortens a token's life, so A3-expired is a separate step that sleeps until `exp` + 35 s of
`aal1.jwt`: up to 30 minutes, once for both APIs.

`--out DIR` (default `./validation`) receives:

- `api-<lang>.log`: every request and response. `Authorization`, cookies, `X-Passflow-*`, `*-Token`
  and the like are replaced with `<redacted sha256:<first 8 hex>>`, so two requests with the same
  token stay correlatable. The run stops and empties the file if a token ever reaches it verbatim.
- `api-<lang>.tsv`: one row per check, replaced on a re-run.
- `result.md`: written by `--result`, which exits 0 only on a full PASS. It adds any
  `browser-<lang>.tsv`, `suites.tsv` and `skipped.tsv` you recorded in the same directory (the
  format is at the top of the script). A row with no result counts against the verdict and is
  listed as skipped.

These examples are for a local machine. `passflow.yaml` holds placeholder keys and no real secret,
and is not a starting point for a deployment.
