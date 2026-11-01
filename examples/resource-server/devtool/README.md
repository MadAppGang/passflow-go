# devtool

Creates the testdata the resource-server examples need on a local Passflow, and issues real tokens
through its public HTTP API. Nothing here signs a token by hand. It is for a local server only.

Run it from this directory, with a local Passflow server running:

```sh
go run . seed
go run . tokens
go run . totp <secret>
```

| Command | What it does |
|---|---|
| `seed` | Creates app A (origin `http://localhost:5173`) and app B, both `Offline` with the 2FA policy `disabled`. Registers one password user on app A and enrols TOTP through `/user/2fa/setup/*`. Prints the app IDs, the user and the TOTP secret, and writes them to `seed.json`. Each run makes new apps and a new user. |
| `tokens` | Signs in on app A (`aal1.jwt`, `aal1.refresh`), upgrades that session with TOTP on `/auth/refresh` (`aal2.jwt`), and signs in on app B (`wrong-aud.jwt`). Writes the `tokens.json` manifest and prints `T0`, the `auth_time` of `aal2.jwt`. |
| `totp <secret>` | Prints the current code for a TOTP secret. |

Every sign-in sends the scopes `offline` and `id`. Passflow issues a refresh token and a `sid` only
when `offline` is requested and the app is `Offline`, and an upgrade needs both.

`tokens.json` is an array with one entry per token: `{file, app, acr, auth_time, exp}`.

## Flags

| Flag | Default | Commands | Meaning |
|---|---|---|---|
| `--server` | `http://localhost:8765` | `seed`, `tokens` | The Passflow base URL |
| `--key` | `test-management-key` | `seed` | The management key from `passflow.yaml` |
| `--out` | `.out` | `seed`, `tokens` | Where the files go. Git ignores the default, because they hold credentials. |

`scripts/api-check.sh` reads the tokens from that directory:

```sh
../scripts/api-check.sh --tokens .out
```
