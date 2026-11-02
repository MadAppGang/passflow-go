# Resource server React client

A Vite page that calls an example API through `@passflow/react` 0.15.1: sign in with a password,
press a route button, and answer the upgrade dialog when the API asks for more assurance.
It is a developer demo, not a shipped UI.

## Run

```bash
cp .env.example .env.local   # set VITE_PASSFLOW_APP_ID to app A's ID from `devtool seed`
pnpm install
pnpm dev                     # http://localhost:5173, the only origin the seeded app allows
```

`VITE_API_URL` selects the API under test. Change it and restart Vite to switch between `go-chi`
and `node-express`.

## What the SDK does and what the page does

- `backend={VITE_API_URL}` declares the API as interception scope. Without it the SDK reports
  `challenge-out-of-scope` and never opens the dialog.
- `withAuth` handles a challenge and replays the request, but it does not attach a credential. The
  page sets `Authorization: Bearer <access token>` on the first send, in `src/api.ts`.
- The default dialog is rendered by `PassflowProvider`. The page adds no prompt of its own.

## Controls

| Control | Accessible name | `data-testid` |
|---|---|---|
| Email, password inputs | `Email`, `Password` | |
| Sign in, sign out | `Sign in`, `Sign out` | |
| Route buttons | `GET /public`, `GET /me`, `GET /invoices`, `POST /transfers` | |
| Session state | | `session-status` (`Signed in` / `Signed out`) |
| Upgrade state | | `upgrade-status`, `upgrade-enabled` |
| Final status | | `status-{public,me,invoices,transfers}` |
| Statuses on the wire, e.g. `401 -> 200` | | `wire-{route}` |
| Challenge header visibility | | `challenge-{route}` |
| Request time | | `requested-at-{route}` |
| `/me` `auth_time`, as epoch seconds and UTC | | `me-auth-time` |
| Console pane | `Console output` (role `log`) | `console-pane` |
| Clear the pane | `Clear console` | |

The SDK's dialog is titled `Extra verification required`. Its controls are `Verification code`
(`upgrade-dialog-code`), `Verify` (`upgrade-dialog-submit`), `Use another way`
(`upgrade-dialog-alternatives`) and `Cancel` (`upgrade-dialog-cancel`).

## Console pane

The pane lists each response as the page could read it, session event names, upgrade state changes
and SDK diagnostics. A diagnostic also goes to the browser console, as the SDK's default sink would
print it. Token values are never written to the pane or the page, and response text passes through a
JWT-shaped filter first.
