import { AAL2, createVerifier, rolesOf } from '@passflow/node';
import { exposeChallengeHeader, getAuth, passflowExpress } from '@passflow/node/express';
import cors from 'cors';
import express from 'express';

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

const allowedOrigin = process.env.ALLOWED_ORIGIN || 'http://localhost:5173';
// Off is the negative case the browser run needs: the SDK must warn and recover, not sign out.
const exposeChallenge = process.env.EXPOSE_CHALLENGE_HEADER !== 'false';
const freshMaxAge = Number(process.env.FRESH_MAX_AGE || 300);
const port = Number(process.env.PORT || 8082);

const verifier = createVerifier({
  issuer: requiredEnv('PASSFLOW_ISSUER'),
  audience: requiredEnv('PASSFLOW_AUDIENCE'),
  jwksUrl: process.env.PASSFLOW_JWKS_URL || undefined,
});
const passflow = passflowExpress(verifier);

const corsOptions = { origin: allowedOrigin, credentials: true };

const app = express();
app.use(cors(exposeChallenge ? exposeChallengeHeader(corsOptions) : corsOptions));

app.get('/public', (_req, res) => {
  res.json({ public: true });
});

app.get('/me', passflow.authenticate, (req, res) => {
  const claims = getAuth(req);
  const roles = Object.fromEntries(Object.keys(claims.tenants).map((tenantId) => [tenantId, rolesOf(claims, tenantId)]));
  res.json({
    sub: claims.sub,
    acr: claims.acr,
    amr: claims.amr,
    auth_time: claims.authTime ?? null,
    roles,
  });
});

app.get('/invoices', passflow.requireACR(AAL2), (req, res) => {
  res.json({ invoices: [], acr: getAuth(req).acr });
});

app.post('/transfers', passflow.requireFresh(freshMaxAge), (req, res) => {
  res.json({ transferred: true, auth_time: getAuth(req).authTime ?? null });
});

app.listen(port, () => {
  console.log(`node-express example on :${port}, CORS origin ${allowedOrigin}, expose challenge ${exposeChallenge}`);
});
