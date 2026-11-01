import {
  type FetchLike,
  type Passflow,
  isUpgradeCancelled,
  isUpgradeExhausted,
  isUpgradeInsufficient,
  isUpgradeSessionChanged,
  isUpgradeTransportFailure,
  isUpgradeUnavailable,
  isUpgradeUnsatisfiable,
  withAuth,
} from '@passflow/react';
import { log, redact } from './console-log';
import { apiUrl } from './env';

export type Route = {
  id: 'public' | 'me' | 'invoices' | 'transfers';
  method: 'GET' | 'POST';
  path: string;
  body?: string;
};

export const ROUTES: readonly Route[] = [
  { id: 'public', method: 'GET', path: '/public' },
  { id: 'me', method: 'GET', path: '/me' },
  { id: 'invoices', method: 'GET', path: '/invoices' },
  { id: 'transfers', method: 'POST', path: '/transfers', body: JSON.stringify({ amount: 100, currency: 'USD' }) },
];

/** One response as this page's JavaScript could read it, before the SDK acted on it. */
export type WireResponse = {
  status: number;
  /** `null` when the server sent none, or sent one that CORS hides from this page. */
  challenge: string | null;
};

export type RouteResult = {
  requestedAt: string;
  sentCredential: boolean;
  wire: readonly WireResponse[];
  status: number | null;
  outcome: string | null;
  body: string;
  authTime: number | null;
};

const OUTCOMES: ReadonlyArray<[string, (response: object) => boolean]> = [
  ['upgrade cancelled', isUpgradeCancelled],
  ['upgrade exhausted', isUpgradeExhausted],
  ['elevated but insufficient', isUpgradeInsufficient],
  ['upgrade unsatisfiable', isUpgradeUnsatisfiable],
  ['upgrade unavailable', isUpgradeUnavailable],
  ['session changed during upgrade', isUpgradeSessionChanged],
  ['upgrade transport failure', isUpgradeTransportFailure],
];

const describeChallenge = ({ status, challenge }: WireResponse): string => {
  if (challenge !== null) return `WWW-Authenticate readable: ${challenge}`;
  return status === 401 || status === 403 ? 'WWW-Authenticate not readable by this page' : 'no WWW-Authenticate';
};

/** The whole-second `auth_time` of a `/me` body, when it has one. */
const readAuthTime = (route: Route, text: string): number | null => {
  if (route.id !== 'me') return null;
  try {
    const authTime: unknown = JSON.parse(text)?.auth_time;
    return typeof authTime === 'number' ? authTime : null;
  } catch {
    return null;
  }
};

const prettyBody = (text: string): string => {
  try {
    return redact(JSON.stringify(JSON.parse(text), null, 2));
  } catch {
    return redact(text);
  }
};

/**
 * Sends one route through the SDK's fetch wrapper.
 *
 * `withAuth` handles the challenge and replays, and swaps a stale credential on
 * replay, but it never adds one: the first send's `Authorization` is ours to set
 * and must be exactly `Bearer <stored access token>`, because the swap matches on
 * that value. The token lives in this function's scope and nowhere else.
 *
 * The wrapper is built per call because the free function binds to the provider's
 * current `Passflow` instance. `wireFetch` is what `withAuth` sends through, so it
 * also sees the 401 the SDK consumes, which is the only place the page can observe
 * whether the challenge header was readable.
 */
export const callRoute = async (route: Route, passflow: Passflow): Promise<RouteResult> => {
  const url = `${apiUrl}${route.path}`;
  const label = `${route.method} ${url}`;
  const requestedAt = new Date().toISOString();
  const wire: WireResponse[] = [];

  const wireFetch: FetchLike = async (input, init) => {
    const response = await fetch(input, init);
    const seen = { status: response.status, challenge: response.headers.get('www-authenticate') };
    wire.push(seen);
    log(response.ok ? 'info' : 'warn', `${label} -> ${seen.status}; ${describeChallenge(seen)}`);
    return response;
  };

  const tokens = await passflow.getTokens(true);
  const accessToken = tokens?.access_token;
  log('info', `${label}: sending ${accessToken ? 'with a bearer credential' : 'with no credential'}`);

  const headers: Record<string, string> = {};
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  if (route.body) headers['Content-Type'] = 'application/json';

  const base = { requestedAt, sentCredential: Boolean(accessToken), wire };
  try {
    const response = await withAuth(wireFetch)(url, { method: route.method, headers, body: route.body });
    const text = await response.text();
    const outcome = OUTCOMES.find(([, matches]) => matches(response))?.[0] ?? null;
    if (outcome) log('warn', `${label}: ${outcome}`);
    return {
      ...base,
      status: response.status,
      outcome,
      body: prettyBody(text),
      authTime: readAuthTime(route, text),
    };
  } catch (error) {
    const message = redact(error instanceof Error ? error.message : String(error));
    log('error', `${label} failed: ${message}`);
    return { ...base, status: null, outcome: `request failed: ${message}`, body: '', authTime: null };
  }
};

/** What the page can say about the challenge header on this call's first refused response. */
export const challengeVisibility = (wire: readonly WireResponse[]): string => {
  const refused = wire.find(({ status }) => status === 401 || status === 403);
  if (!refused) return 'no challenge on this call';
  return refused.challenge === null ? 'not readable by this page' : `readable: ${refused.challenge}`;
};

export const formatAuthTime = (authTime: number): string => `${authTime} (${new Date(authTime * 1000).toISOString()})`;
