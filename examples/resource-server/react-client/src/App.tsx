import {
  PassflowEvent,
  PassflowProvider,
  type PassflowSubscriber,
  recoveryCodesFactor,
  totpFactor,
  useLogout,
  usePassflow,
  useSignIn,
  useUpgrade,
} from '@passflow/react';
import { type FC, type FormEvent, useEffect, useState, useSyncExternalStore } from 'react';
import { ROUTES, type Route, type RouteResult, callRoute, challengeVisibility, formatAuthTime } from './api';
import { clearLog, log, onUpgradeDiagnostic, readLog, subscribeLog } from './console-log';
import { apiUrl, missingEnv, passflowAppId, passflowUrl } from './env';

// `offline` and `id` are what the server needs to issue a refresh token and a
// `sid`. A TOTP upgrade on /auth/refresh fails without them.
const SCOPES = ['id', 'offline'];

// Listed so the dialog leads with TOTP: the SDK ranks a passkey first by default.
const UPGRADE = { factors: [totpFactor, recoveryCodesFactor], onUpgradeDiagnostic };

const SESSION_EVENTS = [
  PassflowEvent.SignIn,
  PassflowEvent.SignOut,
  PassflowEvent.SessionExpired,
  PassflowEvent.Refresh,
  PassflowEvent.TwoFactorRequired,
];

const useSignedIn = (): boolean => {
  const passflow = usePassflow();
  const [signedIn, setSignedIn] = useState(() => passflow.isAuthenticated());

  useEffect(() => {
    setSignedIn(passflow.isAuthenticated());
    // A SignIn or Refresh payload carries the tokens, so only the event's name is logged.
    const subscriber: PassflowSubscriber = {
      onAuthChange: (event) => {
        log('info', `session event: ${event}`);
        setSignedIn(passflow.isAuthenticated());
      },
    };
    passflow.subscribe(subscriber, SESSION_EVENTS);
    return () => passflow.unsubscribe(subscriber);
  }, [passflow]);

  return signedIn;
};

const SignInForm: FC = () => {
  const { fetch: signIn, isLoading, error } = useSignIn();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const succeeded = await signIn({ email, password }, 'password');
    if (succeeded) setPassword('');
    else log('error', 'password sign-in failed');
  };

  return (
    <form className='sign-in' aria-label='Sign in' onSubmit={submit}>
      <label>
        Email
        <input
          type='email'
          name='email'
          autoComplete='username'
          required
          value={email}
          onChange={(event) => setEmail(event.target.value)}
        />
      </label>
      <label>
        Password
        <input
          type='password'
          name='password'
          autoComplete='current-password'
          required
          value={password}
          onChange={(event) => setPassword(event.target.value)}
        />
      </label>
      <button type='submit' disabled={isLoading}>
        Sign in
      </button>
      {error ? (
        <p role='alert' data-testid='sign-in-error'>
          {error.message}
        </p>
      ) : null}
    </form>
  );
};

const SessionPanel: FC<{ signedIn: boolean }> = ({ signedIn }) => {
  const { fetch: signOut, isLoading } = useLogout();
  const { enabled, status } = useUpgrade();

  useEffect(() => {
    log('info', `upgrade state: ${status}`);
  }, [status]);

  return (
    <section aria-labelledby='session-heading'>
      <h2 id='session-heading'>Session</h2>
      <dl>
        <dt>Passflow</dt>
        <dd data-testid='passflow-url'>{passflowUrl}</dd>
        <dt>API</dt>
        <dd data-testid='api-url'>{apiUrl}</dd>
        <dt>Session status</dt>
        <dd role='status' data-testid='session-status'>
          {signedIn ? 'Signed in' : 'Signed out'}
        </dd>
        <dt>Upgrade handling</dt>
        <dd data-testid='upgrade-enabled'>{enabled ? 'installed' : 'not installed'}</dd>
        <dt>Upgrade state</dt>
        <dd role='status' data-testid='upgrade-status'>
          {status}
        </dd>
      </dl>
      {signedIn ? (
        <button type='button' disabled={isLoading} onClick={() => void signOut()}>
          Sign out
        </button>
      ) : (
        <SignInForm />
      )}
    </section>
  );
};

const RouteCard: FC<{ route: Route; signedIn: boolean }> = ({ route, signedIn }) => {
  const passflow = usePassflow();
  const [result, setResult] = useState<RouteResult | null>(null);
  const [busy, setBusy] = useState(false);
  const name = `${route.method} ${route.path}`;

  // A result from the previous session must not read as this session's: the
  // browser run compares `/me`'s auth_time across a sign-out.
  useEffect(() => setResult(null), [signedIn]);

  const send = async () => {
    setBusy(true);
    try {
      setResult(await callRoute(route, passflow));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className='route' aria-label={`${name} result`} data-testid={`route-${route.id}`}>
      <button type='button' disabled={busy} aria-busy={busy} onClick={() => void send()}>
        {name}
      </button>
      <dl>
        <dt>Status</dt>
        <dd role='status' data-testid={`status-${route.id}`}>
          {busy ? 'pending' : result ? (result.status ?? 'no response') : 'not sent'}
        </dd>
        {result ? (
          <>
            <dt>Requested at</dt>
            <dd data-testid={`requested-at-${route.id}`}>{result.requestedAt}</dd>
            <dt>Credential sent</dt>
            <dd data-testid={`credential-${route.id}`}>{result.sentCredential ? 'yes' : 'no'}</dd>
            <dt>Wire statuses</dt>
            <dd data-testid={`wire-${route.id}`}>{result.wire.map(({ status }) => status).join(' -> ') || 'none'}</dd>
            <dt>WWW-Authenticate</dt>
            <dd data-testid={`challenge-${route.id}`}>{challengeVisibility(result.wire)}</dd>
            {result.outcome ? (
              <>
                <dt>Outcome</dt>
                <dd data-testid={`outcome-${route.id}`}>{result.outcome}</dd>
              </>
            ) : null}
            {route.id === 'me' ? (
              <>
                <dt>auth_time</dt>
                <dd data-testid='me-auth-time'>
                  {result.authTime === null ? 'absent' : formatAuthTime(result.authTime)}
                </dd>
              </>
            ) : null}
          </>
        ) : null}
      </dl>
      {result?.body ? <pre data-testid={`body-${route.id}`}>{result.body}</pre> : null}
    </section>
  );
};

const ConsolePane: FC = () => {
  const entries = useSyncExternalStore(subscribeLog, readLog);

  return (
    <section aria-labelledby='console-heading'>
      <h2 id='console-heading'>Console</h2>
      <button type='button' onClick={clearLog}>
        Clear console
      </button>
      <ol className='console' role='log' aria-label='Console output' data-testid='console-pane'>
        {entries.map(({ id, at, level, text }) => (
          <li key={id} data-level={level}>
            <time dateTime={at}>{at}</time> <span>{level}</span> {text}
          </li>
        ))}
      </ol>
    </section>
  );
};

const Client: FC = () => {
  const signedIn = useSignedIn();

  return (
    <main>
      <h1>Passflow resource server client</h1>
      <SessionPanel signedIn={signedIn} />
      <section aria-labelledby='routes-heading'>
        <h2 id='routes-heading'>Routes</h2>
        <div className='routes'>
          {ROUTES.map((route) => (
            <RouteCard key={route.id} route={route} signedIn={signedIn} />
          ))}
        </div>
      </section>
      <ConsolePane />
    </main>
  );
};

export const App: FC = () => {
  if (missingEnv.length > 0) {
    return (
      <main>
        <h1>Passflow resource server client</h1>
        <p role='alert' data-testid='missing-env'>
          Missing environment variables: {missingEnv.join(', ')}. See .env.example.
        </p>
      </main>
    );
  }

  return (
    <PassflowProvider url={passflowUrl} appId={passflowAppId} scopes={SCOPES} backend={apiUrl} upgrade={UPGRADE}>
      <Client />
    </PassflowProvider>
  );
};
