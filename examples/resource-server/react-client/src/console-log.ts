import type { UpgradeDiagnosticSink } from '@passflow/react';

export type LogLevel = 'info' | 'warn' | 'error';

export type LogEntry = {
  id: number;
  at: string;
  level: LogLevel;
  text: string;
};

const MAX_ENTRIES = 500;
const JWT_SHAPE = /\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*)?/g;

let entries: readonly LogEntry[] = [];
let nextId = 1;
const listeners = new Set<() => void>();

/**
 * The last guard before text reaches the page. No caller passes a token on
 * purpose, but response bodies and SDK messages are not this app's to vouch for.
 */
export const redact = (text: string): string => text.replace(JWT_SHAPE, '<redacted token>');

const publish = (next: readonly LogEntry[]): void => {
  entries = next;
  for (const listener of listeners) listener();
};

export const log = (level: LogLevel, text: string): void => {
  const entry = { id: nextId++, at: new Date().toISOString(), level, text: redact(text) };
  publish([...entries, entry].slice(-MAX_ENTRIES));
};

export const clearLog = (): void => publish([]);

export const readLog = (): readonly LogEntry[] => entries;

export const subscribeLog = (listener: () => void): (() => void) => {
  listeners.add(listener);
  return () => listeners.delete(listener);
};

/**
 * A custom sink replaces the SDK's default console.warn, so this one prints the
 * same sentence to the browser console as well as to the pane. The expose-OFF
 * run reads that console line as evidence.
 */
export const onUpgradeDiagnostic: UpgradeDiagnosticSink = ({ status, url, reason, detail }) => {
  const message = detail?.message ?? `[passflow] upgrade challenge not actioned: ${reason}`;
  console.warn(message, { status, url, reason });
  log('warn', `${reason}: ${message}`);
};
