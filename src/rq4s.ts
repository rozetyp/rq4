/**
 * RQ4-S: Session-Level Request Context Transition Detection
 * Reference Implementation v2.0
 *
 * Correlates per-request RQ4 fingerprints across a cookie session to detect
 * the cookie-reuse attack: a real browser solves a WAF challenge, the
 * resulting session cookies are transferred to an HTTP client (e.g.
 * curl_cffi), and the client makes subsequent requests with frozen
 * navigation headers that are contextually impossible.
 *
 * Detection: a session is "clean" while all requests produce only 'v' or '-'
 * RQ4 dimension results. The session is "compromised" the moment a request
 * produces an 'x' (impossible) result. The first such transition catches the
 * handoff on the first bot request.
 *
 * License: MIT
 */

import type { RQ4Result } from './rq4';

// ─── Types ──────────────────────────────────────────────────────────────────

/** State persisted per session in your KV / Redis / Postgres. */
export interface SessionState {
  /** True while all observed RQ4 results have been v/- only. */
  clean: boolean;
  /** Total RQ4 evaluations seen on this session. */
  count: number;
  /** Request count at which the session was flagged (if compromised). */
  flaggedAt?: number;
}

/** Verdict for a single request within a session. */
export type SessionVerdict =
  | { state: 'clean'; session: SessionState }
  | { state: 'transition'; session: SessionState; flaggedAt: number }
  | { state: 'compromised'; session: SessionState };

/** Minimal KV interface — adapt to Cloudflare Workers KV, Redis, etc. */
export interface SessionStore {
  get(sessionId: string): Promise<SessionState | null>;
  put(sessionId: string, state: SessionState, ttlSeconds: number): Promise<void>;
}

// ─── Session cookie extraction ──────────────────────────────────────────────

/**
 * Known WAF / origin session cookie names. Extend as needed.
 * Order matters: composite identifier prefers the most specific match.
 */
export const KNOWN_SESSION_COOKIES = [
  // Imperva Incapsula
  'incap_ses', 'visid_incap', 'nlbi',
  // Cloudflare
  'cf_clearance', '__cf_bm',
  // F5 Shape / BIG-IP
  'TS01', 'BIGipServer',
  // Akamai Bot Manager
  '_abck', 'bm_sz', 'bm_sv',
  // DataDome
  'datadome',
  // Generic ASP.NET / Java
  'ASP.NET_SessionId', 'JSESSIONID',
];

/**
 * Extract a stable session identifier from request cookies.
 *
 * If multiple known session cookies are present, returns a hash-friendly
 * composite key. If none match, falls back to the first cookie if any.
 * Returns null if no cookies present.
 */
export function getSessionId(cookieHeader: string | undefined): string | null {
  if (!cookieHeader) return null;
  const cookies = parseCookies(cookieHeader);

  const matched: string[] = [];
  for (const name of KNOWN_SESSION_COOKIES) {
    for (const cookieName of Object.keys(cookies)) {
      if (cookieName.startsWith(name)) {
        matched.push(`${cookieName}=${cookies[cookieName]}`);
      }
    }
  }

  if (matched.length > 0) {
    return matched.sort().join('|');
  }

  // Fallback: use any cookie at all
  const names = Object.keys(cookies);
  if (names.length === 0) return null;
  return `${names[0]}=${cookies[names[0]]}`;
}

function parseCookies(header: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of header.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf('=');
    if (eq < 0) continue;
    out[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
  }
  return out;
}

// ─── Core: track a request within a session ─────────────────────────────────

/**
 * Update session state given a fresh RQ4 result. Returns a verdict that the
 * caller can act on (e.g., block compromised sessions at the edge).
 *
 * Default TTL: 1200 seconds (20 minutes), matching common WAF session
 * cookie lifetimes. Override per WAF if needed.
 */
export async function trackSession(
  store: SessionStore,
  sessionId: string,
  rq4: RQ4Result,
  ttlSeconds: number = 1200,
): Promise<SessionVerdict> {
  const prior = (await store.get(sessionId)) || { clean: true, count: 0 };
  const state: SessionState = { ...prior, count: prior.count + 1 };

  const hasImpossible = rq4.fingerprint.includes('x');

  if (hasImpossible && state.clean && state.count > 1) {
    // First impossible result on a previously-clean session → transition
    state.clean = false;
    state.flaggedAt = state.count;
    await store.put(sessionId, state, ttlSeconds);
    return { state: 'transition', session: state, flaggedAt: state.count };
  }

  if (!state.clean) {
    // Already-flagged session continues to make requests
    await store.put(sessionId, state, ttlSeconds);
    return { state: 'compromised', session: state };
  }

  // Either rq4 is all v/-, or this is request #1 (no prior to compare against)
  await store.put(sessionId, state, ttlSeconds);
  return { state: 'clean', session: state };
}

// ─── Convenience: in-memory store for testing ──────────────────────────────

/**
 * Simple in-memory session store. Useful for tests and single-instance
 * deployments. Not suitable for production multi-region edge.
 */
export class MemorySessionStore implements SessionStore {
  private map = new Map<string, { state: SessionState; expiresAt: number }>();

  async get(sessionId: string): Promise<SessionState | null> {
    const entry = this.map.get(sessionId);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.map.delete(sessionId);
      return null;
    }
    return entry.state;
  }

  async put(sessionId: string, state: SessionState, ttlSeconds: number): Promise<void> {
    this.map.set(sessionId, {
      state,
      expiresAt: Date.now() + ttlSeconds * 1000,
    });
  }
}

// ─── Example: Cloudflare Workers KV adapter ────────────────────────────────

/**
 * Adapter for Cloudflare Workers KV. Pass your KV binding.
 *
 * Usage:
 *   const store = new CloudflareKVStore(env.RQ4S_SESSIONS);
 *   const verdict = await trackSession(store, sessionId, rq4);
 */
export class CloudflareKVStore implements SessionStore {
  constructor(
    private kv: {
      get: (key: string, opts?: { type: 'json' }) => Promise<unknown>;
      put: (key: string, value: string, opts?: { expirationTtl: number }) => Promise<void>;
    },
    private prefix: string = 'rq4s:',
  ) {}

  async get(sessionId: string): Promise<SessionState | null> {
    const result = await this.kv.get(this.prefix + hashKey(sessionId), { type: 'json' });
    return (result as SessionState) ?? null;
  }

  async put(sessionId: string, state: SessionState, ttlSeconds: number): Promise<void> {
    await this.kv.put(this.prefix + hashKey(sessionId), JSON.stringify(state), {
      expirationTtl: ttlSeconds,
    });
  }
}

/**
 * Hash a session ID into a key-safe string. Used so cookie values don't
 * become storage keys directly (keeps keys bounded length, avoids
 * encoding edge cases).
 */
function hashKey(input: string): string {
  let h = 5381;
  for (let i = 0; i < input.length; i++) {
    h = ((h << 5) + h + input.charCodeAt(i)) | 0;
  }
  return (h >>> 0).toString(36);
}
