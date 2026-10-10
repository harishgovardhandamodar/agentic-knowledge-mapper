/**
 * Typed thin client over the FastAPI backend (same origin, /api).
 *
 * Two layers on purpose:
 * - {@link raw} is the transport (fetch + JSON + ApiError), the same contract
 *   the previous fluid client had.
 * - {@link getParsed} / {@link postParsed} wrap it with a Zod schema, so a
 *   response is checked at the boundary. A mismatch is thrown where it can be
 *   seen, not three components later as `undefined`.
 *
 * The base is same-origin in production (served by FastAPI at /fluid, /api is
 * a sibling). In dev the Next rewrite proxies /api to the backend, so the same
 * relative base works in both.
 */
import { z } from 'zod';

const BASE = `${process.env.NEXT_PUBLIC_API_BASE ?? ''}/api`;

export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;
  constructor(status: number, detail: unknown) {
    super(typeof detail === 'string' ? detail : `HTTP ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined | null>;
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

function qs(query?: RequestOptions['query']): string {
  if (!query) return '';
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null) continue;
    p.append(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : '';
}

/** Transport call. Throws {@link ApiError} on any non-2xx. */
export async function raw<T = unknown>(path: string, opts: RequestOptions = {}): Promise<T> {
  const res = await fetch(`${BASE}${path}${qs(opts.query)}`, {
    method: opts.method ?? 'GET',
    headers: { 'Content-Type': 'application/json', ...(opts.headers ?? {}) },
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    signal: opts.signal,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = (data as { detail?: unknown })?.detail ?? `HTTP ${res.status}`;
    throw new ApiError(res.status, detail);
  }
  return data as T;
}

/**
 * Parsed call. Validates the response against `schema`. On failure the error
 * carries the schema issues so a contract drift is diagnosable, and — because
 * a broken screen is worse than an unvalidated one during an incident — the
 * caller may opt to log-and-continue with `{ lenient: true }`.
 */
export async function request<S extends z.ZodTypeAny>(
  schema: S,
  path: string,
  opts: RequestOptions & { lenient?: boolean } = {},
): Promise<z.infer<S>> {
  const data = await raw<unknown>(path, opts);
  const parsed = schema.safeParse(data);
  if (parsed.success) return parsed.data;
  if (opts.lenient) return data as z.infer<S>;
  const first = parsed.error.issues[0];
  throw new ApiError(
    200,
    `Response for ${path} did not match its schema: ` +
      `${first ? `${first.path.join('.')}: ${first.message}` : 'unknown field'}`,
  );
}

/** GET with schema validation. */
export function getParsed<S extends z.ZodTypeAny>(
  schema: S,
  path: string,
  opts: Omit<RequestOptions, 'method' | 'body'> & { lenient?: boolean } = {},
) {
  return request(schema, path, { ...opts, method: 'GET' });
}

/** POST with schema validation. */
export function postParsed<S extends z.ZodTypeAny>(
  schema: S,
  path: string,
  body?: unknown,
  opts: Omit<RequestOptions, 'method' | 'body'> & { lenient?: boolean } = {},
) {
  return request(schema, path, { ...opts, method: 'POST', body });
}

/** Open an export (Markdown/PDF) in a new tab, same-origin. */
export function openExport(path: string, query?: RequestOptions['query']): void {
  if (typeof window === 'undefined') return;
  window.open(`${BASE}${path}${qs(query)}`, '_blank', 'noopener');
}
