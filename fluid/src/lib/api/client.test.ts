import { afterEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { ApiError, getParsed, raw, request } from './client';

const schema = z.object({ ok: z.boolean(), name: z.string() });

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function mockFetch(body: unknown, status = 200) {
  const stub = vi.fn(async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
  vi.stubGlobal('fetch', stub);
  return stub;
}

describe('raw', () => {
  it('hits the /api base path', async () => {
    const stub = mockFetch({ ok: true });
    await raw('/investigations');
    expect(stub).toHaveBeenCalledWith('/api/investigations', expect.objectContaining({ method: 'GET' }));
  });

  it('serializes query params and drops null/undefined', async () => {
    const stub = mockFetch({});
    await raw('/x', { query: { a: 1, b: 'two', c: undefined, d: null } });
    expect(stub).toHaveBeenCalledWith('/api/x?a=1&b=two', expect.anything());
  });

  it('throws ApiError with the detail on a non-2xx response', async () => {
    mockFetch({ detail: 'not found' }, 404);
    await expect(raw('/missing')).rejects.toBeInstanceOf(ApiError);
    await expect(raw('/missing')).rejects.toMatchObject({ status: 404, detail: 'not found' });
  });
});

describe('request / getParsed', () => {
  it('returns the parsed data on a schema match', async () => {
    mockFetch({ ok: true, name: 'x' });
    const data = await getParsed(schema, '/thing');
    expect(data).toEqual({ ok: true, name: 'x' });
  });

  it('throws when the response does not match the schema', async () => {
    mockFetch({ ok: true, name: 123 });
    await expect(request(schema, '/thing')).rejects.toThrow(/did not match its schema/);
  });

  it('returns the raw data when lenient is set', async () => {
    mockFetch({ ok: true, name: 123 });
    const data = await request(schema, '/thing', { lenient: true });
    expect(data).toMatchObject({ name: 123 });
  });
});
