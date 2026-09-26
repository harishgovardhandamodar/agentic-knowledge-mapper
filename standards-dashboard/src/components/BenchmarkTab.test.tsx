import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import BenchmarkTab from './BenchmarkTab';

function jsonResponse(body: unknown, status = 200) {
  return Promise.resolve({ ok: status >= 200 && status < 300, status, json: () => Promise.resolve(body) } as Response);
}

function stubFetch(runImpl: () => Promise<Response>) {
  const fetchMock = vi.fn((url: string) => {
    const u = String(url);
    if (u.includes('/eval-report-')) return jsonResponse({}, 404);
    if (u.endsWith('/api/benchmark/status')) return jsonResponse({}, 404);
    if (u.endsWith('/api/benchmark/run')) return runImpl();
    throw new Error(`unexpected fetch: ${u}`);
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

describe('BenchmarkTab token flow', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('confirms inline, prompts for the token on 401, and retries authorized', async () => {
    const user = userEvent.setup();
    let runAttempts = 0;
    const fetchMock = stubFetch(() => {
      runAttempts += 1;
      return runAttempts === 1 ? jsonResponse({ error: 'unauthorized' }, 401) : jsonResponse({ started: true });
    });

    render(<BenchmarkTab />);
    const run = await screen.findByRole('button', { name: /▶ Run 500×3/ });

    await user.click(run);
    const dialog = await screen.findByRole('alertdialog', { name: /confirm benchmark action/i });
    expect(dialog).toHaveTextContent(/3–4 h/);
    await user.click(screen.getByRole('button', { name: /^confirm$/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/token required or incorrect/i);
    expect(screen.getByLabelText(/benchmark api token/i)).toBeInTheDocument();

    await user.type(screen.getByLabelText(/benchmark api token/i), 'secret-token');
    await user.click(screen.getByRole('button', { name: /save token/i }));
    expect(screen.getByRole('button', { name: /token set/i })).toBeInTheDocument();

    await user.click(run);
    await user.click(await screen.findByRole('button', { name: /^confirm$/i }));
    await waitFor(() => expect(runAttempts).toBe(2));
    const runPosts = fetchMock.mock.calls.filter(
      ([url]) => String(url).includes('/api/benchmark/run'),
    ) as unknown as Array<[string, RequestInit]>;
    expect(runPosts).toHaveLength(2);
    expect(runPosts[1][1].headers).toMatchObject({ Authorization: 'Bearer secret-token' });
  });

  it('cancelling the inline confirm performs no mutation', async () => {
    const user = userEvent.setup();
    let runAttempts = 0;
    stubFetch(() => {
      runAttempts += 1;
      return jsonResponse({ started: true });
    });

    render(<BenchmarkTab />);
    await user.click(await screen.findByRole('button', { name: /▶ Run 500×3/ }));
    await screen.findByRole('alertdialog', { name: /confirm benchmark action/i });
    await user.click(screen.getByRole('button', { name: /cancel/i }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(runAttempts).toBe(0);
  });

  it('surfaces mutation failures inline instead of alert()', async () => {
    const user = userEvent.setup();
    stubFetch(() => Promise.reject(new Error('backend down')));

    render(<BenchmarkTab />);
    await user.click(await screen.findByRole('button', { name: /▶ Run 500×3/ }));
    await user.click(await screen.findByRole('button', { name: /^confirm$/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/benchmark action failed.*backend down/i);
    await user.click(screen.getByRole('button', { name: /dismiss/i }));
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument());
  });
});