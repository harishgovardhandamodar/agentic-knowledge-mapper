// Runtime config derived from the environment, not build-time secrets.

/** Base URL for the benchmark backend. Empty string = same origin (proxied by
 * nginx in deploy, vite in dev); override only for a cross-origin backend. */
export function benchApiBase(explicit: string | undefined = import.meta.env.VITE_BENCH_API as string | undefined): string {
  return (explicit ?? '').replace(/\/+$/, '');
}

/** Chat UI lives on the same host as the dashboard, port 8080 (compose). */
export function chatLink(hostname?: string): string {
  const host =
    hostname ||
    (typeof window !== 'undefined' ? window.location.hostname || 'localhost' : 'localhost') ||
    'localhost';
  return `http://${host}:8080`;
}