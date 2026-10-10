import type { ReactNode } from 'react';
import { NavRail } from '@/components/shell/nav-rail';
import { Topbar } from '@/components/shell/topbar';

/** App shell: fixed nav rail + top bar, scrollable content region. */
export function Shell({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-screen overflow-hidden">
      <NavRail />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />
        <main className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-6xl px-6 py-6">{children}</div>
        </main>
      </div>
    </div>
  );
}
