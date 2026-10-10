'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { PanelLeftClose, PanelLeft } from 'lucide-react';
import { NAV_ITEMS, NAV_GROUPS } from '@/lib/nav';
import { useUi } from '@/lib/stores/ui';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';

/**
 * Persistent navigation rail. Collapsible to an icon strip for dense layouts;
 * the collapsed state is persisted. Unbuilt surfaces are marked so the user
 * knows they are placeholders, not broken.
 */
export function NavRail() {
  const pathname = usePathname();
  const { navCollapsed, toggleNav } = useUi();

  const isActive = (href: string) =>
    href === '/' ? pathname === '/' : pathname.startsWith(href);

  return (
    <nav
      aria-label="Primary"
      className={cn(
        'flex shrink-0 flex-col gap-4 border-r bg-card/40 p-2 transition-[width] duration-200',
        navCollapsed ? 'w-14' : 'w-56',
      )}
    >
      <div className={cn('flex items-center', navCollapsed ? 'justify-center' : 'justify-between px-1')}>
        {!navCollapsed && (
          <span className="font-mono text-xs font-semibold uppercase tracking-widest text-muted-foreground">
            Fluid
          </span>
        )}
        <Button
          variant="ghost"
          size="icon"
          onClick={toggleNav}
          aria-label={navCollapsed ? 'Expand navigation' : 'Collapse navigation'}
          title={navCollapsed ? 'Expand' : 'Collapse'}
        >
          {navCollapsed ? <PanelLeft className="size-4" /> : <PanelLeftClose className="size-4" />}
        </Button>
      </div>

      <div className="flex flex-1 flex-col gap-4 overflow-y-auto">
        {NAV_GROUPS.map((group) => {
          const items = NAV_ITEMS.filter((i) => i.group === group.id);
          if (items.length === 0) return null;
          return (
            <div key={group.id} className="flex flex-col gap-0.5">
              {!navCollapsed && (
                <span className="px-2 pb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  {group.label}
                </span>
              )}
              {items.map((item) => {
                const Icon = item.icon;
                const active = item.built && isActive(item.href);
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    title={navCollapsed ? item.label : item.hint}
                    aria-current={active ? 'page' : undefined}
                    aria-disabled={!item.built}
                    className={cn(
                      'group flex items-center gap-2 rounded-md px-2 py-1.5 text-sm transition-colors',
                      navCollapsed && 'justify-center',
                      active
                        ? 'bg-accent text-accent-foreground'
                        : 'text-muted-foreground hover:bg-accent/50 hover:text-foreground',
                      !item.built && 'opacity-50',
                    )}
                  >
                    <Icon className="size-4 shrink-0" aria-hidden />
                    {!navCollapsed && (
                      <span className="flex min-w-0 flex-1 items-center justify-between gap-1">
                        <span className="truncate">{item.label}</span>
                        {!item.built && (
                          <span className="rounded bg-muted px-1 text-[9px] uppercase text-muted-foreground">
                            soon
                          </span>
                        )}
                      </span>
                    )}
                  </Link>
                );
              })}
            </div>
          );
        })}
      </div>
    </nav>
  );
}
