import * as React from 'react';

/**
 * Minimal accessible tabs / radio groups: roving tabindex + arrow-key
 * navigation. Tabs wire their panels via aria-labelledby to the active tab.
 */
export function useTabNav<T extends string>(
  name: string,
  ids: readonly T[],
  active: T,
  onSelect: (t: T) => void,
  variant: 'tab' | 'radio' = 'tab',
) {
  const handleKeyDown = (e: React.KeyboardEvent) => {
    const i = ids.indexOf(active);
    let next: number | null = null;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = (i + 1) % ids.length;
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = (i - 1 + ids.length) % ids.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = ids.length - 1;
    if (next === null) return;
    e.preventDefault();
    onSelect(ids[next]);
    requestAnimationFrame(() => {
      document.getElementById(`${name}-${ids[next]}`)?.focus();
    });
  };

  return {
    listProps: { role: variant === 'radio' ? 'radiogroup' : 'tablist', onKeyDown: handleKeyDown },
    itemProps: (id: T) =>
      variant === 'radio'
        ? {
            role: 'radio',
            id: `${name}-${id}`,
            'aria-checked': id === active,
            tabIndex: id === active ? 0 : -1,
            onClick: () => onSelect(id),
          }
        : {
            role: 'tab',
            id: `${name}-${id}`,
            'aria-selected': id === active,
            tabIndex: id === active ? 0 : -1,
            onClick: () => onSelect(id),
          },
  };
}