import { describe, expect, it, vi } from 'vitest';
import type { KeyboardEvent as ReactKeyboardEvent } from 'react';
import { useTabNav } from './tabs';

// handleKeyDown focuses the target inside requestAnimationFrame (fire-and-forget);
// node has no rAF/jsdom here, so no-op it — focus is the app's concern, not the unit's.
vi.stubGlobal('requestAnimationFrame', () => 0);

const ids = ['a', 'b', 'c'] as const;

function run(handler: (e: ReactKeyboardEvent) => void, key: string) {
  const preventDefault = vi.fn();
  handler({ key, preventDefault } as unknown as ReactKeyboardEvent);
  return preventDefault;
}

describe('useTabNav', () => {
  it('exposes tablist / radiogroup list semantics', () => {
    const nav = useTabNav('v', ids, 'a', vi.fn());
    expect(nav.listProps.role).toBe('tablist');
    const radio = useTabNav('p', ids, 'a', vi.fn(), 'radio');
    expect(radio.listProps.role).toBe('radiogroup');
  });

  it('marks only the active tab focusable and selected', () => {
    const nav = useTabNav('v', ids, 'b', vi.fn());
    for (const id of ids) {
      const p = nav.itemProps(id);
      expect(p.role).toBe('tab');
      expect(p.id).toBe(`v-${id}`);
      expect(p.tabIndex).toBe(id === 'b' ? 0 : -1);
      expect(p['aria-selected']).toBe(id === 'b');
    }
  });

  it('navigates with arrows forward and backward', () => {
    const onSelect = vi.fn();
    expect(run(useTabNav('v', ids, 'a', onSelect).listProps.onKeyDown, 'ArrowRight')).toHaveBeenCalled();
    expect(onSelect).toHaveBeenLastCalledWith('b');
    expect(run(useTabNav('v', ids, 'c', onSelect).listProps.onKeyDown, 'ArrowLeft')).toHaveBeenCalled();
    expect(onSelect).toHaveBeenLastCalledWith('b');
  });

  it('wraps at the ends', () => {
    const onSelect = vi.fn();
    expect(run(useTabNav('v', ids, 'c', onSelect).listProps.onKeyDown, 'ArrowDown')).toHaveBeenCalled();
    expect(onSelect).toHaveBeenLastCalledWith('a');
    expect(run(useTabNav('v', ids, 'a', onSelect).listProps.onKeyDown, 'ArrowUp')).toHaveBeenCalled();
    expect(onSelect).toHaveBeenLastCalledWith('c');
  });

  it('moves to first/last on Home/End', () => {
    const onSelect = vi.fn();
    const { listProps } = useTabNav('v', ids, 'b', onSelect);
    run(listProps.onKeyDown, 'Home');
    expect(onSelect).toHaveBeenLastCalledWith('a');
    run(listProps.onKeyDown, 'End');
    expect(onSelect).toHaveBeenLastCalledWith('c');
  });

  it('lets unrelated keys through untouched', () => {
    const onSelect = vi.fn();
    const { listProps } = useTabNav('v', ids, 'a', onSelect);
    const preventDefault = run(listProps.onKeyDown, 'Enter');
    expect(preventDefault).not.toHaveBeenCalled();
    expect(onSelect).not.toHaveBeenCalled();
  });
});