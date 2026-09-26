import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import SecurityEvolved from './SecurityEvolved';
import SupportMaterials from './SupportMaterials';

function stubRaf() {
  vi.stubGlobal('requestAnimationFrame', (cb: FrameRequestCallback) => {
    cb(0);
    return 0;
  });
}

describe('converted tablists (useTabNav)', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('SecurityEvolved streams: roving tabindex with arrow-key selection and focus', async () => {
    stubRaf();
    const user = userEvent.setup();
    render(<SecurityEvolved frameworks={[]} dimensions={[]} graph={null} />);

    const all = screen.getByRole('tab', { name: 'All' });
    expect(all).toHaveAttribute('aria-selected', 'true');
    expect(all.tabIndex).toBe(0);
    expect(screen.getByRole('tab', { name: 'Traditional' }).tabIndex).toBe(-1);

    all.focus();
    await user.keyboard('{ArrowRight}');
    const traditional = await screen.findByRole('tab', { name: 'Traditional', selected: true });
    expect(traditional.tabIndex).toBe(0);
    expect(document.activeElement).toBe(traditional);
  });

  it('SupportMaterials modes: arrow keys move across lens tabs', async () => {
    stubRaf();
    const user = userEvent.setup();
    render(<SupportMaterials frameworks={[]} />);

    const consumption = screen.getByRole('tab', { name: /Consumption/ });
    expect(consumption).toHaveAttribute('aria-selected', 'true');
    consumption.focus();
    await user.keyboard('{ArrowRight}');
    const exposure = await screen.findByRole('tab', { name: /Exposure/, selected: true });
    expect(document.activeElement).toBe(exposure);
  });
});