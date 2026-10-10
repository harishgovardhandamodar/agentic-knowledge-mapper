import * as React from 'react';
import { render, type RenderOptions, type RenderResult } from '@testing-library/react';
import { TooltipProvider } from '@/components/ui/tooltip';

/**
 * Render helper that supplies the providers a component expects (currently the
 * Radix tooltip context). Keeps every component test using `render` from one
 * place, so adding a provider later is a one-line change.
 */
export function renderWithProviders(
  ui: React.ReactElement,
  options?: Omit<RenderOptions, 'wrapper'>,
): RenderResult {
  return render(<TooltipProvider>{ui}</TooltipProvider>, options);
}
