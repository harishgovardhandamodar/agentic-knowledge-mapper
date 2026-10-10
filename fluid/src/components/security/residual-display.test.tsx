import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import { renderWithProviders as render } from '@/test/render';
import { ResidualDisplay } from './residual-display';
import {
  SAMPLE_EVIDENCE,
  SAMPLE_RESIDUAL,
  SAMPLE_RESIDUAL_OUTSIDE,
} from '@/lib/fixtures';

describe('ResidualDisplay', () => {
  it('always renders the interval alongside the point', () => {
    render(<ResidualDisplay residual={SAMPLE_RESIDUAL} />);
    expect(screen.getByText('42')).toBeInTheDocument();
    expect(screen.getByText(/90% interval 31–58%/)).toBeInTheDocument();
  });

  it('exposes the point and interval together to assistive tech', () => {
    render(<ResidualDisplay residual={SAMPLE_RESIDUAL} />);
    expect(
      screen.getByRole('img', {
        name: /Residual 42 percent, 90 percent interval from 31 to 58 percent/,
      }),
    ).toBeInTheDocument();
  });

  it('warns when the headline sits outside its own interval', () => {
    render(<ResidualDisplay residual={SAMPLE_RESIDUAL_OUTSIDE} />);
    expect(screen.getByText(/sits outside its own interval/)).toBeInTheDocument();
  });

  it('does not warn when the headline is inside the interval', () => {
    render(<ResidualDisplay residual={SAMPLE_RESIDUAL} />);
    expect(screen.queryByText(/sits outside its own interval/)).not.toBeInTheDocument();
  });

  it('shows an explicit no-interval state instead of a bare point', () => {
    render(<ResidualDisplay residual={null} pointWithoutInterval={42} />);
    expect(screen.getByText(/No interval was computed/)).toBeInTheDocument();
    // The number appears, but only next to the warning.
    expect(screen.getByText('42')).toBeInTheDocument();
  });

  it('renders the evidence composition when provided', () => {
    render(<ResidualDisplay residual={SAMPLE_RESIDUAL} evidence={SAMPLE_EVIDENCE} />);
    expect(screen.getByText(/Evidence composition/)).toBeInTheDocument();
  });

  it('renders the threat count', () => {
    render(<ResidualDisplay residual={SAMPLE_RESIDUAL} />);
    expect(screen.getByText('n=12')).toBeInTheDocument();
  });
});
