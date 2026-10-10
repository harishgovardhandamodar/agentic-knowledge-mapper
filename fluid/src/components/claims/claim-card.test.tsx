import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders as render } from '@/test/render';
import { ClaimCard } from './claim-card';
import { SAMPLE_CLAIMS, SAMPLE_SOURCE_TEXT } from '@/lib/fixtures';

const sourceText = (id: string) => SAMPLE_SOURCE_TEXT[id];

describe('ClaimCard', () => {
  it('shows the verdict, the support figure and the claim text', () => {
    render(<ClaimCard claim={SAMPLE_CLAIMS[0]!} sourceText={sourceText} />);
    expect(screen.getByText(/Supported/)).toBeInTheDocument();
    expect(screen.getByText(/support 82%/)).toBeInTheDocument();
    expect(screen.getByText(SAMPLE_CLAIMS[0]!.text)).toBeInTheDocument();
  });

  it('shows the confidence interval next to the point when present', () => {
    render(<ClaimCard claim={SAMPLE_CLAIMS[0]!} sourceText={sourceText} />);
    expect(screen.getByText(/\[63%–90%\]/)).toBeInTheDocument();
  });

  it('reveals the evidence span only after clicking View evidence', async () => {
    const user = userEvent.setup();
    render(<ClaimCard claim={SAMPLE_CLAIMS[0]!} sourceText={sourceText} />);
    expect(screen.queryByText(/offset 224–265/)).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /view evidence/i }));
    expect(screen.getByText(/offset 224–265/)).toBeInTheDocument();
  });

  it('warns about unresolved citations', () => {
    render(<ClaimCard claim={SAMPLE_CLAIMS[3]!} sourceText={sourceText} />);
    expect(screen.getByText(/could not be resolved/)).toBeInTheDocument();
    expect(screen.getByText(/src:does-not-exist/)).toBeInTheDocument();
  });

  it('surfaces a contradiction tension', () => {
    render(<ClaimCard claim={SAMPLE_CLAIMS[2]!} sourceText={sourceText} />);
    expect(screen.getByText(/Tension with/)).toBeInTheDocument();
  });

  it('disables the evidence button when there are no spans', () => {
    render(<ClaimCard claim={SAMPLE_CLAIMS[3]!} sourceText={sourceText} />);
    expect(screen.getByRole('button', { name: /no evidence/i })).toBeDisabled();
  });

  it('calls onOpenSource with the source id', async () => {
    const user = userEvent.setup();
    const onOpenSource = vi.fn();
    render(
      <ClaimCard claim={SAMPLE_CLAIMS[0]!} sourceText={sourceText} defaultExpanded onOpenSource={onOpenSource} />,
    );
    await user.click(screen.getByRole('button', { name: /source/i }));
    expect(onOpenSource).toHaveBeenCalledWith('src:arxiv-2411');
  });
});
