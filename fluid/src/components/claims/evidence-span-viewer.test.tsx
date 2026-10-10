import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { EvidenceSpanViewer } from './evidence-span-viewer';
import { SAMPLE_CLAIMS, SAMPLE_SOURCE_TEXT } from '@/lib/fixtures';
import type { Claim } from '@/types/domain';

const sourceText = (id: string) => SAMPLE_SOURCE_TEXT[id];

describe('EvidenceSpanViewer', () => {
  it('highlights the quote inside its surrounding context', () => {
    render(<EvidenceSpanViewer claim={SAMPLE_CLAIMS[0]!} sourceText={sourceText} />);
    const mark = document.querySelector('mark');
    expect(mark).not.toBeNull();
    expect(mark!.textContent).toBe('a 38% reduction in unsupported statements');
    // Context before the quote is present too.
    expect(screen.getByText(/Evaluation on 1,200 questions/)).toBeInTheDocument();
  });

  it('shows the offset of the located span', () => {
    render(<EvidenceSpanViewer claim={SAMPLE_CLAIMS[0]!} sourceText={sourceText} />);
    expect(screen.getByText(/offset 224–265/)).toBeInTheDocument();
  });

  it('falls back to the bare quote when there are no offsets', () => {
    render(<EvidenceSpanViewer claim={SAMPLE_CLAIMS[0]!} />);
    const mark = document.querySelector('mark');
    expect(mark!.textContent).toBe('a 38% reduction in unsupported statements');
    expect(screen.queryByText(/^offset/)).not.toBeInTheDocument();
  });

  it('renders an empty state for a claim with no spans', () => {
    const bare: Claim = { ...SAMPLE_CLAIMS[0]!, spans: [] };
    render(<EvidenceSpanViewer claim={bare} sourceText={sourceText} />);
    expect(screen.getByText(/No evidence span was found/)).toBeInTheDocument();
  });

  it('opens the source when the source button is clicked', async () => {
    const user = userEvent.setup();
    const onOpenSource = vi.fn();
    render(
      <EvidenceSpanViewer
        claim={SAMPLE_CLAIMS[0]!}
        sourceText={sourceText}
        onOpenSource={onOpenSource}
      />,
    );
    await user.click(screen.getByRole('button', { name: /source/i }));
    expect(onOpenSource).toHaveBeenCalledWith('src:arxiv-2411');
  });
});
