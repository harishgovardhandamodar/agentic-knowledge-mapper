import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import { renderWithProviders as render } from '@/test/render';
import { CouncilPanel } from './council-panel';
import type { Assessment } from '@/lib/api/schemas';

const base = { id: 1, threats: [] } as unknown as Assessment;

function withCouncil(council: unknown, rest: Record<string, unknown> = {}): Assessment {
  return { ...base, ...rest, council } as Assessment;
}

const PANEL = {
  panel: {
    n_seats: 2,
    seats: [
      {
        id: 'privacy-cryptography',
        discipline: 'Privacy engineering',
        remit: 'What does an attacker learn about a single record?',
        owns: ['membership_inference'],
        blind_spot: 'Says nothing about deployments with no guarantee at all.',
      },
      {
        id: 'measurement-science',
        discipline: 'Measurement science',
        remit: 'Can this test discriminate the claim from its alternatives?',
        owns: [],
        blind_spot: 'Knows statistics, not systems.',
      },
    ],
  },
  coverage: {
    coverage_pct: 50,
    unexamined: [
      { class: 'poisoning', label: 'Poisoning / backdoors', severity: 75, stored_rows: 2 },
    ],
    not_in_corpus: [{ class: 'theft', label: 'Weight stealing', severity: 70, stored_rows: 0 }],
  },
  seats_contributing: ['privacy-cryptography'],
  contested: 4,
  unexamined: 1,
};

describe('CouncilPanel', () => {
  it('renders nothing when the assessment has no council', () => {
    const { container } = render(<CouncilPanel assessment={base} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('shows the panel size and how many claims were contested', () => {
    render(<CouncilPanel assessment={withCouncil(PANEL)} />);
    expect(screen.getByText(/2 reviewer seats sat on this review/)).toBeInTheDocument();
    expect(screen.getByText(/contested by a seat that did not draft them/)).toBeInTheDocument();
  });

  it('marks a seat that filed nothing as silent rather than omitting it', () => {
    render(<CouncilPanel assessment={withCouncil(PANEL)} />);
    // A silent seat is information: it tells the reader which discipline
    // contributed nothing. Dropping it would make an absent seat
    // indistinguishable from one that was never asked.
    expect(screen.getByText('stayed silent')).toBeInTheDocument();
    expect(screen.getByText('filed a claim')).toBeInTheDocument();
  });

  it("prints every seat's known blind spot", () => {
    render(<CouncilPanel assessment={withCouncil(PANEL)} />);
    expect(screen.getByText(/Says nothing about deployments/)).toBeInTheDocument();
    expect(screen.getByText(/Knows statistics, not systems/)).toBeInTheDocument();
  });

  it('separates "nobody claimed it" from "the corpus never mentions it"', () => {
    // The whole reason the coverage report has two lists. Collapsing them
    // would let a gap in the review read as a clean result.
    render(<CouncilPanel assessment={withCouncil(PANEL)} />);
    expect(screen.getByText(/Unreached by the panel/)).toBeInTheDocument();
    expect(screen.getByText(/Out of scope/)).toBeInTheDocument();
    expect(screen.getByText(/2 stored row\(s\) bear on this/)).toBeInTheDocument();
    expect(screen.getByText(/Unmeasured, which is not the same as absent/)).toBeInTheDocument();
  });

  it('warns that an unobjected-to claim is unreviewed, not verified', () => {
    render(<CouncilPanel assessment={withCouncil(PANEL)} />);
    expect(
      screen.getByText(/unattacked is not the same as unrefutable/i),
    ).toBeInTheDocument();
  });
});
