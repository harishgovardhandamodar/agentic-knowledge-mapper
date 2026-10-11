import * as React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import { renderWithProviders as render } from '@/test/render';
import { CouncilCharts } from './council-charts';

// jsdom has no layout, so ResponsiveContainer measures 0×0 and recharts
// renders nothing inside it. Fix the container size: the charts then render
// synchronously, and what the test asserts is the chart content (labels,
// values, legend entries), not the responsive behaviour.
vi.mock('recharts', async (importOriginal) => {
  const mod = await importOriginal<typeof import('recharts')>();
  return {
    ...mod,
    // The real container measures the DOM and passes width/height down by
    // context. With no layout the charts get neither and render nothing, so
    // hand the child its dimensions directly: what the tests assert is the
    // chart content, not the responsive behaviour.
    ResponsiveContainer: ({ children }: { children: React.ReactNode }) => (
      <>
        {React.Children.map(children, (child) =>
          React.isValidElement(child)
            ? React.cloneElement(child as React.ReactElement<{ width?: number; height?: number }>, {
                width: 420,
                height: 200,
              })
            : child,
        )}
      </>
    ),
  };
});

const CLAIMS = [
  { id: 'H01', confidence: 62, contested: true, seat: 'privacy-cryptography' },
  { id: 'H02', confidence: 41, contested: false, seat: 'ml-systems' },
];

describe('CouncilCharts', () => {
  it('charts confidence per claim with a mean reference', () => {
    render(
      <CouncilCharts
        claims={CLAIMS}
        grounds={{ single_flow: 2 }}
        coverage={{ covered: 2, unexamined: 1, silent: 1, pct: 66.7 }}
        seats={[{ seat: 'privacy-cryptography', filed: 1, reviewing: 0 }]}
      />,
    );
    expect(screen.getByText('Confidence per claim')).toBeInTheDocument();
    // Mean of 62 and 41 rounds to 52.
    expect(screen.getByText(/mean 52/)).toBeInTheDocument();
  });

  it('charts objection grounds ranked commonest-first', () => {
    render(
      <CouncilCharts
        claims={CLAIMS}
        grounds={{ rival_not_excluded: 3, single_flow: 5 }}
        coverage={{ covered: 1, unexamined: 0, silent: 0, pct: 100 }}
        seats={[]}
      />,
    );
    expect(screen.getByText('Objection grounds')).toBeInTheDocument();
    const text = document.body.textContent ?? '';
    expect(text).toMatch(/single flow/);
    // Ranked: the bigger bar's label precedes the smaller's in the DOM.
    expect(text.indexOf('single flow')).toBeLessThan(text.indexOf('rival not excluded'));
  });

  it('charts coverage as covered / unexamined / corpus-silent shares', () => {
    render(
      <CouncilCharts
        claims={CLAIMS}
        grounds={{}}
        coverage={{ covered: 2, unexamined: 1, silent: 1, pct: 66.7 }}
        seats={[]}
      />,
    );
    expect(screen.getByText('Attack-class coverage')).toBeInTheDocument();
    const text = document.body.textContent ?? '';
    // Legend names all three shares, including the one the corpus never mentions.
    expect(text).toMatch(/Unexamined/);
    expect(text).toMatch(/Corpus silent/);
  });

  it('charts seats filed beside reviewing, never merged', () => {
    render(
      <CouncilCharts
        claims={CLAIMS}
        grounds={{}}
        coverage={{ covered: 1, unexamined: 0, silent: 0, pct: 100 }}
        seats={[
          { seat: 'privacy-cryptography', filed: 2, reviewing: 1 },
          { seat: 'measurement-science', filed: 0, reviewing: 3 },
        ]}
      />,
    );
    expect(screen.getByText(/filed vs reviewing/)).toBeInTheDocument();
    // (recharts renders a hidden measuring span duplicating each tick label,
    // so match against the rendered content rather than by single element.)
    const seatsText = document.body.textContent ?? '';
    expect(seatsText).toMatch(/privacy-cryptography/);
    expect(seatsText).toMatch(/measurement-science/);
    // A seat that only reviewed still appears: reviewing is work, and
    // dropping it would make an absent seat indistinguishable from one that
    // objected to everything.
    const text = document.body.textContent ?? '';
    expect(text).toMatch(/Filed/);
    expect(text).toMatch(/Reviewing/);
  });

  it('omits empty charts rather than rendering empty frames', () => {
    render(
      <CouncilCharts
        claims={CLAIMS}
        grounds={{}}
        coverage={{ covered: 1, unexamined: 0, silent: 0, pct: 100 }}
        seats={[]}
      />,
    );
    expect(screen.queryByText('Objection grounds')).not.toBeInTheDocument();
  });
});
