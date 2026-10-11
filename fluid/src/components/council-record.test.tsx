import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import { renderWithProviders as render } from '@/test/render';
import { CouncilRecordView } from './council-record';
import type { CouncilRecord } from '@/lib/api/schemas';

const RECORD = {
  investigation_id: 1,
  logs: [
    {
      assessment_id: 7,
      path: 'model_hypothesis',
      product: 'Widget',
      task_id: 'hyp-x',
      hops: [
        { agent: 'hypothesis-analyst', intent: 'hypotheses_drafted', note: '2 claims drafted' },
        { agent: 'hypothesis-verifier', intent: 'hypotheses_verified', note: '2 verified' },
      ],
    },
  ],
  runs: [],
  actions: [
    { kind: 'assurance_decision', decision: 'accept', actor: 'reviewer' },
    { kind: 'register_edit', hypothesis_id: 'H01', status: 'supported' },
  ],
  decisions: [
    { assessment_id: 7, product: 'Widget', assurance_decision: 'accept', decided_by: 'reviewer' },
  ],
  hypotheses: [
    {
      assessment_id: 7,
      confidence: 44,
      claims: [
        {
          hypothesis_id: 'H01',
          claim: 'Outputs reveal training rows',
          falsifier: 'Canary rows never surface in outputs',
          confidence: 62,
          impact: 4,
          status: 'untested',
          council: {
            seat: 'privacy-cryptography',
            falsifier_audit: { grade: 'decisive' },
            challenges: [{ seat: 'measurement-science', ground: 'single_flow' }],
          },
        },
      ],
      council: {},
    },
  ],
} as unknown as CouncilRecord;

describe('CouncilRecordView', () => {
  it('renders nothing when there is no record yet', () => {
    const { container } = render(<CouncilRecordView record={undefined} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('shows the deliberation log hop by hop', () => {
    render(<CouncilRecordView record={RECORD} />);
    expect(screen.getByText('hypothesis-analyst')).toBeInTheDocument();
    expect(screen.getByText('hypotheses_drafted')).toBeInTheDocument();
    expect(screen.getByText(/2 claims drafted/)).toBeInTheDocument();
  });

  it('shows what humans changed and which verdicts stand', () => {
    render(<CouncilRecordView record={RECORD} />);
    // H01 appears twice by design: once as the edited register entry, once as
    // the claim itself. The action and the claim are different facts.
    expect(screen.getAllByText('H01').length).toBe(2);
    expect(screen.getByText(/supported/)).toBeInTheDocument();
    // The verdict appears in both the action and the decision; either is fine.
    // ('accept' and 'reviewer' sit inside sentences split across JSX text
    // nodes, so match loosely rather than by exact element text.)
    const text = document.body.textContent ?? '';
    expect(text).toMatch(/accept/);
    expect(text).toMatch(/reviewer/);
  });

  it('shows the generated claim with its seat, grade and objection', () => {
    render(<CouncilRecordView record={RECORD} />);
    expect(screen.getByText('Outputs reveal training rows')).toBeInTheDocument();
    // (seat and objection strings sit inside sentences split across JSX
    // text nodes, so match against the rendered text.)
    const text = document.body.textContent ?? '';
    expect(text).toMatch(/privacy-cryptography/);
    expect(text).toMatch(/decisive/);
    expect(text).toMatch(/measurement-science/);
    expect(text).toMatch(/single flow/);
    expect(screen.getByText(/Canary rows never surface/)).toBeInTheDocument();
  });
});
