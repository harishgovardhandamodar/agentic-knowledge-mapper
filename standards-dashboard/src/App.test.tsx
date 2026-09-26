import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from './App';
import type { Framework, IngestedData } from './lib/engine';
import type { GraphData } from './lib/graph';

const dims = [
  { id: 'risk', label: 'Risk', description: 'Risk management' },
  { id: 'data', label: 'Data', description: 'Data governance' },
];

const fw: Framework = {
  id: 'eu-ai-act',
  name: 'EU AI Act',
  issuer: 'EU',
  jurisdiction: 'EU',
  kind: 'regulation',
  version: '2024',
  status: 'in force',
  url: 'https://example.com/eu-ai-act',
  summary: 'Regulates high-risk AI systems in the EU.',
  riskTiers: ['high-risk'],
  controls: ['transparency'],
  coverage: { risk: 2, data: 2 },
  scenarios: ['high-risk'],
  lastChecked: '2026-09-01',
};

const data: IngestedData = {
  generated: '2026-09-20',
  dimensions: dims,
  frameworks: [fw],
  overlap: [],
};

const graph: GraphData = {
  generated: '2026-09-20',
  nodes: [],
  links: [],
  clusterCount: 0,
  clusterLabels: [],
};

describe('App', () => {
  it('renders the shell with accessible tab semantics', () => {
    render(<App data={data} graph={graph} />);
    expect(screen.getByRole('heading', { name: /AI Standards & Regulations Dashboard/i })).toBeInTheDocument();
    expect(screen.getByRole('radiogroup', { name: /persona/i })).toBeInTheDocument();
    expect(screen.getByRole('tablist', { name: /views/i })).toBeInTheDocument();
  });

  it('does not pull heavy views into the initial render (code splitting)', () => {
    render(<App data={data} graph={graph} />);
    expect(screen.getByRole('tabpanel')).toBeInTheDocument();
    expect(screen.queryByText(/Knowledge graph — sources/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Security & Safety — Traditional/i)).not.toBeInTheDocument();
  });

  it('switches to the light Query view synchronously', async () => {
    const user = userEvent.setup();
    render(<App data={data} graph={graph} />);
    await user.click(screen.getByRole('tab', { name: /^Query$/ }));
    expect(await screen.findByRole('textbox', { name: /query all/i })).toBeInTheDocument();
  });

  it('shows a provenance chip for the selected framework', async () => {
    const user = userEvent.setup();
    render(<App data={data} graph={graph} />);
    await user.click(screen.getByRole('button', { name: /EU AI Act/ }));
    // Date-independent: the chip always carries the verified-date tooltip.
    expect(await screen.findByTitle(/Provenance: source last verified 2026-09-01/)).toBeInTheDocument();
  });

  it('lazy-loads the Knowledge Graph view on demand', async () => {
    const user = userEvent.setup();
    render(<App data={data} graph={graph} />);
    await user.click(screen.getByRole('tab', { name: /Knowledge Graph/i }));
    expect(await screen.findByText(/Knowledge graph — sources, themes & relations/i)).toBeInTheDocument();
  });
});