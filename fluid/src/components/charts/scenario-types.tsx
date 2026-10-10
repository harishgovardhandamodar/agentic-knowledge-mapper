'use client';

import * as React from 'react';
import { GitBranch, ShieldAlert, Layers } from 'lucide-react';

export interface ScenarioPoint {
  id: string;
  origin: string;
  title: string;
  coverage_of_exploit?: number;
  residual_score?: number;
  why?: string;
  [k: string]: unknown;
}

export { ORIGIN_COLOR } from './scenario-coverage-scatter';

export function ScenarioGlyph({ origin, className }: { origin: string; className?: string }) {
  if (origin === 'control_gap_chain') return <GitBranch className={className} aria-hidden />;
  if (origin === 'residual_amplifier') return <ShieldAlert className={className} aria-hidden />;
  return <Layers className={className} aria-hidden />;
}