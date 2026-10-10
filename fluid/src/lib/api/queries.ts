/**
 * TanStack Query hooks and key factory for the endpoints the shell and the
 * three primitives read. Keeping keys in one `qk` object stops cache-fragment
 * drift between screens (the old app had the same string built in several
 * files).
 */
import { useMutation, useQuery, type UseQueryOptions } from '@tanstack/react-query';
import { getParsed, postParsed } from './client';
import {
  zAssessment,
  zAssessmentAnalysis,
  zAssessmentList,
  zControlCatalog,
  zEvalReport,
  zHealth,
  zInvestigation,
  zInvestigationList,
  zResearchGaps,
  zThreatPack,
  type Assessment,
  type AssessmentAnalysis,
  type EvalReport,
  type Experiment,
  type Investigation,
  type PrivacyBudget,
  type ResearchGaps,
  type ThreatPack,
  type UncertaintyBand,
  type VarianceBudget,
} from './schemas';
import type { ControlCatalogRow } from './calibration';

export const qk = {
  all: ['akm'] as const,
  health: () => [...qk.all, 'health'] as const,
  investigations: () => [...qk.all, 'investigations'] as const,
  investigation: (id: number) => [...qk.all, 'investigation', id] as const,
  assessments: (invId: number) => [...qk.all, 'assessments', invId] as const,
  assessment: (id: number) => [...qk.all, 'assessment', id] as const,
  analysis: (id: number) => [...qk.all, 'assessment-analysis', id] as const,
  threatPack: () => [...qk.all, 'threat-pack'] as const,
  controls: () => [...qk.all, 'controls'] as const,
  eval: () => [...qk.all, 'eval'] as const,
  gaps: (invId: number) => [...qk.all, 'research-gaps', invId] as const,
  experiments: (assessmentId: number) =>
    [...qk.all, 'experiments', assessmentId] as const,
};

export function useHealth() {
  return useQuery({
    queryKey: qk.health(),
    queryFn: () => getParsed(zHealth, '/health', { lenient: true }),
    retry: false,
  });
}

export function useInvestigations() {
  return useQuery({
    queryKey: qk.investigations(),
    queryFn: async (): Promise<Investigation[]> => {
      const data = await getParsed(zInvestigationList, '/investigations');
      return data.items ?? data.investigations ?? [];
    },
  });
}

export function useInvestigation(id: number | null | undefined) {
  return useQuery({
    queryKey: qk.investigation(id ?? -1),
    enabled: typeof id === 'number' && id > 0,
    queryFn: () =>
      getParsed(zInvestigation, `/investigations/${id}`, { lenient: true }),
  });
}

export function useAssessments(
  invId: number | null | undefined,
  opts: Pick<UseQueryOptions<Assessment[]>, 'enabled'> = {},
) {
  return useQuery({
    queryKey: qk.assessments(invId ?? -1),
    enabled: opts.enabled ?? (typeof invId === 'number' && invId > 0),
    queryFn: async (): Promise<Assessment[]> => {
      const data = await getParsed(
        zAssessmentList,
        `/investigations/${invId}/security/assessments`,
        { lenient: true },
      );
      if (Array.isArray(data)) return data;
      return data.items ?? data.assessments ?? [];
    },
  });
}

export function useAssessment(id: number | null | undefined) {
  return useQuery({
    queryKey: qk.assessment(id ?? -1),
    enabled: typeof id === 'number' && id > 0,
    queryFn: () => getParsed(zAssessment, `/security/assessments/${id}`),
  });
}

/**
 * The analysis bundle (uncertainty band, privacy budget, repro manifest) is a
 * separate, opt-in call so opening an assessment is cheap; panels that need it
 * pass `enabled`.
 */
export function useAssessmentAnalysis(
  id: number | null | undefined,
  enabled = true,
) {
  return useQuery({
    queryKey: qk.analysis(id ?? -1),
    enabled: enabled && typeof id === 'number' && id > 0,
    queryFn: (): Promise<AssessmentAnalysis> =>
      getParsed(zAssessmentAnalysis, `/security/assessments/${id}/analysis`),
  });
}

export function useThreatPack() {
  return useQuery({
    queryKey: qk.threatPack(),
    queryFn: (): Promise<ThreatPack> =>
      getParsed(zThreatPack, '/security/threat-pack', { lenient: true }),
  });
}

/** POST /api/security/assessments/{id}/rescore. */
export function useRescore(assessmentId: number) {
  return useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      postParsed(zAssessment, `/security/assessments/${assessmentId}/rescore`, body, {
        lenient: true,
      }),
  });
}

/**
 * The control catalogue with each efficacy's provenance.
 *
 * This is what the calibration chart reads: the values are the ones the score
 * is computed from, so showing them without their basis would reproduce the
 * problem the calibration layer exists to fix.
 */
export function useControlCatalog() {
  return useQuery({
    queryKey: qk.controls(),
    queryFn: async (): Promise<ControlCatalogRow[]> => {
      const d = await getParsed(zControlCatalog, '/security/controls', {
        lenient: true,
      });
      return (d.controls ?? d.items ?? []) as ControlCatalogRow[];
    },
    staleTime: 10 * 60_000,
  });
}

/**
 * The scoring regression suite. Read-only and fast (no model call), so it can
 * be polled on the calibration page to show the engine's own gate is green.
 */
export function useEval() {
  return useQuery({
    queryKey: qk.eval(),
    queryFn: (): Promise<EvalReport> =>
      getParsed(zEvalReport, '/security/eval', { lenient: true }),
    staleTime: 5 * 60_000,
  });
}

/** Open research questions ranked by coverage, plus unasked areas. */
export function useResearchGaps(invId: number | null | undefined) {
  return useQuery({
    queryKey: qk.gaps(invId ?? -1),
    enabled: typeof invId === 'number' && invId > 0,
    queryFn: (): Promise<ResearchGaps> =>
      getParsed(zResearchGaps, `/investigations/${invId}/research-gaps`),
  });
}

/**
 * Planned experiments for what is still open on an assessment.
 *
 * Plan only — the engine never executes these. Surfacing the plan is the point:
 * a proposed test with stated success criteria is the difference between a
 * recommendation and a measurement.
 */
export function useExperiments(assessmentId: number | null | undefined) {
  return useQuery({
    queryKey: qk.experiments(assessmentId ?? -1),
    enabled: false, // requires an explicit POST to build; see buildExperiments
    queryFn: async (): Promise<Experiment[]> => {
      const r = await postParsed(
        zAssessment.passthrough() as never,
        `/security/assessments/${assessmentId}/experiments/build`,
        {},
        { lenient: true },
      );
      return (r as unknown as { experiments?: Experiment[] }).experiments ?? [];
    },
  });
}

/** Narrow helper for panels that only want the band out of a bundle. */
export function pickBand(a?: AssessmentAnalysis | null): UncertaintyBand | null {
  return a?.uncertainty ?? null;
}

export function pickBudget(a?: AssessmentAnalysis | null): PrivacyBudget | null {
  return a?.privacy ?? null;
}

export function pickVarianceBudget(
  a?: AssessmentAnalysis | null,
): VarianceBudget | null {
  return a?.variance_budget ?? null;
}
