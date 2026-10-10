'use client';

import Link from 'next/link';
import { FlaskConical } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

interface ProbeRef {
  probe_id: string;
  attack_class: string;
  description: string;
}

interface ProbePlan {
  scenario_id: string;
  probes: ProbeRef[];
  attribute_to: string[];
  n_trials: number;
  rationale: string;
}

interface ScenarioProbes {
  plans: ProbePlan[];
  untestable_scenarios: number;
  n_trials_each: number;
}

/**
 * The wire between "what would an attacker do" and "go measure it".
 *
 * A derived scenario that cannot be tested is a story with provenance. This
 * links each chain card to the probes that exercise its weakest link, with
 * the attribution the outcome would record -- so the reader goes from the
 * finding to the falsification in one click rather than two tabs.
 */
export function ScenarioProbePlan({
  scenarioId,
  plans,
}: {
  scenarioId: string;
  plans: ScenarioProbes | null;
}) {
  if (!plans) return null;
  const plan = plans.plans.find((p) => p.scenario_id === scenarioId);
  if (!plan || plan.probes.length === 0) return null;

  return (
    <Link
      href="/probes"
      className="flex flex-wrap items-center gap-1.5 rounded-md border border-primary/40 bg-primary/5 px-2.5 py-1.5 text-xs transition-colors hover:bg-primary/10"
    >
      <FlaskConical className="size-3.5 shrink-0" aria-hidden />
      <span className="font-medium">
        Test this: {plan.probes.map((p) => p.probe_id).join(' + ')}
      </span>
      <span className="tabular text-muted-foreground">
        {plan.n_trials} trials each
      </span>
      {plan.attribute_to.length > 0 && (
        <span className="flex flex-wrap items-center gap-1">
          {plan.attribute_to.slice(0, 4).map((c) => (
            <Badge key={c} variant="outline" className="font-mono text-[10px]">
              {c}
            </Badge>
          ))}
        </span>
      )}
    </Link>
  );
}
