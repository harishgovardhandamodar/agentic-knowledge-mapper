import { Shapes } from 'lucide-react';
import { Placeholder } from '@/components/shell/placeholder';

export const metadata = { title: 'Agent Patterns & Advisor' };

export default function AgentsPage() {
  return (
    <Placeholder
      title="Agent Patterns & Advisor"
      description="Patterns, failure scenarios and guardrail advice from the sibling AI-Agents-Patterns catalog. The full tab lives in the Classic GUI (#agents); this workspace reads the same catalog over /api/patterns/*."
      icon={Shapes}
      planned={[
        'Catalog counts and search via GET /api/patterns/summary and /api/patterns/search',
        'Pattern / scenario / cascade cards linked to the Classic #agents tab',
        'Deployment-planner and guardrail-lab deep links into /patterns/',
      ]}
    />
  );
}
