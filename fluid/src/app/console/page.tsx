import { Terminal } from 'lucide-react';
import { Placeholder } from '@/components/shell/placeholder';

export const metadata = { title: 'Console' };

export default function ConsolePage() {
  return (
    <Placeholder
      title="Console"
      description="Runs, logs and reproducibility manifests."
      icon={Terminal}
      planned={[
        'Live run timeline from the observability spans',
        'Reproducibility manifest viewer and diff',
        'Mermaid diagrams for data-flow and threat paths',
      ]}
    />
  );
}
