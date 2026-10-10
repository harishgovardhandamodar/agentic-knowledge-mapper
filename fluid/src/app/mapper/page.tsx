import { Network } from 'lucide-react';
import { Placeholder } from '@/components/shell/placeholder';

export const metadata = { title: 'Mapper' };

export default function MapperPage() {
  return (
    <Placeholder
      title="Mapper"
      description="The knowledge graph of an investigation."
      icon={Network}
      planned={[
        'Force-directed claim/source graph (react-force-graph)',
        'Contradiction edges highlighted, never averaged away',
        'Click a node to open its claim and evidence span',
      ]}
    />
  );
}
