import { LayoutDashboard } from 'lucide-react';
import { Placeholder } from '@/components/shell/placeholder';

export const metadata = { title: 'Dashboard' };

export default function DashboardPage() {
  return (
    <Placeholder
      title="Dashboard"
      description="Cross-investigation metrics and trends."
      icon={LayoutDashboard}
      planned={[
        'Recharts trend lines with interval bands, not bare points',
        'Benchmark coverage and inter-rater reliability',
        'Query-yield and stale-shape warnings',
      ]}
    />
  );
}
